#!/usr/bin/env python3
"""
ingest_cves.py
--------------
Walks the entire cvelistV5-main/cves folder tree and inserts
every CVE JSON file into the PostgreSQL cves table.

Usage:
    python ingest_cves.py --cve-dir /path/to/cvelistV5-main/cves

Requirements:
    pip install psycopg2-binary
"""

import os
import json
import argparse
import logging
from datetime import datetime
from pathlib import Path

import psycopg2
from psycopg2.extras import execute_batch

# ── Config ────────────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("DB_HOST",     "localhost"),
    "port":     int(os.getenv("DB_PORT", "5432")),
    "dbname":   os.getenv("DB_NAME",     "threat_intel"),
    "user":     os.getenv("DB_USER",     "threatuser"),
    "password": os.getenv("DB_PASSWORD", "threatpass"),
}

BATCH_SIZE  = 500   # rows per INSERT batch
LOG_EVERY   = 100   # print progress every N files

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_cve(data: dict) -> dict | None:
    """Extract flat fields from a CVE 5.1 JSON record."""
    try:
        meta = data.get("cveMetadata", {})
        cna  = data.get("containers", {}).get("cna", {})

        cve_id = meta.get("cveId", "")
        if not cve_id:
            return None

        # Year from CVE ID
        try:
            year = int(cve_id.split("-")[1])
        except Exception:
            year = None

        # Description (first English one)
        description = None
        for d in cna.get("descriptions", []):
            if d.get("lang", "").startswith("en"):
                description = d.get("value")
                break

        # Problem types
        problem_types = []
        for pt in cna.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                val = desc.get("description") or desc.get("cweId")
                if val and val.lower() != "n/a":
                    problem_types.append(val)

        # Vendor / product (first entry)
        vendor  = None
        product = None
        versions_affected = []
        affected = cna.get("affected", [])
        if affected:
            first = affected[0]
            vendor  = first.get("vendor")  if first.get("vendor")  != "n/a" else None
            product = first.get("product") if first.get("product") != "n/a" else None
            for v in first.get("versions", []):
                ver = v.get("version")
                if ver and ver != "n/a":
                    versions_affected.append(ver)

        # CVSS scores — check metrics block (CVE 5.x)
        cvss_v3_score    = None
        cvss_v3_severity = None
        cvss_v2_score    = None
        for metric in cna.get("metrics", []):
            if "cvssV3_1" in metric:
                cvss_v3_score    = metric["cvssV3_1"].get("baseScore")
                cvss_v3_severity = metric["cvssV3_1"].get("baseSeverity")
            elif "cvssV3_0" in metric:
                cvss_v3_score    = metric["cvssV3_0"].get("baseScore")
                cvss_v3_severity = metric["cvssV3_0"].get("baseSeverity")
            elif "cvssV2_0" in metric:
                cvss_v2_score    = metric["cvssV2_0"].get("baseScore")

        # Reference URLs
        reference_urls = [
            r.get("url") for r in cna.get("references", []) if r.get("url")
        ]

        # Date parsing helper
        def parse_dt(s):
            if not s:
                return None
            try:
                return datetime.fromisoformat(s.replace("Z", "+00:00"))
            except Exception:
                return None

        return {
            "cve_id":           cve_id,
            "year":             year,
            "state":            meta.get("state"),
            "assigner":         meta.get("assignerShortName"),
            "date_published":   parse_dt(meta.get("datePublished")),
            "date_updated":     parse_dt(meta.get("dateUpdated")),
            "date_reserved":    parse_dt(meta.get("dateReserved")),
            "description":      description,
            "problem_types":    problem_types or None,
            "vendor":           vendor,
            "product":          product,
            "versions_affected":versions_affected or None,
            "cvss_v3_score":    cvss_v3_score,
            "cvss_v3_severity": cvss_v3_severity,
            "cvss_v2_score":    cvss_v2_score,
            "reference_urls":   reference_urls or None,
            "raw_json":         json.dumps(data),
        }
    except Exception as e:
        log.warning(f"Failed to parse CVE: {e}")
        return None


INSERT_SQL = """
INSERT INTO cves (
    cve_id, year, state, assigner,
    date_published, date_updated, date_reserved,
    description, problem_types, vendor, product, versions_affected,
    cvss_v3_score, cvss_v3_severity, cvss_v2_score,
    reference_urls, raw_json
) VALUES (
    %(cve_id)s, %(year)s, %(state)s, %(assigner)s,
    %(date_published)s, %(date_updated)s, %(date_reserved)s,
    %(description)s, %(problem_types)s, %(vendor)s, %(product)s, %(versions_affected)s,
    %(cvss_v3_score)s, %(cvss_v3_severity)s, %(cvss_v2_score)s,
    %(reference_urls)s, %(raw_json)s
)
ON CONFLICT (cve_id) DO UPDATE SET
    state            = EXCLUDED.state,
    date_updated     = EXCLUDED.date_updated,
    description      = EXCLUDED.description,
    cvss_v3_score    = EXCLUDED.cvss_v3_score,
    cvss_v3_severity = EXCLUDED.cvss_v3_severity,
    cvss_v2_score    = EXCLUDED.cvss_v2_score,
    raw_json         = EXCLUDED.raw_json,
    ingested_at      = NOW();
"""


# ── Main ──────────────────────────────────────────────────────────────────────

def ingest(cve_dir: str):
    cve_path = Path(cve_dir)
    if not cve_path.exists():
        log.error(f"Directory not found: {cve_dir}")
        return

    log.info(f"Connecting to PostgreSQL at {DB_CONFIG['host']}:{DB_CONFIG['port']} ...")
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = False
    cur = conn.cursor()

    total   = 0
    skipped = 0
    errors  = 0
    batch   = []

    log.info(f"Walking CVE directory: {cve_dir}")

    def flush_batch(batch):
        """Insert batch one by one with savepoints so one failure doesn't abort all."""
        inserted = 0
        failed   = 0
        for record in batch:
            try:
                cur.execute("SAVEPOINT sp1")
                cur.execute(INSERT_SQL, record)
                cur.execute("RELEASE SAVEPOINT sp1")
                inserted += 1
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT sp1")
                log.warning(f"Skipping {record.get('cve_id','?')}: {e}")
                failed += 1
        conn.commit()
        return inserted, failed

    for json_file in sorted(cve_path.rglob("CVE-*.json")):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            record = parse_cve(data)
            if record is None:
                skipped += 1
                print(f"  [SKIP] {json_file.name} — no cve_id", flush=True)
                continue

            batch.append(record)
            total += 1

            # Always print current file being processed
            print(f"  [READ] {json_file.name}  (total: {total:,}  errors: {errors})", end="\r", flush=True)

            if len(batch) >= BATCH_SIZE:
                ins, fail = flush_batch(batch)
                errors += fail
                batch = []
                print(f"  [BATCH SAVED] {total:,} processed  |  skipped: {skipped}  |  errors: {errors}     ", flush=True)

            if total % LOG_EVERY == 0:
                log.info(f"  Processed {total:,} CVEs  |  skipped {skipped}  |  errors {errors}")

        except Exception as e:
            errors += 1
            print(f"  [ERROR] {json_file.name}: {e}", flush=True)
            log.warning(f"Error reading {json_file.name}: {e}")

    # Insert remaining
    if batch:
        ins, fail = flush_batch(batch)
        errors += fail

    cur.close()
    conn.close()

    log.info("=" * 50)
    log.info(f"Done! Inserted/updated : {total:,}")
    log.info(f"Skipped (no cve_id)    : {skipped}")
    log.info(f"Errors                 : {errors}")
    log.info("=" * 50)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest CVE JSON files into PostgreSQL")
    parser.add_argument(
        "--cve-dir",
        required=True,
        help="Path to cvelistV5-main/cves directory",
    )
    args = parser.parse_args()
    ingest(args.cve_dir)