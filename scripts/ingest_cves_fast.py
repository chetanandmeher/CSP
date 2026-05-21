#!/usr/bin/env python3
"""
ingest_cves_fast.py
-------------------
Blazing fast CVE ingestion using PostgreSQL COPY command.
Converts all CVE JSONs to CSV first, then bulk loads in one shot.

Steps:
  1. Walk all CVE JSON files -> parse -> write to temp CSV
  2. COPY CSV into PostgreSQL in one command

Usage:
    python scripts/ingest_cves_fast.py --cve-dir cvelistV5-main/cves

Requirements:
    pip install psycopg2-binary
"""

import os
import io
import csv
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime

import psycopg2

# ── Config ────────────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("DB_HOST",     "localhost"),
    "port":     int(os.getenv("DB_PORT", "5432")),
    "dbname":   os.getenv("DB_NAME",     "threat_intel"),
    "user":     os.getenv("DB_USER",     "threatuser"),
    "password": os.getenv("DB_PASSWORD", "threatpass"),
}

PRINT_EVERY = 1000   # print progress every N files
CSV_PATH    = Path("cve_bulk.csv")  # temp CSV file

COLUMNS = [
    "cve_id", "year", "state", "assigner",
    "date_published", "date_updated", "date_reserved",
    "description", "problem_types", "vendor", "product", "versions_affected",
    "cvss_v3_score", "cvss_v3_severity", "cvss_v2_score",
    "reference_urls", "raw_json",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ── Parser ────────────────────────────────────────────────────────────────────

def parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).isoformat()
    except Exception:
        return None


def parse_cve(data: dict) -> dict | None:
    try:
        meta = data.get("cveMetadata", {})
        cna  = data.get("containers", {}).get("cna", {})

        cve_id = meta.get("cveId", "")
        if not cve_id:
            return None

        try:
            year = int(cve_id.split("-")[1])
        except Exception:
            year = None

        description = None
        for d in cna.get("descriptions", []):
            if d.get("lang", "").startswith("en"):
                description = d.get("value")
                break

        problem_types = []
        for pt in cna.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                val = desc.get("description") or desc.get("cweId")
                if val and val.lower() != "n/a":
                    problem_types.append(val)

        vendor  = None
        product = None
        versions_affected = []
        affected = cna.get("affected", [])
        if affected:
            first   = affected[0]
            vendor  = first.get("vendor")  if first.get("vendor")  != "n/a" else None
            product = first.get("product") if first.get("product") != "n/a" else None
            for v in first.get("versions", []):
                ver = v.get("version")
                if ver and ver != "n/a":
                    versions_affected.append(ver)

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

        reference_urls = [r.get("url") for r in cna.get("references", []) if r.get("url")]

        # PostgreSQL array literal format: {val1,val2}
        def to_pg_array(lst):
            if not lst:
                return None
            escaped = [str(x).replace('"', '\\"') for x in lst]
            return "{" + ",".join(f'"{e}"' for e in escaped) + "}"

        return {
            "cve_id":            cve_id,
            "year":              year,
            "state":             meta.get("state"),
            "assigner":          meta.get("assignerShortName"),
            "date_published":    parse_dt(meta.get("datePublished")),
            "date_updated":      parse_dt(meta.get("dateUpdated")),
            "date_reserved":     parse_dt(meta.get("dateReserved")),
            "description":       description,
            "problem_types":     to_pg_array(problem_types),
            "vendor":            vendor,
            "product":           product,
            "versions_affected": to_pg_array(versions_affected),
            "cvss_v3_score":     cvss_v3_score,
            "cvss_v3_severity":  cvss_v3_severity,
            "cvss_v2_score":     cvss_v2_score,
            "reference_urls":    to_pg_array(reference_urls),
            "raw_json":          json.dumps(data, ensure_ascii=False),
        }
    except Exception as e:
        return None


# ── Step 1: Build CSV ─────────────────────────────────────────────────────────

def build_csv(cve_dir: str) -> int:
    cve_path = Path(cve_dir)
    total   = 0
    skipped = 0
    errors  = 0

    log.info(f"Step 1/2 — Parsing CVE files and writing CSV: {CSV_PATH}")

    with open(CSV_PATH, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=COLUMNS,
            extrasaction="ignore",
            quoting=csv.QUOTE_ALL,
        )
        writer.writeheader()

        for json_file in sorted(cve_path.rglob("CVE-*.json")):
            try:
                with open(json_file, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)

                record = parse_cve(data)
                if record is None:
                    skipped += 1
                    continue

                # Replace None with empty string for CSV
                row = {k: ("" if v is None else v) for k, v in record.items()}
                writer.writerow(row)
                total += 1

                if total % PRINT_EVERY == 0:
                    print(f"  [PARSE] {total:,} files done | skipped={skipped} errors={errors}", flush=True)

            except Exception as e:
                errors += 1
                print(f"  [ERROR] {json_file.name}: {e}", flush=True)

    print(f"\n  [PARSE COMPLETE] total={total:,} | skipped={skipped} | errors={errors}", flush=True)
    csv_size = CSV_PATH.stat().st_size / (1024 * 1024)
    print(f"  [CSV SIZE] {csv_size:.1f} MB", flush=True)
    return total


# ── Step 2: COPY into PostgreSQL ──────────────────────────────────────────────

def copy_to_db():
    log.info("Step 2/2 — Bulk loading CSV into PostgreSQL via COPY ...")

    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = False
    cur  = conn.cursor()

    # Create a temp staging table
    print("  [DB] Creating staging table ...", flush=True)
    cur.execute("""
        CREATE TEMP TABLE cves_staging (LIKE cves INCLUDING DEFAULTS)
        ON COMMIT DROP;
    """)

    print("  [DB] Copying CSV into staging table ...", flush=True)
    with open(CSV_PATH, "r", encoding="utf-8") as f:
        cur.copy_expert("""
            COPY cves_staging (
                cve_id, year, state, assigner,
                date_published, date_updated, date_reserved,
                description, problem_types, vendor, product, versions_affected,
                cvss_v3_score, cvss_v3_severity, cvss_v2_score,
                reference_urls, raw_json
            )
            FROM STDIN
            WITH (FORMAT CSV, HEADER TRUE, QUOTE '"', ENCODING 'UTF8')
        """, f)

    print("  [DB] Upserting from staging into cves table ...", flush=True)
    cur.execute("""
        INSERT INTO cves (
            cve_id, year, state, assigner,
            date_published, date_updated, date_reserved,
            description, problem_types, vendor, product, versions_affected,
            cvss_v3_score, cvss_v3_severity, cvss_v2_score,
            reference_urls, raw_json
        )
        SELECT
            cve_id, year, state, assigner,
            date_published, date_updated, date_reserved,
            description, problem_types, vendor, product, versions_affected,
            cvss_v3_score, cvss_v3_severity, cvss_v2_score,
            reference_urls, raw_json
        FROM cves_staging
        ON CONFLICT (cve_id) DO UPDATE SET
            state            = EXCLUDED.state,
            date_updated     = EXCLUDED.date_updated,
            description      = EXCLUDED.description,
            cvss_v3_score    = EXCLUDED.cvss_v3_score,
            cvss_v3_severity = EXCLUDED.cvss_v3_severity,
            cvss_v2_score    = EXCLUDED.cvss_v2_score,
            raw_json         = EXCLUDED.raw_json,
            ingested_at      = NOW();
    """)

    conn.commit()

    # Final count
    cur.execute("SELECT COUNT(*) FROM cves;")
    count = cur.fetchone()[0]
    print(f"  [DB] Total CVEs in database: {count:,}", flush=True)

    cur.close()
    conn.close()


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fast bulk CVE ingestion via PostgreSQL COPY")
    parser.add_argument(
        "--cve-dir",
        required=True,
        help="Path to cvelistV5-main/cves directory",
    )
    parser.add_argument(
        "--skip-csv",
        action="store_true",
        help="Skip CSV generation and use existing cve_bulk.csv (if already built)",
    )
    args = parser.parse_args()

    start = datetime.now()

    if not args.skip_csv:
        total = build_csv(args.cve_dir)
        if total == 0:
            log.error("No records parsed. Check your --cve-dir path.")
            exit(1)
    else:
        print("  [SKIP] Using existing cve_bulk.csv", flush=True)

    copy_to_db()

    # Cleanup CSV
    if CSV_PATH.exists():
        CSV_PATH.unlink()
        print("  [CLEANUP] Removed temp CSV file", flush=True)

    elapsed = datetime.now() - start
    log.info(f"All done in {elapsed}")