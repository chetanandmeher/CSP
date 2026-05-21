#!/usr/bin/env python3
"""
ingest_suricata.py
------------------
Parses Suricata eve.json log files and inserts alerts
into the PostgreSQL suricata_alerts table.

Usage:
    python scripts/ingest_suricata.py --log-dir suricata

Requirements:
    pip install psycopg2-binary
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime

import psycopg2

# ── Config ────────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import DB_CONFIG

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def parse_alert(line: str, source_file: str) -> dict | None:
    """Parse a single eve.json line into a flat record."""
    try:
        data = json.loads(line.strip())
    except json.JSONDecodeError:
        return None

    # Only process alert events
    if data.get("event_type") != "alert":
        return None

    alert  = data.get("alert", {})
    flow   = data.get("flow", {})

    return {
        "timestamp":     parse_dt(data.get("timestamp")),
        "flow_id":       data.get("flow_id"),
        "in_iface":      data.get("in_iface"),
        "src_ip":        data.get("src_ip"),
        "src_port":      data.get("src_port"),
        "dest_ip":       data.get("dest_ip"),
        "dest_port":     data.get("dest_port"),
        "proto":         data.get("proto"),
        "direction":     data.get("direction"),
        "signature_id":  alert.get("signature_id"),
        "signature":     alert.get("signature"),
        "category":      alert.get("category"),
        "severity":      alert.get("severity"),
        "action":        alert.get("action"),
        "pkts_toserver": flow.get("pkts_toserver"),
        "pkts_toclient": flow.get("pkts_toclient"),
        "bytes_toserver":flow.get("bytes_toserver"),
        "bytes_toclient":flow.get("bytes_toclient"),
        "flow_start":    parse_dt(flow.get("start")),
        "source_file":   source_file,
        "raw_json":      json.dumps(data),
    }


INSERT_SQL = """
INSERT INTO suricata_alerts (
    timestamp, flow_id, in_iface,
    src_ip, src_port, dest_ip, dest_port, proto, direction,
    signature_id, signature, category, severity, action,
    pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient,
    flow_start, source_file, raw_json
) VALUES (
    %(timestamp)s, %(flow_id)s, %(in_iface)s,
    %(src_ip)s, %(src_port)s, %(dest_ip)s, %(dest_port)s, %(proto)s, %(direction)s,
    %(signature_id)s, %(signature)s, %(category)s, %(severity)s, %(action)s,
    %(pkts_toserver)s, %(pkts_toclient)s, %(bytes_toserver)s, %(bytes_toclient)s,
    %(flow_start)s, %(source_file)s, %(raw_json)s
)
ON CONFLICT DO NOTHING;
"""


# ── Main ──────────────────────────────────────────────────────────────────────

def ingest(log_dir: str):
    log_path = Path(log_dir)
    if not log_path.exists():
        log.error(f"Directory not found: {log_dir}")
        return

    # Find all eve.json files (handles eve.json, eve.json.processed, eve.json.20260515_xxx.processed)
    log_files = sorted(
        list(log_path.rglob("eve.json*"))
    )

    if not log_files:
        log.error(f"No eve.json files found in {log_dir}")
        return

    log.info(f"Found {len(log_files)} Suricata log file(s)")
    for f in log_files:
        print(f"  -> {f}", flush=True)

    print("", flush=True)
    log.info(f"Connecting to PostgreSQL at {DB_CONFIG['host']}:{DB_CONFIG['port']} ...")
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = False
    cur  = conn.cursor()

    total   = 0
    skipped = 0
    errors  = 0

    for log_file in log_files:
        print(f"\n[FILE] Processing: {log_file.name}", flush=True)
        file_count = 0

        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue

                record = parse_alert(line, log_file.name)

                if record is None:
                    skipped += 1
                    continue

                try:
                    cur.execute("SAVEPOINT sp1")
                    cur.execute(INSERT_SQL, record)
                    cur.execute("RELEASE SAVEPOINT sp1")
                    total      += 1
                    file_count += 1
                    print(
                        f"  [INSERT] line {line_num} | src={record['src_ip']}:{record['src_port']} "
                        f"-> {record['dest_ip']}:{record['dest_port']} | sig={record['signature_id']} "
                        f"| total={total}",
                        flush=True
                    )
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT sp1")
                    errors += 1
                    print(f"  [ERROR] line {line_num}: {e}", flush=True)

        conn.commit()
        print(f"  [DONE] {log_file.name} — inserted {file_count} alerts", flush=True)

    cur.close()
    conn.close()

    print("", flush=True)
    log.info("=" * 50)
    log.info(f"Total inserted : {total}")
    log.info(f"Skipped (non-alert events) : {skipped}")
    log.info(f"Errors         : {errors}")
    log.info("=" * 50)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest Suricata eve.json logs into PostgreSQL")
    parser.add_argument(
        "--log-dir",
        required=True,
        help="Path to folder containing Suricata eve.json log files",
    )
    args = parser.parse_args()
    ingest(args.log_dir)