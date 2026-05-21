import math
import psycopg2

from multiprocessing import Pool
from psycopg2.extras import execute_values
from tqdm import tqdm

DB_CONFIG = {
    "host": "localhost",
    "database": "threat_intel",
    "user": "threatuser",
    "password": "threatpass",
    "port": 5432
}

BATCH_SIZE = 5000
MAX_WORKERS = 4


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def get_id_ranges():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT MIN(id), MAX(id)
        FROM threat_raw_events
        WHERE source_type = 'suricata'
    """)

    min_id, max_id = cursor.fetchone()

    cursor.close()
    conn.close()

    return min_id, max_id


def insert_batch(cursor, batch):

    query = """
        INSERT INTO suricata_alerts (
            raw_event_id,
            timestamp,
            src_ip,
            dest_ip,
            src_port,
            dest_port,
            proto,
            app_proto,
            event_type,
            alert_signature,
            alert_signature_id,
            category,
            severity,
            flow_id
        )
        VALUES %s
    """

    execute_values(cursor, query, batch)


def process_range(id_range):

    start_id, end_id = id_range

    read_conn = get_connection()
    read_cursor = read_conn.cursor()

    write_conn = get_connection()
    write_cursor = write_conn.cursor()

    read_cursor.execute("""
        SELECT id, payload
        FROM threat_raw_events
        WHERE source_type = 'suricata'
        AND id BETWEEN %s AND %s
    """, (start_id, end_id))

    rows = read_cursor.fetchmany()

    batch = []

    processed = 0

    for raw_id, payload in rows:

        try:

            if payload.get("event_type") != "alert":
                continue

            alert = payload.get("alert", {})

            batch.append((
                raw_id,
                payload.get("timestamp"),
                payload.get("src_ip"),
                payload.get("dest_ip"),
                payload.get("src_port"),
                payload.get("dest_port"),
                payload.get("proto"),
                payload.get("app_proto"),
                payload.get("event_type"),
                alert.get("signature"),
                alert.get("signature_id"),
                alert.get("category"),
                alert.get("severity"),
                payload.get("flow_id")
            ))

            processed += 1

            if len(batch) >= BATCH_SIZE:

                try:

                    insert_batch(write_cursor, batch)

                    write_conn.commit()

                    batch.clear()

                except Exception as e:

                    write_conn.rollback()

                    with open(
                        "logs/suricata_parse_failed.log",
                        "a",
                        encoding="utf-8"
                    ) as log_file:

                        log_file.write(
                            f"BATCH INSERT ERROR | {str(e)}\n"
                        )

        except Exception as e:

            write_conn.rollback()

            with open(
                "logs/suricata_parse_failed.log",
                "a",
                encoding="utf-8"
            ) as log_file:

                log_file.write(
                    f"raw_event_id={raw_id} | error={str(e)}\n"
                )

    if batch:

        insert_batch(write_cursor, batch)

        write_conn.commit()

    read_cursor.close()
    read_conn.close()

    write_cursor.close()
    write_conn.close()

    return processed


def main():

    min_id, max_id = get_id_ranges()

    print(f"ID Range: {min_id} -> {max_id}")

    total_ids = max_id - min_id

    chunk_size = math.ceil(total_ids / MAX_WORKERS)

    ranges = []

    start = min_id

    while start <= max_id:

        end = start + chunk_size

        ranges.append((start, end))

        start = end + 1

    with Pool(processes=MAX_WORKERS) as pool:

        results = list(
            tqdm(
                pool.imap_unordered(process_range, ranges),
                total=len(ranges),
                desc="Workers"
            )
        )

    total_processed = sum(results)

    print(f"Total Parsed Alerts: {total_processed}")


if __name__ == "__main__":
    main()