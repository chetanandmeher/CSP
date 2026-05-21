import sys
import os
import psycopg2
from psycopg2.extras import execute_values
from tqdm import tqdm

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import DB_CONFIG

FETCH_SIZE = 5000
INSERT_BATCH_SIZE = 1000


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


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


def insert_row(cursor, row):

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
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    cursor.execute(query, row)


def main():

    read_conn = get_connection()
    read_cursor = read_conn.cursor(name="suricata_stream")

    write_conn = get_connection()
    write_cursor = write_conn.cursor()

    read_cursor.itersize = FETCH_SIZE

    read_cursor.execute("""
        SELECT id, payload
        FROM threat_raw_events
        WHERE source_type = 'suricata'
        AND payload->>'event_type' = 'alert'
    """)

    total_processed = 0

    while True:

        rows = read_cursor.fetchmany(FETCH_SIZE)

        if not rows:
            break

        batch = []

        for raw_id, payload in tqdm(rows):

            try:

                alert = payload.get("alert", {})

                row = (
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
                )

                batch.append(row)

                if len(batch) >= INSERT_BATCH_SIZE:

                    try:

                        insert_batch(write_cursor, batch)

                        write_conn.commit()

                        total_processed += len(batch)

                        batch.clear()

                    except Exception:

                        write_conn.rollback()

                        for single_row in batch:

                            try:

                                insert_row(write_cursor, single_row)

                                write_conn.commit()

                                total_processed += 1

                            except Exception as e:

                                write_conn.rollback()

                                with open(
                                    "logs/suricata_parse_failed.log",
                                    "a",
                                    encoding="utf-8"
                                ) as log_file:

                                    log_file.write(
                                        f"raw_event_id={single_row[0]} | error={str(e)}\n"
                                    )

                        batch.clear()

            except Exception as e:

                with open(
                    "logs/suricata_parse_failed.log",
                    "a",
                    encoding="utf-8"
                ) as log_file:

                    log_file.write(
                        f"raw_event_id={raw_id} | error={str(e)}\n"
                    )

        if batch:

            try:

                insert_batch(write_cursor, batch)

                write_conn.commit()

                total_processed += len(batch)

            except Exception:

                write_conn.rollback()

                for single_row in batch:

                    try:

                        insert_row(write_cursor, single_row)

                        write_conn.commit()

                        total_processed += 1

                    except Exception as e:

                        write_conn.rollback()

                        with open(
                            "logs/suricata_parse_failed.log",
                            "a",
                            encoding="utf-8"
                        ) as log_file:

                            log_file.write(
                                f"raw_event_id={single_row[0]} | error={str(e)}\n"
                            )

    read_cursor.close()
    read_conn.close()

    write_cursor.close()
    write_conn.close()

    print(f"Total Parsed Alerts: {total_processed}")


if __name__ == "__main__":
    main()