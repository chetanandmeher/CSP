import psycopg2
from psycopg2.extras import execute_values
from tqdm import tqdm
import pandas as pd
import json
from pathlib import Path

DB_CONFIG = {
    "host": "localhost",
    "database": "threat_intel",
    "user": "threatuser",
    "password": "threatpass",
    "port": 5432
}

FETCH_SIZE = 5000
INSERT_BATCH_SIZE = 1000


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def insert_batch(cursor, batch):

    query = """
        INSERT INTO cowrie_events (
            raw_event_id,
            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            eventid,
            session,
            message,
            sensor
        )
        VALUES %s
    """

    execute_values(cursor, query, batch)


def insert_row(cursor, row):

    query = """
        INSERT INTO cowrie_events (
            raw_event_id,
            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            eventid,
            session,
            message,
            sensor
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    cursor.execute(query, row)


def validate_dataframe(df):

    report = {}

    report["total_rows"] = len(df)

    report["null_percentages"] = (
        df.isnull().mean() * 100
    ).round(2).to_dict()

    report["duplicate_rows"] = int(df.duplicated().sum())

    required_cols = [
        "timestamp",
        "src_ip",
        "eventid"
    ]

    missing_required = {}

    for col in required_cols:

        missing_required[col] = int(
            df[col].isnull().sum()
        )

    report["missing_required"] = missing_required

    report["timestamp_dtype"] = str(
        df["timestamp"].dtype
    )

    return report


def main():

    read_conn = get_connection()
    read_cursor = read_conn.cursor(name="cowrie_stream")

    write_conn = get_connection()
    write_cursor = write_conn.cursor()

    read_cursor.itersize = FETCH_SIZE

    read_cursor.execute("""
        SELECT id, payload
        FROM threat_raw_events
        WHERE source_type = 'cowrie'
    """)

    total_processed = 0

    while True:

        rows = read_cursor.fetchmany(FETCH_SIZE)

        if not rows:
            break

        batch = []

        for raw_id, payload in tqdm(rows):

            try:

                row = (
                    raw_id,
                    payload.get("timestamp"),
                    payload.get("src_ip"),
                    payload.get("dst_ip"),
                    payload.get("src_port"),
                    payload.get("dst_port"),
                    payload.get("protocol"),
                    payload.get("eventid"),
                    payload.get("session"),
                    payload.get("message"),
                    payload.get("sensor")
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
                                    "logs/cowrie_parse_failed.log",
                                    "a",
                                    encoding="utf-8"
                                ) as log_file:

                                    log_file.write(
                                        f"raw_event_id={single_row[0]} | error={str(e)}\n"
                                    )

                        batch.clear()

            except Exception as e:

                with open(
                    "logs/cowrie_parse_failed.log",
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
                            "logs/cowrie_parse_failed.log",
                            "a",
                            encoding="utf-8"
                        ) as log_file:

                            log_file.write(
                                f"raw_event_id={single_row[0]} | error={str(e)}\n"
                            )

    validation_conn = get_connection()

    df = pd.read_sql("""
        SELECT *
        FROM cowrie_events
    """, validation_conn)

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    df["src_ip"] = df["src_ip"].astype(str)

    df["eventid"] = df["eventid"].astype(str)

    report = validate_dataframe(df)

    Path("reports").mkdir(exist_ok=True)

    with open(
        "reports/cowrie_validation_report.json",
        "w"
    ) as f:

        json.dump(report, f, indent=2)

    with open(
        "reports/cowrie_validation_summary.txt",
        "w"
    ) as f:

        f.write(
            f"Total Rows: {report['total_rows']}\n"
        )

        f.write(
            f"Duplicate Rows: {report['duplicate_rows']}\n"
        )

    print("\n===== SAMPLE DATA =====\n")

    print(df.sample(20))

    print("\n===== DATA TYPES =====\n")

    print(df.dtypes)

    validation_conn.close()

    read_cursor.close()
    read_conn.close()

    write_cursor.close()
    write_conn.close()

    print(f"\nTotal Parsed Cowrie Events: {total_processed}")
    print("\nValidation reports generated successfully.")


if __name__ == "__main__":
    main()