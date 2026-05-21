import json
import traceback
from datetime import datetime

import psycopg2
from psycopg2.extras import execute_values
from tqdm import tqdm

DB_CONFIG = {
    "host": "localhost",
    "database": "threat_intel",
    "user": "threatuser",
    "password": "threatpass",
    "port": 5432
}

JSON_PATH = "data/mitre/enterprise-attack.json"

INSERT_BATCH_SIZE = 500


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def log_failed_object(
    obj,
    error,
    stage="unknown"
):

    failed_record = {

        "timestamp": datetime.utcnow().isoformat(),

        "stage": stage,

        "object_id": obj.get("id"),

        "object_type": obj.get("type"),

        "technique_name": obj.get("name"),

        "error": str(error),

        "traceback": traceback.format_exc(),

        "raw_object": obj
    }

    with open(
        "logs/attack_parse_failed.jsonl",
        "a",
        encoding="utf-8"
    ) as log_file:

        log_file.write(
            json.dumps(failed_record)
        )

        log_file.write("\n")


def log_failed_row(
    row,
    error,
    stage="insert_row"
):

    failed_record = {

        "timestamp": datetime.utcnow().isoformat(),

        "stage": stage,

        "technique_id": row[1],

        "technique_name": row[2],

        "error": str(error),

        "traceback": traceback.format_exc(),

        "row_data": {
            "technique_stix_id": row[0],
            "technique_id": row[1],
            "name": row[2],
            "description": row[3],
            "tactic": row[4],
            "platforms": row[5],
            "detection": row[6],
            "created": row[7],
            "modified": row[8],
            "url": row[9]
        }
    }

    with open(
        "logs/attack_parse_failed.jsonl",
        "a",
        encoding="utf-8"
    ) as log_file:

        log_file.write(
            json.dumps(failed_record)
        )

        log_file.write("\n")


def insert_batch(cursor, batch):

    query = """
        INSERT INTO attack_techniques (

            technique_stix_id,
            technique_id,
            name,
            description,
            tactic,
            platforms,
            detection,
            created,
            modified,
            url

        )
        VALUES %s
    """

    execute_values(cursor, query, batch)


def insert_row(cursor, row):

    query = """
        INSERT INTO attack_techniques (

            technique_stix_id,
            technique_id,
            name,
            description,
            tactic,
            platforms,
            detection,
            created,
            modified,
            url

        )
        VALUES (
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s
        )
    """

    cursor.execute(query, row)


def extract_technique_id(external_refs):

    if not external_refs:
        return None, None

    for ref in external_refs:

        if ref.get("source_name") == "mitre-attack":

            return (
                ref.get("external_id"),
                ref.get("url")
            )

    return None, None


def extract_tactic(kill_chain_phases):

    if not kill_chain_phases:
        return None

    for phase in kill_chain_phases:

        if phase.get("kill_chain_name") == "mitre-attack":

            return phase.get("phase_name")

    return None


def main():

    with open(JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    objects = data.get("objects", [])

    conn = get_connection()
    cursor = conn.cursor()

    batch = []

    total_processed = 0

    for obj in tqdm(objects):

        try:

            if obj.get("type") != "attack-pattern":
                continue

            technique_id, url = extract_technique_id(
                obj.get("external_references", [])
            )

            row = (

                obj.get("id"),

                technique_id,

                obj.get("name"),

                obj.get("description"),

                extract_tactic(
                    obj.get("kill_chain_phases", [])
                ),

                obj.get("x_mitre_platforms", []),

                obj.get("x_mitre_detection"),

                obj.get("created"),

                obj.get("modified"),

                url
            )

            batch.append(row)

            if len(batch) >= INSERT_BATCH_SIZE:

                try:

                    insert_batch(cursor, batch)

                    conn.commit()

                    total_processed += len(batch)

                    print(
                        f"Committed {total_processed} ATT&CK techniques"
                    )

                    batch.clear()

                except Exception as batch_error:

                    conn.rollback()

                    print(
                        f"Batch insert failed. Falling back to row inserts..."
                    )

                    for single_row in batch:

                        try:

                            insert_row(cursor, single_row)

                            conn.commit()

                            total_processed += 1

                        except Exception as row_error:

                            conn.rollback()

                            log_failed_row(
                                single_row,
                                row_error,
                                stage="batch_row_fallback"
                            )

                    batch.clear()

        except Exception as parse_error:

            log_failed_object(
                obj,
                parse_error,
                stage="main_parse_loop"
            )

    if batch:

        try:

            insert_batch(cursor, batch)

            conn.commit()

            total_processed += len(batch)

        except Exception as batch_error:

            conn.rollback()

            print(
                f"Final batch insert failed. Falling back to row inserts..."
            )

            for single_row in batch:

                try:

                    insert_row(cursor, single_row)

                    conn.commit()

                    total_processed += 1

                except Exception as row_error:

                    conn.rollback()

                    log_failed_row(
                        single_row,
                        row_error,
                        stage="final_batch_row_fallback"
                    )
    
    expected_count = 0

    for obj in objects:

        if obj.get("type") == "attack-pattern":
            expected_count += 1

    print("\n===== VALIDATION =====\n")

    print(f"Expected Techniques : {expected_count}")

    print(f"Parsed Techniques   : {total_processed}")

    print(
        f"Difference           : "
        f"{expected_count - total_processed}"
    )

    cursor.close()
    conn.close()

    print(
        f"\nTotal ATT&CK Techniques Parsed: {total_processed}"
    )


if __name__ == "__main__":
    main()