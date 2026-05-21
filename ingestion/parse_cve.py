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

FETCH_SIZE = 2000
INSERT_BATCH_SIZE = 500


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def safe_get(dct, keys, default=None):

    current = dct

    for key in keys:

        if isinstance(current, dict):
            current = current.get(key)
        else:
            return default

        if current is None:
            return default

    return current


def insert_batch(cursor, batch):

    query = """
        INSERT INTO cve_records (

            raw_event_id,

            cve_id,

            published_date,
            updated_date,

            state,

            assigner_short_name,

            title,
            description,

            base_score,
            base_severity,

            attack_vector,
            attack_complexity,

            privileges_required,
            user_interaction,

            scope,

            confidentiality_impact,
            integrity_impact,
            availability_impact,

            vendor_name,
            product_name,

            affected_versions,

            cwe_id,
            cwe_description,

            references_count

        )
        VALUES %s
    """

    execute_values(cursor, query, batch)


def insert_row(cursor, row):

    query = """
        INSERT INTO cve_records (

            raw_event_id,

            cve_id,

            published_date,
            updated_date,

            state,

            assigner_short_name,

            title,
            description,

            base_score,
            base_severity,

            attack_vector,
            attack_complexity,

            privileges_required,
            user_interaction,

            scope,

            confidentiality_impact,
            integrity_impact,
            availability_impact,

            vendor_name,
            product_name,

            affected_versions,

            cwe_id,
            cwe_description,

            references_count

        )
        VALUES (
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s
        )
    """

    cursor.execute(query, row)


def main():

    read_conn = get_connection()
    read_cursor = read_conn.cursor(name="cve_stream")

    write_conn = get_connection()
    write_cursor = write_conn.cursor()

    read_cursor.itersize = FETCH_SIZE

    read_cursor.execute("""
        SELECT id, payload
        FROM threat_raw_events
        WHERE source_type = 'cve'
    """)

    total_processed = 0

    while True:

        rows = read_cursor.fetchmany(FETCH_SIZE)

        if not rows:
            break

        batch = []

        for raw_id, payload in tqdm(rows):

            try:

                cve_meta = payload.get("cveMetadata", {})

                cna = safe_get(
                    payload,
                    ["containers", "cna"],
                    {}
                )

                metrics = safe_get(
                    cna,
                    ["metrics"],
                    []
                )

                cvss = {}

                if metrics and isinstance(metrics, list):

                    first_metric = metrics[0]

                    cvss = first_metric.get(
                        "cvssV3_1",
                        {}
                    )

                descriptions = cna.get(
                    "descriptions",
                    []
                )

                description = None

                if descriptions:
                    description = descriptions[0].get(
                        "value"
                    )

                affected = cna.get(
                    "affected",
                    []
                )

                vendor_name = None
                product_name = None
                affected_versions = None

                if affected:

                    first_affected = affected[0]

                    vendor_name = first_affected.get(
                        "vendor"
                    )

                    product_name = first_affected.get(
                        "product"
                    )

                    versions = first_affected.get(
                        "versions",
                        []
                    )

                    if versions:
                        affected_versions = versions[0].get(
                            "version"
                        )

                problem_types = cna.get(
                    "problemTypes",
                    []
                )

                cwe_id = None
                cwe_description = None

                if problem_types:

                    descriptions_block = problem_types[0].get(
                        "descriptions",
                        []
                    )

                    if descriptions_block:

                        first_desc = descriptions_block[0]

                        cwe_id = first_desc.get("cweId")

                        cwe_description = first_desc.get(
                            "description"
                        )

                references = cna.get(
                    "references",
                    []
                )

                row = (

                    raw_id,

                    cve_meta.get("cveId"),

                    cve_meta.get("datePublished"),
                    cve_meta.get("dateUpdated"),

                    cve_meta.get("state"),

                    cve_meta.get("assignerShortName"),

                    cna.get("title"),
                    description,

                    cvss.get("baseScore"),
                    cvss.get("baseSeverity"),

                    cvss.get("attackVector"),
                    cvss.get("attackComplexity"),

                    cvss.get("privilegesRequired"),
                    cvss.get("userInteraction"),

                    cvss.get("scope"),

                    cvss.get("confidentialityImpact"),
                    cvss.get("integrityImpact"),
                    cvss.get("availabilityImpact"),

                    vendor_name,
                    product_name,

                    affected_versions,

                    cwe_id,
                    cwe_description,

                    len(references)
                )

                batch.append(row)

                if len(batch) >= INSERT_BATCH_SIZE:

                    try:

                        insert_batch(write_cursor, batch)

                        write_conn.commit()

                        total_processed += len(batch)

                        print(
                            f"Committed {total_processed} CVEs"
                        )

                        batch.clear()

                    except Exception:

                        write_conn.rollback()

                        for single_row in batch:

                            try:

                                insert_row(
                                    write_cursor,
                                    single_row
                                )

                                write_conn.commit()

                                total_processed += 1

                            except Exception as e:

                                write_conn.rollback()

                                with open(
                                    "logs/cve_parse_failed.log",
                                    "a",
                                    encoding="utf-8"
                                ) as log_file:

                                    log_file.write(
                                        f"raw_event_id={single_row[0]} | error={str(e)}\n"
                                    )

                        batch.clear()

            except Exception as e:

                with open(
                    "logs/cve_parse_failed.log",
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
                        "logs/cve_parse_failed.log",
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

    print(f"\nTotal Parsed CVEs: {total_processed}")


if __name__ == "__main__":
    main()