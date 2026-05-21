import os
import sys
import math
import orjson
import psycopg2

from multiprocessing import Pool
from psycopg2.extras import execute_values, Json
from tqdm import tqdm

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import DB_CONFIG

BATCH_SIZE = 2000
MAX_WORKERS = 4


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def insert_batch(cursor, batch):

    query = """
        INSERT INTO threat_raw_events
        (source_type, file_name, payload)
        VALUES %s
    """

    execute_values(cursor, query, batch)


def process_file_chunk(file_chunk):

    conn = get_connection()
    cursor = conn.cursor()

    batch = []

    processed = 0

    for file_path in file_chunk:

        try:

            with open(file_path, "rb") as f:

                payload = orjson.loads(f.read())

                batch.append((
                    "cve",
                    os.path.basename(file_path),
                    Json(payload)
                ))

                processed += 1
                with open("logs/success.log", "a", encoding="utf-8") as log_file:
                    log_file.write(f"{file_path}\n")

                if len(batch) >= BATCH_SIZE:

                    insert_batch(cursor, batch)

                    conn.commit()

                    batch.clear()

        except Exception as e:

            with open("logs/failed.log", "a", encoding="utf-8") as log_file:
                log_file.write(f"{file_path} | {str(e)}\n")

    if batch:

        insert_batch(cursor, batch)

        conn.commit()

    cursor.close()
    conn.close()

    return processed


def chunkify(lst, n):

    return [lst[i:i + n] for i in range(0, len(lst), n)]


def ingest_directory(directory_path):

    files = []

    for root, _, filenames in os.walk(directory_path):

        for filename in filenames:

            if filename.endswith(".json"):

                files.append(os.path.join(root, filename))

    print(f"Found {len(files)} CVE files")

    chunk_size = math.ceil(len(files) / MAX_WORKERS)

    file_chunks = chunkify(files, chunk_size)

    total_processed = 0

    with Pool(processes=MAX_WORKERS) as pool:

        results = list(
            tqdm(
                pool.imap_unordered(process_file_chunk, file_chunks),
                total=len(file_chunks),
                desc="Workers"
            )
        )

    total_processed = sum(results)

    print(f"Total CVEs Inserted: {total_processed}")


if __name__ == "__main__":

    ingest_directory(
        r"C:\Users\pc\Desktop\CSP\cvelistV5-main\cves"
    )