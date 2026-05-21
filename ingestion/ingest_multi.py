import os
import math
import orjson
import psycopg2
from multiprocessing import Pool, cpu_count
from psycopg2.extras import execute_values, Json
from tqdm import tqdm

DB_CONFIG = {
    "host": "localhost",
    "database": "threat_intel",
    "user": "threatuser",
    "password": "threatpass",
    "port": 5432
}

BATCH_SIZE = 10000
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


def process_file_chunk(args):

    file_chunk, source_type = args

    conn = get_connection()
    cursor = conn.cursor()

    batch = []

    processed = 0

    for file_path in file_chunk:

        try:

            with open(file_path, "rb") as f:

                for line in f:

                    line = line.strip()

                    if not line:
                        continue

                    try:

                        payload = orjson.loads(line)

                        batch.append((
                            source_type,
                            os.path.basename(file_path),
                            Json(payload)
                        ))

                        processed += 1

                        if len(batch) >= BATCH_SIZE:

                            insert_batch(cursor, batch)

                            conn.commit()

                            batch.clear()

                    except Exception:
                        pass

        except Exception:
            pass

    if batch:

        insert_batch(cursor, batch)

        conn.commit()

    cursor.close()
    conn.close()

    return processed


def chunkify(lst, n):

    return [lst[i:i + n] for i in range(0, len(lst), n)]


def ingest_directory(directory_path, source_type):

    files = []

    for root, _, filenames in os.walk(directory_path):

        for filename in filenames:

            if filename.endswith(".processed") or filename.endswith(".json"):

                files.append(os.path.join(root, filename))

    print(f"Found {len(files)} files")

    chunk_size = math.ceil(len(files) / MAX_WORKERS)

    file_chunks = chunkify(files, chunk_size)

    tasks = [(chunk, source_type) for chunk in file_chunks]

    total_processed = 0

    with Pool(processes=MAX_WORKERS) as pool:

        results = list(
            tqdm(
                pool.imap_unordered(process_file_chunk, tasks),
                total=len(tasks),
                desc="Workers"
            )
        )

    total_processed = sum(results)

    print(f"Total Events Inserted: {total_processed}")


if __name__ == "__main__":

    ingest_directory(
        r"C:\Users\pc\Desktop\CSP\cowrie\\",
        "cowrie"
    )