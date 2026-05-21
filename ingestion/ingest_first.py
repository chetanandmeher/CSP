import os
import sys
import orjson
import psycopg2
from psycopg2.extras import execute_values
from tqdm import tqdm

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import DB_CONFIG

BATCH_SIZE = 1000

def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def insert_batch(cursor, batch):

    query = """
        INSERT INTO threat_raw_events
        (source_type, file_name, payload)
        VALUES %s
    """

    execute_values(cursor, query, batch)

def ingest_directory(directory_path, source_type):

    conn = get_connection()
    cursor = conn.cursor()

    batch = []

    files = []

    for root, _, filenames in os.walk(directory_path):

        for filename in filenames:

            if filename.endswith(".processed") or filename.endswith(".json"):

                files.append(os.path.join(root, filename))

    print(f"Found {len(files)} files")

    for file_path in tqdm(files, desc="Processing files"):

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
                            psycopg2.extras.Json(payload)
                        ))

                        if len(batch) >= BATCH_SIZE:

                            insert_batch(cursor, batch)

                            conn.commit()

                            batch.clear()

                    except Exception as e:

                        print(f"JSON Error in {file_path}: {e}")

        except Exception as e:

            print(f"File Error {file_path}: {e}")

    if batch:

        insert_batch(cursor, batch)

        conn.commit()

    cursor.close()

    conn.close()

    print("Ingestion completed")

if __name__ == "__main__":

    ingest_directory(
        r"C:\Users\pc\Desktop\CSP\cowrie\\",
        "cowrie"
    )