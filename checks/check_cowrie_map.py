import sys
import os
import psycopg2

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import DATABASE_URL

def main():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    
    cur.execute("SELECT * FROM cowrie_attack_mapping")
    print("=== Cowrie Attack Mapping ===")
    for r in cur.fetchall():
        print(r)
        
    cur.close()
    conn.close()

if __name__ == "__main__":
    main()
