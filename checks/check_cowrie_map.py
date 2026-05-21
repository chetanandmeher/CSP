import psycopg2

def main():
    conn = psycopg2.connect("postgresql://threatuser:threatpass@localhost:5432/threat_intel")
    cur = conn.cursor()
    
    cur.execute("SELECT * FROM cowrie_attack_mapping")
    print("=== Cowrie Attack Mapping ===")
    for r in cur.fetchall():
        print(r)
        
    cur.close()
    conn.close()

if __name__ == "__main__":
    main()
