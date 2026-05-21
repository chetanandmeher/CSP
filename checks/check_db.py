import psycopg2

def print_columns(cur, table):
    cur.execute(f"SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '{table}'")
    print(f"\nColumns for {table}:")
    for r in cur.fetchall():
        print(f"  - {r[0]} ({r[1]})")

def main():
    try:
        conn = psycopg2.connect("postgresql://threatuser:threatpass@localhost:5432/threat_intel")
        cur = conn.cursor()
        
        print_columns(cur, "cve_records")
        print_columns(cur, "attack_techniques")
        print_columns(cur, "suricata_alerts")
        print_columns(cur, "cowrie_events")
        print_columns(cur, "cowrie_attack_mapping")
        print_columns(cur, "suricata_signature_category")
        print_columns(cur, "unified_attacker_intelligence")
        
        cur.close()
        conn.close()
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
