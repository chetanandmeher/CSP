import sys
import os
import psycopg2
import re

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import DATABASE_URL

def main():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    
    # Let's find some suricata alerts containing 'CVE'
    cur.execute("""
        SELECT src_ip, alert_signature, category, severity, timestamp
        FROM suricata_alerts
        WHERE alert_signature ILIKE '%CVE%'
        LIMIT 10
    """)
    
    alerts = cur.fetchall()
    print(f"=== Suricata Alerts with CVE references ({len(alerts)} found) ===")
    for alert in alerts:
        src_ip, signature, cat, sev, ts = alert
        cve_match = re.search(r'(CVE-\d{4}-\d{4,})', signature, re.IGNORECASE)
        cve_id = cve_match.group(1).upper() if cve_match else None
        
        cve_detail = None
        if cve_id:
            cur.execute("""
                SELECT cve_id, title, description, base_score, base_severity
                FROM cve_records
                WHERE cve_id = %s
                LIMIT 1
            """, (cve_id,))
            cve_detail = cur.fetchone()
            
        print(f"\nIP: {src_ip} | Signature: {signature}")
        if cve_id:
            print(f"  - Extracted CVE: {cve_id}")
            if cve_detail:
                print(f"    Title: {cve_detail[1]}")
                print(f"    Severity: {cve_detail[4]} (Score: {cve_detail[3]})")
            else:
                print("    No cve_records entry found.")
                
    # Let's check how many total suricata signatures have CVEs
    cur.execute("SELECT COUNT(*) FROM suricata_alerts WHERE alert_signature ILIKE '%CVE%'")
    print(f"\nTotal alerts containing 'CVE': {cur.fetchone()[0]}")
    
    # Let's find how many have successful MITRE mappings in suricata_signature_category
    cur.execute("""
        SELECT COUNT(*) 
        FROM suricata_alerts a
        JOIN suricata_signature_category m 
        ON a.alert_signature ILIKE '%%' || m.signature_pattern || '%%'
    """)
    print(f"Total alerts mapping to a MITRE technique: {cur.fetchone()[0]}")
    
    cur.close()
    conn.close()

if __name__ == "__main__":
    main()
