from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
import re
import requests
from backend.app.database import get_db

router = APIRouter()


@router.get("/top")
def get_top_attackers(
    limit: int = 20,
    db: Session = Depends(get_db)
):

    query = text("""

        SELECT
            src_ip,
            total_events,
            unique_techniques,
            unique_tactics,
            suricata_events,
            cowrie_events,
            risk_score,
            threat_level

        FROM unified_attacker_intelligence

        ORDER BY risk_score DESC

        LIMIT :limit

    """)

    result = db.execute(
        query,
        {"limit": limit}
    )

    attackers = [
        dict(row._mapping)
        for row in result
    ]

    return {
        "count": len(attackers),
        "results": attackers
    }


@router.get("/details")
def get_attacker_details(
    src_ip: str,
    db: Session = Depends(get_db)
):

    query = text("""

        SELECT
            src_ip,
            total_events,
            unique_techniques,
            unique_tactics,
            suricata_events,
            cowrie_events,
            risk_score,
            threat_level,
            created_at

        FROM unified_attacker_intelligence

        WHERE src_ip = :src_ip

    """)

    result = db.execute(
        query,
        {"src_ip": src_ip}
    ).fetchone()

    if not result:

        return {
            "message":
            "Attacker not found"
        }

    attacker_data = dict(result._mapping)

    geo_data = {}

    try:

        # Clean IP: remove /32 CIDR mask if present
        clean_ip = src_ip.split("/")[0]

        geo_response = requests.get(
            f"http://ip-api.com/json/{clean_ip}"
        )

        if geo_response.status_code == 200:

            geo_json = geo_response.json()

            geo_data = {
                "country": geo_json.get("country"),
                "region": geo_json.get("regionName"),
                "city": geo_json.get("city"),
                "isp": geo_json.get("isp"),
                "asn": geo_json.get("as"),
                "lat": geo_json.get("lat"),
                "lon": geo_json.get("lon")
            }

    except Exception as e:

        print("GeoIP lookup failed:", e)

    attacker_data["geo"] = geo_data

    return attacker_data


@router.get("/dashboard/summary")
def get_dashboard_summary(
    db: Session = Depends(get_db)
):

    query = text("""

        SELECT

            (
                SELECT COUNT(DISTINCT src_ip)
                FROM attacker_risk_scores
            ) AS total_attackers,

            (
                SELECT COUNT(*)
                FROM attacker_risk_scores
                WHERE threat_level = 'critical'
            ) AS critical_attackers,

            (
                SELECT SUM(suricata_events)
                FROM attacker_risk_scores
            ) AS total_suricata_events,

            (
                SELECT SUM(cowrie_events)
                FROM attacker_risk_scores
            ) AS total_cowrie_events,

            (
                SELECT tactic

                FROM (
                    SELECT
                        tactic,
                        COUNT(*) AS cnt

                    FROM suricata_signature_category

                    GROUP BY tactic

                    ORDER BY cnt DESC

                    LIMIT 1
                ) t
            ) AS top_tactic

    """)

    result = db.execute(query).fetchone()

    return dict(result._mapping)


@router.get("/critical")
def get_critical_attackers(
    limit: int = 20,
    db: Session = Depends(get_db)
):

    query = text("""

        SELECT

            src_ip,

            total_events,

            unique_techniques,

            unique_tactics,

            suricata_events,

            cowrie_events,

            risk_score,

            threat_level

        FROM unified_attacker_intelligence

        WHERE threat_level = 'critical'

        ORDER BY risk_score DESC

        LIMIT :limit

    """)

    result = db.execute(
        query,
        {"limit": limit}
    )

    attackers = [
        dict(row._mapping)
        for row in result
    ]

    return {
        "count": len(attackers),
        "results": attackers
    }


@router.get("/{src_ip}/events")
def get_attacker_events(
    src_ip: str,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    # 1. Fetch Suricata NIDS alerts with MITRE mappings
    suricata_query = text("""
        SELECT 
            a.id,
            a.timestamp,
            a.src_ip::text as src_ip,
            a.dest_ip::text as dest_ip,
            a.src_port,
            a.dest_port,
            a.proto,
            a.app_proto,
            a.alert_signature,
            a.category,
            a.severity,
            a.flow_id,
            m.technique_id,
            m.technique_name,
            m.tactic,
            t.description as technique_description,
            t.url as technique_url
        FROM suricata_alerts a
        LEFT JOIN suricata_signature_category m ON a.alert_signature ILIKE '%%' || m.signature_pattern || '%%'
        LEFT JOIN attack_techniques t ON m.technique_id = t.technique_id
        WHERE a.src_ip = :src_ip
        ORDER BY a.timestamp DESC
        LIMIT :limit
    """)
    
    suricata_results = db.execute(
        suricata_query,
        {"src_ip": src_ip, "limit": limit}
    )
    
    events = []
    
    for row in suricata_results:
        r = dict(row._mapping)
        
        # Convert timestamp to ISO string format
        if r.get("timestamp"):
            r["timestamp"] = r["timestamp"].isoformat()
            
        r["source_type"] = "suricata"
        events.append(r)
        
    # 2. Fetch Cowrie honeypot events with MITRE mappings
    cowrie_query = text("""
        SELECT 
            c.id,
            c.timestamp,
            c.src_ip::text as src_ip,
            c.dst_ip::text as dest_ip,
            c.src_port,
            c.dst_port as dest_port,
            c.protocol as proto,
            c.eventid,
            c.message as alert_signature,
            c.sensor as category,
            m.technique_id,
            m.technique_name,
            m.tactic,
            t.description as technique_description,
            t.url as technique_url
        FROM cowrie_events c
        LEFT JOIN cowrie_attack_mapping m ON c.eventid = m.eventid
        LEFT JOIN attack_techniques t ON m.technique_id = t.technique_id
        WHERE c.src_ip = :src_ip
        ORDER BY c.timestamp DESC
        LIMIT :limit
    """)
    
    cowrie_results = db.execute(
        cowrie_query,
        {"src_ip": src_ip, "limit": limit}
    )
    
    for row in cowrie_results:
        r = dict(row._mapping)
        
        if r.get("timestamp"):
            r["timestamp"] = r["timestamp"].isoformat()
            
        r["source_type"] = "cowrie"
        
        # Infer severity for honeypot events
        # Successful SSH logins are CRITICAL (severity 1), others are HIGH (severity 2)
        eventid = r.get("eventid")
        if eventid == "cowrie.login.success":
            r["severity"] = 1
        elif eventid == "cowrie.login.failed":
            r["severity"] = 3
        else:
            r["severity"] = 2
            
        events.append(r)
        
    # 3. Sort chronologically (newest first)
    events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    # Slice to combined limit
    events = events[:limit]
    
    # Cache for CVE lookups in this request to avoid redundant queries
    cve_cache = {}
    
    # 4. Enrich events with CVE details
    for e in events:
        sig = e.get("alert_signature", "") or ""
        cve_match = re.search(r'(CVE-\d{4}-\d{4,})', sig, re.IGNORECASE)
        
        e["cve_id"] = None
        e["cve_details"] = None
        
        if cve_match:
            cve_id = cve_match.group(1).upper()
            e["cve_id"] = cve_id
            
            if cve_id in cve_cache:
                e["cve_details"] = cve_cache[cve_id]
            else:
                cve_query = text("""
                    SELECT 
                        cve_id,
                        title,
                        description,
                        base_score,
                        base_severity,
                        attack_vector,
                        vendor_name,
                        product_name,
                        affected_versions
                    FROM cve_records
                    WHERE cve_id = :cve_id
                    LIMIT 1
                """)
                
                cve_row = db.execute(cve_query, {"cve_id": cve_id}).fetchone()
                if cve_row:
                    cve_data = dict(cve_row._mapping)
                    # Convert base_score (decimal) to float for easy JSON serialization
                    if cve_data.get("base_score") is not None:
                        cve_data["base_score"] = float(cve_data["base_score"])
                    cve_cache[cve_id] = cve_data
                    e["cve_details"] = cve_data
                else:
                    cve_cache[cve_id] = None
                    
    return {
        "src_ip": src_ip,
        "count": len(events),
        "results": events
    }
