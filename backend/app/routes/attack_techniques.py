from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.database import get_db

router = APIRouter()


@router.get("/top")
def get_top_attack_techniques(
    limit: int = 20,
    db: Session = Depends(get_db)
):

    query = text("""
        WITH suricata_agg AS (
            SELECT alert_signature, COUNT(*) as cnt
            FROM suricata_alerts
            GROUP BY alert_signature
        ),
        suricata_techniques AS (
            SELECT m.technique_id, m.technique_name, SUM(a.cnt) as occurrences
            FROM suricata_agg a
            JOIN suricata_signature_category m
            ON a.alert_signature ILIKE '%' || m.signature_pattern || '%'
            GROUP BY m.technique_id, m.technique_name
        ),
        cowrie_agg AS (
            SELECT eventid, COUNT(*) as cnt
            FROM cowrie_events
            GROUP BY eventid
        ),
        cowrie_techniques AS (
            SELECT m.technique_id, m.technique_name, SUM(c.cnt) as occurrences
            FROM cowrie_agg c
            JOIN cowrie_attack_mapping m
            ON c.eventid = m.eventid
            GROUP BY m.technique_id, m.technique_name
        ),
        all_techniques AS (
            SELECT technique_id, technique_name, occurrences FROM suricata_techniques
            UNION ALL
            SELECT technique_id, technique_name, occurrences FROM cowrie_techniques
        )
        SELECT technique_id, technique_name, SUM(occurrences) as occurrences
        FROM all_techniques
        GROUP BY technique_id, technique_name
        ORDER BY occurrences DESC
        LIMIT :limit
    """)

    result = db.execute(
        query,
        {"limit": limit}
    )

    techniques = [
        dict(row._mapping)
        for row in result
    ]

    return {
        "count": len(techniques),
        "results": techniques
    }