from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.database import get_db

router = APIRouter()


@router.get("/top")
def get_top_attack_tactics(
    limit: int = 20,
    db: Session = Depends(get_db)
):

    query = text("""
        WITH suricata_agg AS (
            SELECT alert_signature, COUNT(*) as cnt
            FROM suricata_alerts
            GROUP BY alert_signature
        ),
        suricata_tactics AS (
            SELECT m.tactic, SUM(a.cnt) as occurrences
            FROM suricata_agg a
            JOIN suricata_signature_category m
            ON a.alert_signature ILIKE '%' || m.signature_pattern || '%'
            GROUP BY m.tactic
        ),
        cowrie_agg AS (
            SELECT eventid, COUNT(*) as cnt
            FROM cowrie_events
            GROUP BY eventid
        ),
        cowrie_tactics AS (
            SELECT m.tactic, SUM(c.cnt) as occurrences
            FROM cowrie_agg c
            JOIN cowrie_attack_mapping m
            ON c.eventid = m.eventid
            GROUP BY m.tactic
        ),
        all_tactics AS (
            SELECT tactic, occurrences FROM suricata_tactics
            UNION ALL
            SELECT tactic, occurrences FROM cowrie_tactics
        )
        SELECT tactic, SUM(occurrences) as occurrences
        FROM all_tactics
        GROUP BY tactic
        ORDER BY occurrences DESC
        LIMIT :limit
    """)

    result = db.execute(
        query,
        {"limit": limit}
    )

    tactics = [
        dict(row._mapping)
        for row in result
    ]

    return {
        "count": len(tactics),
        "results": tactics
    }