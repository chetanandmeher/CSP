INSERT INTO attacker_risk_scores (
    src_ip,
    total_events,
    unique_techniques,
    unique_tactics,
    suricata_events,
    cowrie_events,
    risk_score,
    threat_level
)

WITH combined_data AS (

    SELECT
        c.src_ip,
        m.technique_id,
        m.tactic,
        'cowrie' AS source,

        CASE
            WHEN m.tactic = 'credential-access' THEN 30
            WHEN m.tactic = 'execution' THEN 35
            WHEN m.tactic = 'lateral-movement' THEN 40
            WHEN m.tactic = 'reconnaissance' THEN 15
            ELSE 10
        END AS tactic_score

    FROM cowrie_events c
    JOIN cowrie_attack_mapping m
        ON c.eventid = m.eventid

    UNION ALL

    SELECT
        s.src_ip,
        m.technique_id,
        m.tactic,
        'suricata' AS source,

        CASE
            WHEN m.tactic = 'initial-access' THEN 50
            WHEN m.tactic = 'credential-access' THEN 40
            WHEN m.tactic = 'execution' THEN 40
            WHEN m.tactic = 'lateral-movement' THEN 35
            WHEN m.tactic = 'discovery' THEN 20
            WHEN m.tactic = 'reconnaissance' THEN 15
            ELSE 10
        END AS tactic_score

    FROM suricata_alerts s
    JOIN suricata_signature_category m
        ON s.alert_signature ILIKE
           '%' || m.signature_pattern || '%'
)

SELECT
    src_ip,

    COUNT(*) AS total_events,

    COUNT(DISTINCT technique_id)
        AS unique_techniques,

    COUNT(DISTINCT tactic)
        AS unique_tactics,

    COUNT(*) FILTER (
        WHERE source = 'suricata'
    ) AS suricata_events,

    COUNT(*) FILTER (
        WHERE source = 'cowrie'
    ) AS cowrie_events,

    LEAST(
        100,

        ROUND(
            (LOG(GREATEST(COUNT(*), 1)) * 10)
            + (COUNT(DISTINCT technique_id) * 12)
            + (COUNT(DISTINCT tactic) * 15)
            + AVG(tactic_score)
            + (
                CASE
                    WHEN COUNT(DISTINCT source) > 1
                        THEN 20
                    ELSE 0
                END
            )
        )

    ) AS risk_score,

    CASE

        WHEN LEAST(
            100,
            ROUND(
                (LOG(GREATEST(COUNT(*), 1)) * 10)
                + (COUNT(DISTINCT technique_id) * 12)
                + (COUNT(DISTINCT tactic) * 15)
                + AVG(tactic_score)
            )
        ) >= 85

        THEN 'critical'

        WHEN LEAST(
            100,
            ROUND(
                (LOG(GREATEST(COUNT(*), 1)) * 10)
                + (COUNT(DISTINCT technique_id) * 12)
                + (COUNT(DISTINCT tactic) * 15)
                + AVG(tactic_score)
            )
        ) >= 65

        THEN 'high'

        WHEN LEAST(
            100,
            ROUND(
                (LOG(GREATEST(COUNT(*), 1)) * 10)
                + (COUNT(DISTINCT technique_id) * 12)
                + (COUNT(DISTINCT tactic) * 15)
                + AVG(tactic_score)
            )
        ) >= 40

        THEN 'medium'

        ELSE 'low'

    END AS threat_level

FROM combined_data

GROUP BY src_ip;