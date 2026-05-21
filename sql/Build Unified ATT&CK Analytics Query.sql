WITH cowrie_data AS (

    SELECT

        c.src_ip,

        m.technique_id,

        m.technique_name,

        m.tactic,

        'cowrie' AS source

    FROM cowrie_events c

    JOIN cowrie_attack_mapping m
    ON c.eventid = m.eventid

),

suricata_data AS (

    SELECT

        s.src_ip,

        m.technique_id,

        m.technique_name,

        m.tactic,

        'suricata' AS source

    FROM suricata_alerts s

    JOIN suricata_signature_category m
    ON s.alert_signature ILIKE
       '%' || m.signature_pattern || '%'
)

SELECT

    src_ip,

    COUNT(*) AS total_attack_events,

    STRING_AGG(
        DISTINCT source,
        ', '
    ) AS telemetry_sources,

    STRING_AGG(
        DISTINCT technique_id,
        ', '
    ) AS techniques,

    STRING_AGG(
        DISTINCT technique_name,
        ', '
    ) AS technique_names,

    STRING_AGG(
        DISTINCT tactic,
        ', '
    ) AS tactics

FROM (

    SELECT * FROM cowrie_data

    UNION ALL

    SELECT * FROM suricata_data

) combined

GROUP BY src_ip

ORDER BY total_attack_events DESC

LIMIT 50;