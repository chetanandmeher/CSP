CREATE OR REPLACE VIEW unified_attacker_intelligence AS

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

FROM attacker_risk_scores;