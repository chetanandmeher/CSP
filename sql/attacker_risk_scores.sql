CREATE TABLE attacker_risk_scores (

    id BIGSERIAL PRIMARY KEY,

    src_ip TEXT,

    total_events INTEGER,

    unique_techniques INTEGER,

    unique_tactics INTEGER,

    suricata_events INTEGER,

    cowrie_events INTEGER,

    risk_score INTEGER,

    threat_level TEXT,

    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);