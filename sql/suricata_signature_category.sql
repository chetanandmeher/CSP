CREATE TABLE suricata_signature_category (

    id BIGSERIAL PRIMARY KEY,

    signature_pattern TEXT,

    category TEXT,

    technique_id TEXT,

    technique_name TEXT,

    tactic TEXT
);