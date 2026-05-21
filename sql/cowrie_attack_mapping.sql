CREATE TABLE cowrie_attack_mapping (

    id BIGSERIAL PRIMARY KEY,

    eventid TEXT,

    technique_id TEXT,

    technique_name TEXT,

    tactic TEXT
);  