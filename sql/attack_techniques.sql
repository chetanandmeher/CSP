CREATE TABLE attack_techniques (

    id BIGSERIAL PRIMARY KEY,

    technique_stix_id TEXT,

    technique_id TEXT,

    name TEXT,

    description TEXT,

    tactic TEXT,

    platforms TEXT[],

    detection TEXT,

    created TIMESTAMPTZ,

    modified TIMESTAMPTZ,

    url TEXT
);