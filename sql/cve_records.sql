CREATE TABLE IF NOT EXISTS cve_records (

    id BIGSERIAL PRIMARY KEY,

    raw_event_id BIGINT,

    cve_id TEXT,

    published_date TIMESTAMPTZ,

    updated_date TIMESTAMPTZ,

    state TEXT,

    assigner_short_name TEXT,

    title TEXT,

    description TEXT,

    base_score NUMERIC,

    base_severity TEXT,

    attack_vector TEXT,

    attack_complexity TEXT,

    privileges_required TEXT,

    user_interaction TEXT,

    scope TEXT,

    confidentiality_impact TEXT,

    integrity_impact TEXT,

    availability_impact TEXT,

    vendor_name TEXT,

    product_name TEXT,

    affected_versions TEXT,

    cwe_id TEXT,

    cwe_description TEXT,

    references_count INTEGER,

    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);