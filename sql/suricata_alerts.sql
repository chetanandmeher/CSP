CREATE TABLE suricata_alerts (

    id BIGSERIAL PRIMARY KEY,

    raw_event_id BIGINT,

    timestamp TIMESTAMPTZ,

    src_ip INET,
    dest_ip INET,

    src_port INTEGER,
    dest_port INTEGER,

    proto TEXT,
    app_proto TEXT,

    event_type TEXT,

    alert_signature TEXT,
    alert_signature_id BIGINT,

    category TEXT,
    severity INTEGER,

    flow_id BIGINT,

    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);