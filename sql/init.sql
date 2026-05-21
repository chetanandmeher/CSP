-- -- ============================================================
-- -- THREAT INTEL DATABASE SCHEMA
-- -- ============================================================

-- -- Enable required extensions
-- CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- for text search on CVE descriptions

-- -- ============================================================
-- -- 1. CVEs TABLE
-- -- ============================================================
-- CREATE TABLE IF NOT EXISTS cves (
--     id                  UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
--     cve_id              VARCHAR(30) UNIQUE NOT NULL,        -- e.g. CVE-2024-12345
--     year                INTEGER,                            -- extracted from cve_id
--     state               VARCHAR(20),                       -- PUBLISHED, REJECTED, etc.
--     assigner            VARCHAR(100),
--     date_published      TIMESTAMPTZ,
--     date_updated        TIMESTAMPTZ,
--     date_reserved       TIMESTAMPTZ,

--     -- Core content
--     description         TEXT,                              -- primary English description
--     problem_types       TEXT[],                            -- array of problem type strings
--     vendor              VARCHAR(255),
--     product             VARCHAR(255),
--     versions_affected   TEXT[],

--     -- CVSS scores (if present)
--     cvss_v3_score       NUMERIC(4,1),
--     cvss_v3_severity    VARCHAR(20),                       -- CRITICAL, HIGH, MEDIUM, LOW
--     cvss_v2_score       NUMERIC(4,1),

--     -- References
--     reference_urls      TEXT[],

--     -- Full raw JSON for anything not extracted above
--     raw_json            JSONB NOT NULL,

--     -- Metadata
--     ingested_at         TIMESTAMPTZ DEFAULT NOW()
-- );

-- -- Indexes for fast lookup and search
-- CREATE INDEX IF NOT EXISTS idx_cves_cve_id       ON cves(cve_id);
-- CREATE INDEX IF NOT EXISTS idx_cves_year         ON cves(year);
-- CREATE INDEX IF NOT EXISTS idx_cves_severity     ON cves(cvss_v3_severity);
-- CREATE INDEX IF NOT EXISTS idx_cves_description  ON cves USING gin(to_tsvector('english', COALESCE(description, '')));
-- CREATE INDEX IF NOT EXISTS idx_cves_raw          ON cves USING gin(raw_json);
-- CREATE INDEX IF NOT EXISTS idx_cves_vendor       ON cves(vendor);
-- CREATE INDEX IF NOT EXISTS idx_cves_product      ON cves(product);


-- -- ============================================================
-- -- 2. SURICATA ALERTS TABLE
-- -- ============================================================
-- CREATE TABLE IF NOT EXISTS suricata_alerts (
--     id                  UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
--     timestamp           TIMESTAMPTZ NOT NULL,
--     flow_id             BIGINT,
--     in_iface            VARCHAR(20),

--     -- Network info
--     src_ip              INET NOT NULL,
--     src_port            INTEGER,
--     dest_ip             INET NOT NULL,
--     dest_port           INTEGER,
--     proto               VARCHAR(10),
--     direction           VARCHAR(20),

--     -- Alert details
--     signature_id        INTEGER,
--     signature           TEXT,
--     category            VARCHAR(100),
--     severity            INTEGER,
--     action              VARCHAR(20),

--     -- Flow stats
--     pkts_toserver       INTEGER,
--     pkts_toclient       INTEGER,
--     bytes_toserver      INTEGER,
--     bytes_toclient      INTEGER,
--     flow_start          TIMESTAMPTZ,

--     -- Source file
--     source_file         VARCHAR(255),

--     -- Full raw JSON
--     raw_json            JSONB NOT NULL,

--     ingested_at         TIMESTAMPTZ DEFAULT NOW()
-- );

-- CREATE INDEX IF NOT EXISTS idx_suricata_timestamp    ON suricata_alerts(timestamp);
-- CREATE INDEX IF NOT EXISTS idx_suricata_src_ip       ON suricata_alerts(src_ip);
-- CREATE INDEX IF NOT EXISTS idx_suricata_dest_ip      ON suricata_alerts(dest_ip);
-- CREATE INDEX IF NOT EXISTS idx_suricata_sig_id       ON suricata_alerts(signature_id);
-- CREATE INDEX IF NOT EXISTS idx_suricata_severity     ON suricata_alerts(severity);
-- CREATE INDEX IF NOT EXISTS idx_suricata_dest_port    ON suricata_alerts(dest_port);


-- -- ============================================================
-- -- 3. COWRIE EVENTS TABLE
-- -- ============================================================
-- CREATE TABLE IF NOT EXISTS cowrie_events (
--     id                  UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
--     timestamp           TIMESTAMPTZ NOT NULL,
--     session             VARCHAR(50),
--     event_type          VARCHAR(50) NOT NULL,              -- cowrie.login.failed, cowrie.session.connect, etc.

--     -- Network info
--     src_ip              INET,
--     src_port            INTEGER,
--     dst_ip              INET,
--     dst_port            INTEGER,
--     protocol            VARCHAR(20),

--     -- Auth attempts
--     username            VARCHAR(255),
--     password            VARCHAR(255),
--     login_success       BOOLEAN,

--     -- Client fingerprint
--     ssh_version         VARCHAR(100),
--     hassh               VARCHAR(64),

--     -- Session info
--     duration_seconds    NUMERIC(10,2),
--     sensor              VARCHAR(100),
--     message             TEXT,

--     -- Commands executed (for cowrie.command.input events)
--     command             TEXT,

--     -- Source file
--     source_file         VARCHAR(255),

--     -- Full raw JSON
--     raw_json            JSONB NOT NULL,

--     ingested_at         TIMESTAMPTZ DEFAULT NOW()
-- );

-- CREATE INDEX IF NOT EXISTS idx_cowrie_timestamp   ON cowrie_events(timestamp);
-- CREATE INDEX IF NOT EXISTS idx_cowrie_src_ip      ON cowrie_events(src_ip);
-- CREATE INDEX IF NOT EXISTS idx_cowrie_event_type  ON cowrie_events(event_type);
-- CREATE INDEX IF NOT EXISTS idx_cowrie_session     ON cowrie_events(session);
-- CREATE INDEX IF NOT EXISTS idx_cowrie_username    ON cowrie_events(username);


-- -- ============================================================
-- -- 4. ATTACK <-> CVE MAPPING TABLE
-- -- ============================================================
-- CREATE TABLE IF NOT EXISTS attack_cve_mapping (
--     id                  UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

--     -- Source of the attack event
--     source_type         VARCHAR(20) NOT NULL,              -- 'suricata' or 'cowrie'
--     source_id           UUID NOT NULL,                     -- FK to suricata_alerts or cowrie_events

--     -- Linked CVE
--     cve_id              VARCHAR(30) NOT NULL,              -- FK to cves.cve_id

--     -- How the mapping was made
--     match_method        VARCHAR(50),                       -- 'port', 'signature', 'keyword', 'manual'
--     match_reason        TEXT,                              -- human-readable explanation
--     confidence          VARCHAR(20),                       -- 'high', 'medium', 'low'

--     mapped_at           TIMESTAMPTZ DEFAULT NOW(),

--     FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
-- );

-- CREATE INDEX IF NOT EXISTS idx_mapping_source_id   ON attack_cve_mapping(source_id);
-- CREATE INDEX IF NOT EXISTS idx_mapping_cve_id      ON attack_cve_mapping(cve_id);
-- CREATE INDEX IF NOT EXISTS idx_mapping_source_type ON attack_cve_mapping(source_type);
-- CREATE INDEX IF NOT EXISTS idx_mapping_confidence  ON attack_cve_mapping(confidence);


-- -- ============================================================
-- -- 5. KNOWN PORTS REFERENCE TABLE (helps with CVE mapping)
-- -- ============================================================
-- CREATE TABLE IF NOT EXISTS known_ports (
--     port                INTEGER PRIMARY KEY,
--     proto               VARCHAR(10),
--     service_name        VARCHAR(100),
--     description         TEXT,
--     common_cve_keywords TEXT[]
-- );

-- -- Seed with ports seen in our logs
-- INSERT INTO known_ports (port, proto, service_name, description, common_cve_keywords) VALUES
-- (22,   'TCP', 'SSH',  'Secure Shell',                ARRAY['ssh', 'openssh', 'secure shell']),
-- (5900, 'TCP', 'VNC',  'Virtual Network Computing',   ARRAY['vnc', 'remote desktop', 'rfb']),
-- (5903, 'TCP', 'VNC',  'VNC display :3',              ARRAY['vnc', 'remote desktop', 'rfb']),
-- (7070, 'TCP', 'RTSP', 'Real Time Streaming Protocol',ARRAY['rtsp', 'streaming']),
-- (5640, 'TCP', 'Unknown', 'Unknown service',          ARRAY[])
-- ON CONFLICT (port) DO NOTHING;


-- -- ============================================================
-- -- VIEWS FOR EASY QUERYING
-- -- ============================================================

-- -- Suricata alerts enriched with CVE info
-- CREATE OR REPLACE VIEW v_suricata_with_cves AS
-- SELECT
--     s.timestamp,
--     s.src_ip,
--     s.dest_ip,
--     s.dest_port,
--     s.proto,
--     s.signature,
--     s.severity,
--     s.category,
--     m.cve_id,
--     m.match_reason,
--     m.confidence,
--     c.description     AS cve_description,
--     c.cvss_v3_score,
--     c.cvss_v3_severity,
--     c.vendor,
--     c.product
-- FROM suricata_alerts s
-- LEFT JOIN attack_cve_mapping m ON m.source_id = s.id AND m.source_type = 'suricata'
-- LEFT JOIN cves c ON c.cve_id = m.cve_id;

-- -- Cowrie events enriched with CVE info
-- CREATE OR REPLACE VIEW v_cowrie_with_cves AS
-- SELECT
--     e.timestamp,
--     e.src_ip,
--     e.dst_port,
--     e.event_type,
--     e.username,
--     e.password,
--     e.ssh_version,
--     e.hassh,
--     e.session,
--     m.cve_id,
--     m.match_reason,
--     m.confidence,
--     c.description     AS cve_description,
--     c.cvss_v3_score,
--     c.cvss_v3_severity
-- FROM cowrie_events e
-- LEFT JOIN attack_cve_mapping m ON m.source_id = e.id AND m.source_type = 'cowrie'
-- LEFT JOIN cves c ON c.cve_id = m.cve_id;

-- -- All attacker IPs seen across both sources
-- CREATE OR REPLACE VIEW v_attacker_summary AS
-- SELECT
--     src_ip,
--     'suricata'     AS source,
--     COUNT(*)       AS event_count,
--     MIN(timestamp) AS first_seen,
--     MAX(timestamp) AS last_seen
-- FROM suricata_alerts
-- GROUP BY src_ip
-- UNION ALL
-- SELECT
--     src_ip,
--     'cowrie'       AS source,
--     COUNT(*),
--     MIN(timestamp),
--     MAX(timestamp)
-- FROM cowrie_events
-- WHERE src_ip IS NOT NULL
-- GROUP BY src_ip
-- ORDER BY event_count DESC;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS threat_raw_events (
    id BIGSERIAL PRIMARY KEY,
    source_type TEXT NOT NULL,
    file_name TEXT,
    payload JSONB NOT NULL,
    ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);