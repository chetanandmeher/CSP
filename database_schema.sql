-- Security Data PostgreSQL Database Schema
-- Database: security_data

-- Drop existing tables if they exist
DROP TABLE IF EXISTS cowrie_sessions CASCADE;
DROP TABLE IF EXISTS cowrie_login_attempts CASCADE;
DROP TABLE IF EXISTS cowrie_commands CASCADE;
DROP TABLE IF EXISTS cowrie_downloads CASCADE;
DROP TABLE IF EXISTS cowrie_client_versions CASCADE;
DROP TABLE IF EXISTS suricata_alerts CASCADE;
DROP TABLE IF EXISTS suricata_flows CASCADE;
DROP TABLE IF EXISTS suricata_dns CASCADE;
DROP TABLE IF EXISTS suricata_http CASCADE;
DROP TABLE IF EXISTS cve_records CASCADE;
DROP TABLE IF EXISTS cve_references CASCADE;
DROP TABLE IF EXISTS cve_affected_products CASCADE;

-- ============================================
-- COWRIE HONEYPOT TABLES
-- ============================================

-- Cowrie Sessions Table
CREATE TABLE cowrie_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(50) UNIQUE NOT NULL,
    src_ip INET NOT NULL,
    src_port INTEGER,
    dst_ip INET,
    dst_port INTEGER,
    protocol VARCHAR(20),
    sensor VARCHAR(100),
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    duration FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
--    INDEX idx_cowrie_session_id (session_id),
--    INDEX idx_cowrie_src_ip (src_ip),
--    INDEX idx_cowrie_start_time (start_time)
);

-- Cowrie Login Attempts Table
CREATE TABLE cowrie_login_attempts (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(50) REFERENCES cowrie_sessions(session_id),
    src_ip INET NOT NULL,
    username VARCHAR(255),
    password VARCHAR(255),
    success BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMP,
    sensor VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
--    INDEX idx_login_session (session_id),
--    INDEX idx_login_username (username),
--    INDEX idx_login_timestamp (timestamp)
);

-- Cowrie Commands Table
CREATE TABLE cowrie_commands (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(50) REFERENCES cowrie_sessions(session_id),
    src_ip INET,
    command TEXT,
    timestamp TIMESTAMP,
    sensor VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
--    INDEX idx_cmd_session (session_id),
--    INDEX idx_cmd_timestamp (timestamp)
);

-- Cowrie Downloads Table
CREATE TABLE cowrie_downloads (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(50) REFERENCES cowrie_sessions(session_id),
    src_ip INET,
    url TEXT,
    outfile VARCHAR(500),
    shasum VARCHAR(64),
    timestamp TIMESTAMP,
    sensor VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
--    INDEX idx_download_session (session_id),
--    INDEX idx_download_shasum (shasum)
);

-- Cowrie Client Versions Table
CREATE TABLE cowrie_client_versions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(50) REFERENCES cowrie_sessions(session_id),
    src_ip INET,
    version VARCHAR(255),
    hassh VARCHAR(64),
    timestamp TIMESTAMP,
    sensor VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
--    INDEX idx_client_hassh (hassh)
);

-- ============================================
-- SURICATA IDS/IPS TABLES
-- ============================================

-- Suricata Alerts Table
CREATE TABLE suricata_alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    flow_id BIGINT,
    in_iface VARCHAR(50),
    event_type VARCHAR(50),
    src_ip INET NOT NULL,
    src_port INTEGER,
    dest_ip INET NOT NULL,
    dest_port INTEGER,
    proto VARCHAR(20),
    ip_version INTEGER,
    alert_action VARCHAR(50),
    alert_gid INTEGER,
    alert_signature_id INTEGER,
    alert_rev INTEGER,
    alert_signature TEXT,
    alert_category VARCHAR(255),
    alert_severity INTEGER,
    direction VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
--    INDEX idx_suricata_timestamp (timestamp),
--    INDEX idx_suricata_src_ip (src_ip),
--    INDEX idx_suricata_dest_ip (dest_ip),
--    INDEX idx_suricata_signature_id (alert_signature_id),
--    INDEX idx_suricata_flow_id (flow_id)
);

-- Suricata Flows Table
CREATE TABLE suricata_flows (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    flow_id BIGINT UNIQUE,
    src_ip INET NOT NULL,
    src_port INTEGER,
    dest_ip INET NOT NULL,
    dest_port INTEGER,
    proto VARCHAR(20),
    pkts_toserver INTEGER,
    pkts_toclient INTEGER,
    bytes_toserver BIGINT,
    bytes_toclient BIGINT,
    flow_start TIMESTAMP,
    flow_end TIMESTAMP,
    flow_age INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
--    INDEX idx_flow_id (flow_id),
--    INDEX idx_flow_src_ip (src_ip),
--    INDEX idx_flow_dest_ip (dest_ip)
);

-- Suricata DNS Table
CREATE TABLE suricata_dns (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    flow_id BIGINT,
    src_ip INET,
    dest_ip INET,
    dns_type VARCHAR(20),
    dns_id INTEGER,
    dns_rrname VARCHAR(255),
    dns_rrtype VARCHAR(20),
    dns_rcode VARCHAR(50),
    dns_answers JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
--    INDEX idx_dns_rrname (dns_rrname),
--    INDEX idx_dns_timestamp (timestamp)
);

-- Suricata HTTP Table
CREATE TABLE suricata_http (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    flow_id BIGINT,
    src_ip INET,
    dest_ip INET,
    http_hostname VARCHAR(255),
    http_url TEXT,
    http_method VARCHAR(20),
    http_protocol VARCHAR(20),
    http_status INTEGER,
    http_length INTEGER,
    http_user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
--    INDEX idx_http_hostname (http_hostname),
--    INDEX idx_http_timestamp (timestamp)
);

-- ============================================
-- CVE DATABASE TABLES
-- ============================================

-- CVE Records Table
CREATE TABLE cve_records (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    state VARCHAR(50),
    assigner_org_id VARCHAR(100),
    date_published TIMESTAMP,
    date_updated TIMESTAMP,
    date_reserved TIMESTAMP,
    title TEXT,
    description TEXT,
    cvss_version VARCHAR(10),
    cvss_score FLOAT,
    cvss_severity VARCHAR(20),
    cvss_vector VARCHAR(255),
    cwe_id VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
--    INDEX idx_cve_id (cve_id),
--    INDEX idx_cve_score (cvss_score),
--    INDEX idx_cve_published (date_published)
);

-- CVE References Table
CREATE TABLE cve_references (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) REFERENCES cve_records(cve_id),
    url TEXT,
    reference_name VARCHAR(255),
    reference_tags TEXT[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
--    INDEX idx_ref_cve_id (cve_id)
);

-- CVE Affected Products Table
CREATE TABLE cve_affected_products (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) REFERENCES cve_records(cve_id),
    vendor VARCHAR(255),
    product VARCHAR(255),
    version VARCHAR(100),
    version_type VARCHAR(50),
    platform VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
--    INDEX idx_affected_cve_id (cve_id),
--    INDEX idx_affected_vendor (vendor),
--    INDEX idx_affected_product (product)
);

-- ============================================
-- VIEWS FOR COMMON QUERIES
-- ============================================

-- View: Top Attacking IPs from Cowrie
CREATE VIEW v_top_cowrie_attackers AS
SELECT 
    src_ip,
    COUNT(DISTINCT session_id) as session_count,
    COUNT(*) as login_attempts,
    COUNT(CASE WHEN success = TRUE THEN 1 END) as successful_logins
FROM cowrie_login_attempts
GROUP BY src_ip
ORDER BY login_attempts DESC;

-- View: Top Attacked Ports from Suricata
CREATE VIEW v_top_attacked_ports AS
SELECT 
    dest_port,
    COUNT(*) as alert_count,
    COUNT(DISTINCT src_ip) as unique_attackers
FROM suricata_alerts
GROUP BY dest_port
ORDER BY alert_count DESC;

-- View: Most Common Cowrie Credentials
CREATE VIEW v_common_credentials AS
SELECT 
    username,
    password,
    COUNT(*) as attempt_count,
    COUNT(DISTINCT src_ip) as unique_ips
FROM cowrie_login_attempts
GROUP BY username, password
ORDER BY attempt_count DESC;

-- View: High Severity CVEs
CREATE VIEW v_high_severity_cves AS
SELECT 
    cve_id,
    title,
    cvss_score,
    cvss_severity,
    date_published,
    description
FROM cve_records
WHERE cvss_score >= 7.0
ORDER BY cvss_score DESC, date_published DESC;

-- View: Suricata Alert Summary
CREATE VIEW v_suricata_alert_summary AS
SELECT 
    alert_signature,
    alert_category,
    alert_severity,
    COUNT(*) as alert_count,
    COUNT(DISTINCT src_ip) as unique_sources,
    COUNT(DISTINCT dest_ip) as unique_destinations,
    MIN(timestamp) as first_seen,
    MAX(timestamp) as last_seen
FROM suricata_alerts
GROUP BY alert_signature, alert_category, alert_severity
ORDER BY alert_count DESC;

-- ============================================
-- GRANT PERMISSIONS (adjust as needed)
-- ============================================

-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO your_username;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO your_username;
-- Indexes
CREATE INDEX idx_cowrie_session_id ON cowrie_sessions(session_id);
CREATE INDEX idx_cowrie_src_ip ON cowrie_sessions(src_ip);
CREATE INDEX idx_cowrie_start_time ON cowrie_sessions(start_time);
CREATE INDEX idx_login_session ON cowrie_login_attempts(session_id);
CREATE INDEX idx_login_username ON cowrie_login_attempts(username);
CREATE INDEX idx_login_timestamp ON cowrie_login_attempts(timestamp);
CREATE INDEX idx_cmd_session ON cowrie_commands(session_id);
CREATE INDEX idx_cmd_timestamp ON cowrie_commands(timestamp);
CREATE INDEX idx_download_session ON cowrie_downloads(session_id);
CREATE INDEX idx_download_shasum ON cowrie_downloads(shasum);
CREATE INDEX idx_client_hassh ON cowrie_client_versions(hassh);
CREATE INDEX idx_suricata_timestamp ON suricata_alerts(timestamp);
CREATE INDEX idx_suricata_src_ip ON suricata_alerts(src_ip);
CREATE INDEX idx_suricata_dest_ip ON suricata_alerts(dest_ip);
CREATE INDEX idx_suricata_signature_id ON suricata_alerts(alert_signature_id);
CREATE INDEX idx_suricata_flow_id ON suricata_alerts(flow_id);
CREATE INDEX idx_flow_id ON suricata_flows(flow_id);
CREATE INDEX idx_flow_src_ip ON suricata_flows(src_ip);
CREATE INDEX idx_flow_dest_ip ON suricata_flows(dest_ip);
CREATE INDEX idx_dns_rrname ON suricata_dns(dns_rrname);
CREATE INDEX idx_dns_timestamp ON suricata_dns(timestamp);
CREATE INDEX idx_http_hostname ON suricata_http(http_hostname);
CREATE INDEX idx_http_timestamp ON suricata_http(timestamp);
CREATE INDEX idx_cve_id ON cve_records(cve_id);
CREATE INDEX idx_cve_score ON cve_records(cvss_score);
CREATE INDEX idx_cve_published ON cve_records(date_published);
CREATE INDEX idx_ref_cve_id ON cve_references(cve_id);
CREATE INDEX idx_affected_cve_id ON cve_affected_products(cve_id);
CREATE INDEX idx_affected_vendor ON cve_affected_products(vendor);
CREATE INDEX idx_affected_product ON cve_affected_products(product);
