CREATE INDEX idx_suricata_src_ip
ON suricata_alerts(src_ip);

CREATE INDEX idx_suricata_dest_ip
ON suricata_alerts(dest_ip);

CREATE INDEX idx_suricata_timestamp
ON suricata_alerts(timestamp);

CREATE INDEX idx_suricata_signature
ON suricata_alerts(alert_signature);

CREATE INDEX idx_suricata_signature_id
ON suricata_alerts(alert_signature_id);

CREATE INDEX idx_suricata_severity
ON suricata_alerts(severity);

CREATE INDEX idx_suricata_event_type
ON suricata_alerts(event_type);