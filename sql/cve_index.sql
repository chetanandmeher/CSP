CREATE INDEX idx_cve_cve_id
ON cve_records(cve_id);

CREATE INDEX idx_cve_vendor
ON cve_records(vendor_name);

CREATE INDEX idx_cve_product
ON cve_records(product_name);

CREATE INDEX idx_cve_severity
ON cve_records(base_severity);

CREATE INDEX idx_cve_score
ON cve_records(base_score);

CREATE INDEX idx_cve_cwe
ON cve_records(cwe_id);

CREATE INDEX idx_cve_published
ON cve_records(published_date);