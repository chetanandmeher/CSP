CREATE INDEX idx_cowrie_src_ip
ON cowrie_events(src_ip);

CREATE INDEX idx_cowrie_timestamp
ON cowrie_events(timestamp);

CREATE INDEX idx_cowrie_eventid
ON cowrie_events(eventid);

CREATE INDEX idx_cowrie_session
ON cowrie_events(session);

CREATE INDEX idx_cowrie_protocol
ON cowrie_events(protocol);