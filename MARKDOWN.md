# CSP Threat Intelligence Platform Progress

Enterprise-grade Cyber Threat Intelligence (CTI) and SOC analytics platform built using FastAPI, PostgreSQL, Docker, React, and MITRE ATT&CK enrichment.

---

# Project Goal

Build a unified cyber threat intelligence platform capable of:

- ingesting large-scale security telemetry
- parsing structured threat data
- enriching telemetry with MITRE ATT&CK intelligence
- correlating attacker behaviors
- generating attacker-centric analytics
- visualizing operational SOC intelligence
- supporting analyst investigation workflows

---

# Current Architecture

```text
Suricata IDS
      +
Cowrie Honeypot
      +
CVE Intelligence
      +
MITRE ATT&CK
      ↓
Unified Threat Intelligence Platform
      ↓
FastAPI Backend APIs
      ↓
React SOC Dashboard
      ↓
Interactive Threat Investigation Console
```

---

# Completed Work

# 1. Dockerized Infrastructure

## Completed

- PostgreSQL containerized
- pgAdmin containerized
- Docker Compose setup completed
- Persistent Docker volumes configured
- Environment cleanup completed
- Docker networking configured

## Active Containers

- threat_intel_db
- threat_intel_pgadmin

## Infrastructure Status

| Service | Status |
|---|---|
| PostgreSQL | ✅ |
| pgAdmin | ✅ |
| Docker Compose | ✅ |
| Persistent Volumes | ✅ |

---

# 2. Raw Data Ingestion Layer

## Structured Table

```sql
threat_raw_events
```

## Data Sources Integrated

- Suricata IDS telemetry
- Cowrie honeypot telemetry
- CVE/NVD intelligence feeds

## Features Implemented

- raw JSON storage
- scalable ingestion pipeline
- streaming inserts
- source_type segregation
- structured ingestion validation

---

# 3. Suricata Structured Parsing

## Structured Table

```sql
suricata_alerts
```

## Parsed Fields

- src_ip
- dest_ip
- ports
- protocol
- alert_signature
- severity
- timestamps
- flow metadata

## Features Implemented

- batch parsing
- fallback inserts
- transaction rollback recovery
- parser validation
- structured indexing
- failure logging

## Validation

- row count validation completed
- parsing integrity verified
- database indexing validated

---

# 4. Cowrie Structured Parsing

## Structured Table

```sql
cowrie_events
```

## Parsed Fields

- eventid
- src_ip
- username
- password
- command input
- session data
- protocol
- timestamps

## Features Implemented

- ETL parsing
- fallback insert recovery
- structured error logging
- parser validation
- indexing
- transaction rollback handling

## Validation

- successful parsing completed
- telemetry integrity verified

---

# 5. CVE Intelligence Pipeline

## Structured Table

```sql
cve_records
```

## Parsed Intelligence

- CVE IDs
- CVSS scores
- severity classifications
- attack vectors
- vendors/products
- CWE mappings
- references
- timestamps

## Features Implemented

- semi-structured JSON extraction
- sparse field handling
- validation framework
- scalable ETL pipeline
- structured logging
- indexing optimization

## Validation

- parser validation completed
- NULL analysis completed
- row integrity verified

---

# 6. MITRE ATT&CK Integration

## Dataset Integrated

- Enterprise ATT&CK STIX dataset

## Dataset Path

```text
data/mitre/enterprise-attack.json
```

## MITRE SDK

```text
mitreattack-python
```

## Structured Table

```sql
attack_techniques
```

## Parsed ATT&CK Intelligence

- technique IDs
- technique names
- tactics
- platforms
- detection guidance
- ATT&CK URLs
- STIX identifiers

## Features Implemented

- STIX JSON parser
- structured ATT&CK ingestion
- parser validation
- JSONL failure logging
- ATT&CK enrichment APIs

## Validation

- expected vs parsed count verification
- parser integrity validated

---

# 7. ATT&CK Mapping Layer

# Cowrie ATT&CK Mapping

## Table

```sql
cowrie_attack_mapping
```

## ATT&CK Behaviors Mapped

- T1110 - Brute Force
- T1059 - Command and Scripting Interpreter
- T1021 - Remote Services
- T1595 - Active Scanning
- T1090 - Proxy

## Outcome

Cowrie telemetry became ATT&CK-aware.

---

# Suricata ATT&CK Mapping

## Table

```sql
suricata_signature_category
```

## Features Implemented

- signature normalization
- category-based enrichment
- semantic ATT&CK mapping
- reusable detection enrichment

## ATT&CK Techniques Mapped

- T1046 - Network Service Discovery
- T1110 - Brute Force
- T1190 - Exploit Public-Facing Application
- T1210 - Exploitation of Remote Services
- T1021 - Remote Services
- T1595 - Active Scanning
- T1083 - File and Directory Discovery

## Outcome

Suricata IDS telemetry is now ATT&CK-enriched.

---

# 8. Behavioral Analytics Layer

## Implemented Analytics

### Unified Attacker Profiling

- attacker IP aggregation
- ATT&CK technique aggregation
- ATT&CK tactic aggregation
- telemetry source aggregation

### Threat Intelligence Analytics

- top attackers
- top techniques
- top tactics
- reconnaissance analytics
- credential-access analytics
- exploitation analytics
- lateral movement analytics

### Cross-Source Correlation

- Suricata + Cowrie overlap
- attacker-centric aggregation
- multi-source threat visibility

---

# 9. Engineering Features

# Reliability

- transaction rollback handling
- row-level fallback inserts
- parser validation
- integrity checks
- ETL batch recovery

# Observability

- JSONL failure logs
- contextual error logging
- traceback capture
- validation reporting
- parser metrics

# Performance

- PostgreSQL indexing
- optimized joins
- scalable ETL batching
- streaming parsers

---

# 10. Unified Threat Scoring Engine

## Structured Table

```sql
attacker_risk_scores
```

## Features Implemented

- unified attacker aggregation
- telemetry scoring
- ATT&CK tactic scoring
- ATT&CK technique diversity scoring
- logarithmic risk normalization
- behavioral prioritization

## Scoring Signals

- Suricata telemetry
- Cowrie telemetry
- ATT&CK tactics
- ATT&CK techniques
- behavioral diversity
- tactic severity weighting
- cross-source visibility

## Threat Levels

- low
- medium
- high
- critical

## Engineering Improvements

- normalized scoring
- capped risk range (0–100)
- mathematically stable scoring model
- SOC-style prioritization logic

---

# 11. Unified Intelligence Views

## View Created

```sql
unified_attacker_intelligence
```

## Purpose

- centralized attacker intelligence layer
- reusable analytics abstraction
- simplified API querying
- simplified dashboard integration

## Exposed Intelligence

- attacker IP
- total events
- ATT&CK techniques
- ATT&CK tactics
- telemetry source counts
- risk score
- threat level

---

# 12. FastAPI Backend APIs

## Backend Framework

```text
FastAPI
```

## Implemented Routes

### Attackers APIs

| Endpoint | Description |
|---|---|
| `/attackers/dashboard/summary` | Dashboard intelligence metrics |
| `/attackers/critical` | Critical attacker feed |
| `/attackers/details` | Detailed attacker intelligence |
| `/attackers/top` | Top risk attackers |

---

### MITRE APIs

| Endpoint | Description |
|---|---|
| `/mitre/technique/{id}` | ATT&CK technique enrichment |
| `/mitre/top-techniques/details` | Enriched ATT&CK analytics |

---

### ATT&CK Analytics APIs

| Endpoint | Description |
|---|---|
| `/attack-techniques/top` | Top ATT&CK techniques |
| `/attack-tactics/top` | Top ATT&CK tactics |

---

# 13. React SOC Dashboard

## Frontend Stack

- React 19
- TypeScript
- Vite
- Recharts
- Glassmorphism UI

## Dashboard Features

### Executive Overview

- Active Threat Actors
- Critical Threat Actors
- Total Events
- ATT&CK Analytics
- Threat Telemetry

### Critical Attackers Table

- live PostgreSQL data
- threat severity indicators
- attacker risk scoring
- operational telemetry

### ATT&CK Analytics

- ATT&CK tactics visualization
- dynamic analytics
- MITRE enrichment integration

### Interactive Investigation Workflow

Implemented:

```text
Click Attacker
      ↓
Open Side Investigation Panel
      ↓
Fetch Live Backend Intelligence
      ↓
Display Threat Analytics
```

---

# 14. Interactive Threat Investigation Panel

## Features Implemented

- attacker selection workflow
- live backend intelligence fetching
- risk score visualization
- threat level classification
- total event visibility
- ATT&CK technique counts
- tactical action buttons

## SOC UI Features

- cyberpunk SOC styling
- neon intelligence indicators
- glassmorphism panels
- tactical controls
- operational threat layout

## Tactical Controls

- Isolate Host
- Export IOC
- Open Timeline
- Generate Report

---

# 15. MITRE ATT&CK Intelligence Enrichment

## Features Implemented

- dynamic technique lookup
- tactic extraction
- STIX intelligence parsing
- enriched ATT&CK analytics
- top techniques enrichment

## Current Intelligence Capabilities

- ATT&CK tactic analytics
- ATT&CK technique analytics
- attacker-centric ATT&CK profiling
- cross-source ATT&CK correlation

---

# Current Platform Maturity

```text
Raw Ingestion                     ✅
Structured Parsing                ✅
Threat Intelligence               ✅
MITRE ATT&CK Integration          ✅
Behavioral Analytics              ✅
Cross-Source Correlation          ✅
Threat Scoring                    ✅
FastAPI Backend                   ✅
Docker Infrastructure             ✅
React SOC Dashboard               ✅
Investigation Workflow            ✅
Operational CTI Dashboard         ✅
```

---

# Current Capabilities

## Backend

- FastAPI APIs
- PostgreSQL intelligence layer
- ATT&CK enrichment APIs
- threat scoring engine
- attacker analytics

## Frontend

- SOC dashboard
- ATT&CK analytics
- threat investigation panel
- tactical analyst workflows
- live backend integration

## Intelligence

- ATT&CK enrichment
- CVE intelligence
- attacker correlation
- telemetry aggregation
- behavioral analytics

---

# Technologies Used

## Backend

- Python
- FastAPI
- PostgreSQL
- SQLAlchemy
- Poetry
- Docker

## Frontend

- React
- TypeScript
- Vite
- Recharts
- Tailwind CSS

## Security Telemetry

- Suricata IDS
- Cowrie Honeypot
- MITRE ATT&CK
- CVE/NVD Intelligence

## Data Engineering

- STIX parsing
- ETL pipelines
- JSON processing
- structured threat enrichment

---

# NEXT DEVELOPMENT PHASE

# Immediate Next Steps

## 1. GeoIP Intelligence Enrichment

Planned:

- country resolution
- ASN enrichment
- ISP intelligence
- attacker geolocation
- flag visualization

---

## 2. Threat Timeline Visualization

Planned:

- chronological attacker activity
- event sequencing
- attack chain visualization
- temporal intelligence analytics

---

## 3. ATT&CK Technique Badges

Planned:

- glowing ATT&CK chips
- tactic badges
- dynamic MITRE mappings
- analyst ATT&CK visualization

---

## 4. Real-Time Telemetry Streaming

Planned:

- websocket integration
- live SOC updates
- streaming telemetry
- real-time attack visibility

---

## 5. IOC Export Engine

Planned:

- IOC extraction
- CSV/JSON exports
- threat sharing workflows
- analyst reporting

---

## 6. ATT&CK Navigator Export

Planned:

- ATT&CK heatmaps
- navigator JSON exports
- coverage analytics
- ATT&CK reporting

---

## 7. Sigma Rule Generation

Planned:

- Sigma detection generation
- ATT&CK-aligned detections
- automated rule creation

---

# Future Platform Expansion

## Advanced Threat Intelligence

- malware family intelligence
- threat actor attribution
- threat hunting dashboards
- detection coverage analytics
- reputation feed integration

## Operational SOC Features

- case management
- incident workflows
- analyst collaboration
- alert triage

---

# Current Engineering Status

```text
Platform State:
Enterprise CTI + SOC Dashboard Platform
```

```text
Backend APIs                  ✅ Stable
Frontend Dashboard            ✅ Operational
Threat Intelligence           ✅ Operational
ATT&CK Enrichment             ✅ Operational
Analyst Investigation Flow    ✅ Operational
Docker Infrastructure         ✅ Stable
Database Integration          ✅ Stable
```

---

# Repository Structure

```text
CSP/
│
├── backend/
│   └── app/
│       ├── routes/
│       ├── services/
│       ├── database/
│       └── main.py
│
├── frontend/
│   └── src/
│       ├── components/
│       ├── services/
│       ├── assets/
│       └── App.tsx
│
├── data/
│   └── mitre/
│
├── sql/
│
├── docker-compose.yml
│
└── README.md
```

---

# Author

Cheta  
B.Tech Electrical Engineering  
National Institute of Technology Rourkela