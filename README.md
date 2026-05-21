# Sentinel: Cyber Threat Intelligence Platform

Enterprise-grade Cyber Threat Intelligence (CTI) & SOC Dashboard Platform built using FastAPI, PostgreSQL, React, Docker, and MITRE ATT&CK Intelligence Enrichment.

---

# Overview

Sentinel is a unified cyber threat intelligence and SOC operations platform designed to simulate a real-world enterprise Security Operations Center (SOC).

The platform combines:

- FastAPI backend APIs
- PostgreSQL threat intelligence storage
- MITRE ATT&CK STIX enrichment
- React-based SOC dashboard
- Interactive analyst investigation workflows
- Threat telemetry analytics
- ATT&CK intelligence visualization

---

# Core Architecture

```text
PostgreSQL
    ↓
FastAPI Threat APIs
    ↓
MITRE ATT&CK Intelligence Layer
    ↓
React SOC Dashboard
    ↓
Interactive Threat Investigation Console
```

---

# Tech Stack

## Backend

- FastAPI
- SQLAlchemy
- PostgreSQL
- Poetry
- Docker
- mitreattack-python SDK

## Frontend

- React 19
- TypeScript
- Vite
- Recharts
- Tailwind CSS
- Glassmorphism Cyber UI

## Threat Intelligence

- MITRE ATT&CK Enterprise
- Suricata IDS
- Cowrie Honeypot
- STIX 2.0 Intelligence
- Threat Scoring Engine

---

# Key Features

## SOC Dashboard

- Live cyber telemetry
- Executive intelligence overview
- Threat severity analytics
- ATT&CK tactic distributions
- MITRE analytics charts
- Threat trend visualization

---

## Interactive Investigation Panel

- Click attacker IPs
- Open intelligence side panel
- View attacker risk score
- Threat level classification
- Unique ATT&CK techniques
- Tactical response actions

---

## MITRE ATT&CK Enrichment

Integrated using:

```text
mitreattack-python
```

Capabilities:

- Dynamic technique lookup
- Tactic extraction
- STIX intelligence parsing
- ATT&CK enrichment APIs
- Threat analytics mapping

---

# Backend API Endpoints

## Attackers APIs

| Endpoint | Description |
|---|---|
| `/attackers/dashboard/summary` | Dashboard intelligence metrics |
| `/attackers/critical` | Critical attacker feed |
| `/attackers/details` | Detailed attacker intelligence |
| `/attackers/top` | Highest risk attackers |

---

## MITRE APIs

| Endpoint | Description |
|---|---|
| `/mitre/technique/{id}` | ATT&CK technique intelligence |
| `/mitre/top-techniques/details` | Enriched ATT&CK analytics |

---

## ATT&CK Analytics APIs

| Endpoint | Description |
|---|---|
| `/attack-techniques/top` | Top exploited techniques |
| `/attack-tactics/top` | Top active tactics |

---

# PostgreSQL Threat Intelligence

The platform stores:

- attacker telemetry
- Suricata IDS alerts
- Cowrie honeypot logs
- ATT&CK mappings
- threat scoring metrics

---

# Docker Infrastructure

## Containers

| Service | Purpose |
|---|---|
| PostgreSQL 16 | Threat intelligence database |
| pgAdmin4 | Database administration |

---

# Docker Setup

## Start Containers

```bash
docker compose up -d
```

## Stop Containers

```bash
docker compose down
```

---

# pgAdmin Access

URL:

```text
http://localhost:5050
```

Credentials:

```text
Email: admin@threat.local
Password: adminpass
```

---

# PostgreSQL Credentials

| Field | Value |
|---|---|
| Host | threat_intel_db |
| Port | 5432 |
| Database | threat_intel |
| Username | threatuser |
| Password | threatpass |

---

# Backend Setup

## Install Dependencies

```bash
poetry install
```

## Run Backend

```bash
poetry run uvicorn backend.app.main:app --reload
```

Backend URL:

```text
http://127.0.0.1:8000
```

---

# Frontend Setup

## Install Dependencies

```bash
npm install
```

## Run Frontend

```bash
npm run dev
```

Frontend URL:

```text
http://localhost:3000
```

---

# MITRE ATT&CK Dataset

Location:

```text
data/mitre/enterprise-attack.json
```

Used for:

- technique enrichment
- tactic extraction
- ATT&CK metadata
- STIX intelligence parsing

---

# Frontend Components

## DashboardView.tsx

Provides:

- KPI cards
- Threat analytics
- ATT&CK charts
- Critical attacker table
- Tactical actions

---

## Interactive Attacker Panel

Features:

- Real-time attacker selection
- Risk scoring visualization
- Threat severity classification
- Intelligence summaries
- Tactical response actions

---

## MITREMatrixView.tsx

- ATT&CK matrix visualization
- Dynamic ATT&CK analytics
- Tactic mapping

---

## AlertsView.tsx

- Threat event monitoring
- Incident investigation
- Forensic log analysis

---

# Current Operational Features

| Capability | Status |
|---|---|
| FastAPI APIs | ✅ |
| PostgreSQL Integration | ✅ |
| Docker Deployment | ✅ |
| React SOC Dashboard | ✅ |
| MITRE ATT&CK SDK | ✅ |
| ATT&CK Enrichment | ✅ |
| Threat Scoring Engine | ✅ |
| Interactive Investigation Panel | ✅ |
| Real-Time Analytics | ✅ |

---

# Threat Intelligence Workflow

```text
Threat Event
    ↓
Suricata / Cowrie
    ↓
PostgreSQL
    ↓
FastAPI APIs
    ↓
MITRE ATT&CK Enrichment
    ↓
React SOC Dashboard
    ↓
Analyst Investigation
```

---

# UI Design Language

The frontend uses:

- dark enterprise SOC styling
- glassmorphism panels
- neon cyber accents
- tactical intelligence widgets
- operational dashboard layouts

Inspired by:

- CrowdStrike Falcon
- Microsoft Sentinel
- IBM QRadar
- Splunk Enterprise Security

---

# Future Roadmap

## Planned Features

- GeoIP enrichment
- ASN intelligence
- IOC export engine
- ATT&CK Navigator export
- Sigma rule generation
- Real-time websocket telemetry
- Malware family intelligence
- Threat actor attribution
- Attack timeline visualization
- Detection coverage analytics

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

# Platform Status

| Component | Status |
|---|---|
| Backend APIs | ✅ Stable |
| Frontend Dashboard | ✅ Operational |
| PostgreSQL | ✅ Operational |
| Docker Stack | ✅ Running |
| MITRE Integration | ✅ Active |
| ATT&CK Analytics | ✅ Active |
| Threat Investigation Workflow | ✅ Operational |

---

# Screenshots

## SOC Dashboard

- Executive SOC overview
- ATT&CK analytics
- Live threat telemetry
- Interactive investigation workflows
- Tactical threat response panel

---

# Author

Cheta  
B.Tech Electrical Engineering  
National Institute of Technology Rourkela