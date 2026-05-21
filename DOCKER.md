# Threat Intelligence Platform - Docker Environment

This document summarizes the current state of the containerized environment and database schema for the Threat Intelligence platform.

## 1. Services Overview (Docker Compose)

| Service | Container Name | Image | Internal Port | External Port |
| :--- | :--- | :--- | :--- | :--- |
| **PostgreSQL** | `threat_intel_db` | `postgres:16` | `5432` | `5432` |
| **pgAdmin** | `threat_intel_pgadmin` | `dpage/pgadmin4` | `80` | `5050` |

### Network Configuration
- **Network Name**: `threat_net` (Bridge)
- **Restart Policy**: `unless-stopped`

## 2. Credentials & Connection Details

### PostgreSQL
- **Database Name**: `threat_intel`
- **Username**: `threatuser`
- **Password**: `threatpass`
- **Connection URI**: `postgresql://threatuser:threatpass@localhost:5432/threat_intel`

### pgAdmin (Web UI)
- **URL**: `http://localhost:5050`
- **Login Email**: `admin@threat.local`
- **Login Password**: `adminpass`

## 3. Database Schema (`sql/init.sql`)

The database is initialized with the following core tables:

### Core Data Tables
1.  **`cves`**: Stores CVE records from the V5 list. Includes JSONB for raw data.
2.  **`suricata_alerts`**: Stores IDS alerts from `eve.json` files.
3.  **`cowrie_events`**: Stores honeypot events (logins, commands, sessions).
4.  **`attack_cve_mapping`**: Links security events to specific CVE IDs.
5.  **`known_ports`**: A reference table for common ports (22, 5900, 7070, etc.).

### Key Views
- **`v_suricata_with_cves`**: Alerts joined with CVE severity and descriptions.
- **`v_cowrie_with_cves`**: Honeypot events joined with CVE data.
- **`v_attacker_summary`**: Ranked list of attacker IPs across both sources.

## 4. Current Workflows

### CVE Ingestion
- **Script**: `scripts/ingest_cves.py`
- **Source**: `cvelistV5-main/cves`
- **Capability**: Recursively walks folders, parses V5 JSON, and performs "upserts" (updates existing records on conflict).

### Manual Commands
- **Check DB Status**: `docker exec -it threat_intel_db psql -U threatuser -d threat_intel`
- **Restart All**: `docker-compose up -d`
