# MITRE ATT&CK Enterprise Attack Framework - Data Structure & Schema

## File Overview
- **File**: enterprise-attack.json
- **Format**: STIX 2.1 (Structured Threat Information Expression)
- **Size**: Large (50MB+)
- **Content**: Relationships between threat actors, malware, tools, techniques, and campaigns

## Main Object Types in the File

### 1. **Relationship Objects** (Most Common)
Describes connections between entities (who uses what, what mitigates what, etc.)

```json
{
  "type": "relationship",
  "spec_version": "2.1",
  "id": "relationship--ffa16031-220f-4bb3-9be4-241b4b43b53e",
  "created": "2024-12-17T00:37:25.668Z",
  "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
  "revoked": false,
  "external_references": [
    {
      "source_name": "Microsoft BlackByte 2023",
      "description": "Microsoft Incident Response. (2023, July 6). The five-day job: A BlackByte ransomware intrusion case study. Retrieved December 16, 2024.",
      "url": "https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/"
    }
  ],
  "object_marking_refs": ["marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"],
  "modified": "2026-04-29T14:23:06.272Z",
  "description": "[BlackByte](https://attack.mitre.org/groups/G1043) has used [Mimikatz](https://attack.mitre.org/software/S0002) for credential dumping during operations.",
  "relationship_type": "uses",
  "source_ref": "intrusion-set--02b16bd6-ae88-417a-8a3f-02c5e166175a",
  "target_ref": "tool--afc079f3-c0ea-4096-b75d-3f05338b7f60",
  "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
  "x_mitre_deprecated": false,
  "x_mitre_attack_spec_version": "3.3.0"
}
```

**Key Fields**:
- `relationship_type`: "uses", "mitigates", "detects", "exploits", etc.
- `source_ref`: ID of the source entity (intrusion-set, malware, tool, campaign)
- `target_ref`: ID of the target entity (attack-pattern, tool, malware, etc.)
- `description`: Human-readable explanation with citations
- `external_references`: Sources and citations

### 2. **Identity Objects**
Organization information (MITRE Corporation)

```json
{
  "type": "identity",
  "spec_version": "2.1",
  "id": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
  "created": "2017-06-01T00:00:00Z",
  "object_marking_refs": ["marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"],
  "modified": "2026-05-12T16:33:30.227Z",
  "name": "The MITRE Corporation",
  "identity_class": "organization",
  "x_mitre_attack_spec_version": "3.2.0"
}
```

### 3. **Marking Definition Objects**
Copyright and usage information

```json
{
  "definition": {
    "statement": "Copyright 2015-2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation."
  },
  "id": "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168",
  "type": "marking-definition",
  "spec_version": "2.1",
  "created": "2017-06-01T00:00:00Z",
  "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
  "definition_type": "statement"
}
```

## Entity Types Referenced in Relationships

### Source Entities (source_ref):
- `intrusion-set--*`: Threat actor groups (e.g., BlackByte, APT41, Rocke)
- `malware--*`: Malicious software (e.g., Mimikatz, Lizar, DarkGate)
- `campaign--*`: Coordinated attack campaigns (e.g., C0015, HomeLand Justice)
- `tool--*`: Legitimate tools used maliciously

### Target Entities (target_ref):
- `attack-pattern--*`: Techniques/tactics (e.g., credential dumping, DLL side-loading)
- `malware--*`: Malware samples
- `tool--*`: Tools
- `course-of-action--*`: Mitigation strategies

## Relationship Types
- **uses**: Actor/malware uses a technique or tool
- **mitigates**: A course of action mitigates a technique
- **detects**: A detection method identifies a technique
- **exploits**: Malware exploits a vulnerability
- **indicates**: Evidence indicates an attack pattern

---

## Proposed PostgreSQL Schema

### Main Tables

#### 1. **mitre_entities** (Base table for all entities)
```sql
CREATE TABLE mitre_entities (
    id SERIAL PRIMARY KEY,
    stix_id VARCHAR(100) UNIQUE NOT NULL,
    entity_type VARCHAR(50) NOT NULL,  -- intrusion-set, malware, tool, attack-pattern, campaign, etc.
    name VARCHAR(500),
    description TEXT,
    created TIMESTAMP,
    modified TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    x_mitre_attack_spec_version VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_stix_id (stix_id),
    INDEX idx_entity_type (entity_type),
    INDEX idx_name (name)
);
```

#### 2. **mitre_relationships**
```sql
CREATE TABLE mitre_relationships (
    id SERIAL PRIMARY KEY,
    relationship_id VARCHAR(100) UNIQUE NOT NULL,
    source_ref VARCHAR(100) NOT NULL,
    target_ref VARCHAR(100) NOT NULL,
    relationship_type VARCHAR(50) NOT NULL,  -- uses, mitigates, detects, exploits, indicates
    description TEXT,
    created TIMESTAMP,
    modified TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (source_ref) REFERENCES mitre_entities(stix_id),
    FOREIGN KEY (target_ref) REFERENCES mitre_entities(stix_id),
    INDEX idx_source_ref (source_ref),
    INDEX idx_target_ref (target_ref),
    INDEX idx_relationship_type (relationship_type)
);
```

#### 3. **mitre_external_references**
```sql
CREATE TABLE mitre_external_references (
    id SERIAL PRIMARY KEY,
    relationship_id VARCHAR(100),
    entity_id VARCHAR(100),
    source_name VARCHAR(255),
    description TEXT,
    url TEXT,
    published_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (relationship_id) REFERENCES mitre_relationships(relationship_id),
    FOREIGN KEY (entity_id) REFERENCES mitre_entities(stix_id),
    INDEX idx_source_name (source_name),
    INDEX idx_url (url)
);
```

#### 4. **mitre_threat_actors** (Specialized view/table)
```sql
CREATE TABLE mitre_threat_actors (
    id SERIAL PRIMARY KEY,
    stix_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(500),
    aliases TEXT[],
    description TEXT,
    first_seen DATE,
    last_seen DATE,
    country_of_origin VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (stix_id) REFERENCES mitre_entities(stix_id),
    INDEX idx_name (name)
);
```

#### 5. **mitre_malware** (Specialized view/table)
```sql
CREATE TABLE mitre_malware (
    id SERIAL PRIMARY KEY,
    stix_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(500),
    aliases TEXT[],
    description TEXT,
    malware_type VARCHAR(100),  -- ransomware, trojan, worm, etc.
    platforms TEXT[],  -- Windows, Linux, macOS, etc.
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (stix_id) REFERENCES mitre_entities(stix_id),
    INDEX idx_name (name),
    INDEX idx_malware_type (malware_type)
);
```

#### 6. **mitre_techniques** (Attack patterns)
```sql
CREATE TABLE mitre_techniques (
    id SERIAL PRIMARY KEY,
    stix_id VARCHAR(100) UNIQUE NOT NULL,
    technique_id VARCHAR(20),  -- T1234, T1234.001, etc.
    name VARCHAR(500),
    description TEXT,
    tactic VARCHAR(100),  -- reconnaissance, resource-development, initial-access, etc.
    platforms TEXT[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (stix_id) REFERENCES mitre_entities(stix_id),
    INDEX idx_technique_id (technique_id),
    INDEX idx_tactic (tactic)
);
```

#### 7. **mitre_campaigns**
```sql
CREATE TABLE mitre_campaigns (
    id SERIAL PRIMARY KEY,
    stix_id VARCHAR(100) UNIQUE NOT NULL,
    campaign_id VARCHAR(20),  -- C0001, C0002, etc.
    name VARCHAR(500),
    description TEXT,
    first_seen DATE,
    last_seen DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (stix_id) REFERENCES mitre_entities(stix_id),
    INDEX idx_campaign_id (campaign_id)
);
```

---

## Useful Views

### View 1: Threat Actor Techniques
```sql
CREATE VIEW v_threat_actor_techniques AS
SELECT 
    ta.name as threat_actor,
    t.name as technique,
    t.tactic,
    mr.description,
    mr.modified
FROM mitre_threat_actors ta
JOIN mitre_relationships mr ON ta.stix_id = mr.source_ref
JOIN mitre_techniques t ON mr.target_ref = t.stix_id
WHERE mr.relationship_type = 'uses'
ORDER BY ta.name, t.tactic;
```

### View 2: Malware Capabilities
```sql
CREATE VIEW v_malware_capabilities AS
SELECT 
    m.name as malware,
    t.name as technique,
    t.tactic,
    mr.description,
    er.source_name,
    er.url
FROM mitre_malware m
JOIN mitre_relationships mr ON m.stix_id = mr.source_ref
JOIN mitre_techniques t ON mr.target_ref = t.stix_id
LEFT JOIN mitre_external_references er ON mr.relationship_id = er.relationship_id
WHERE mr.relationship_type = 'uses'
ORDER BY m.name, t.tactic;
```

### View 3: Mitigation Strategies
```sql
CREATE VIEW v_mitigation_strategies AS
SELECT 
    t.name as technique,
    t.tactic,
    coa.name as mitigation,
    mr.description,
    er.source_name
FROM mitre_techniques t
JOIN mitre_relationships mr ON t.stix_id = mr.target_ref
JOIN mitre_entities coa ON mr.source_ref = coa.stix_id
LEFT JOIN mitre_external_references er ON mr.relationship_id = er.relationship_id
WHERE mr.relationship_type = 'mitigates'
AND coa.entity_type = 'course-of-action'
ORDER BY t.tactic, t.name;
```

---

## Sample Data Extraction Queries

### Find all techniques used by a specific threat actor:
```sql
SELECT DISTINCT t.name, t.tactic
FROM mitre_threat_actors ta
JOIN mitre_relationships mr ON ta.stix_id = mr.source_ref
JOIN mitre_techniques t ON mr.target_ref = t.stix_id
WHERE ta.name = 'BlackByte'
AND mr.relationship_type = 'uses';
```

### Find all malware that uses a specific technique:
```sql
SELECT DISTINCT m.name, m.malware_type
FROM mitre_malware m
JOIN mitre_relationships mr ON m.stix_id = mr.source_ref
JOIN mitre_techniques t ON mr.target_ref = t.stix_id
WHERE t.name LIKE '%credential%'
AND mr.relationship_type = 'uses';
```

### Find threat actors and their tools:
```sql
SELECT DISTINCT ta.name as threat_actor, tool.name as tool
FROM mitre_threat_actors ta
JOIN mitre_relationships mr ON ta.stix_id = mr.source_ref
JOIN mitre_entities tool ON mr.target_ref = tool.stix_id
WHERE tool.entity_type = 'tool'
AND mr.relationship_type = 'uses'
ORDER BY ta.name;
```
