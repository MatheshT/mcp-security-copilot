# MCP Security Copilot - Complete System Architecture

## Executive Summary

The MCP Security Copilot is an enterprise-grade autonomous security operations center (SOC) platform that automatically collects Windows Event Logs, Sysmon logs, and Windows Defender logs, analyzes them using LLM, extracts IOCs (IP, hash, URL, process, user), and intelligently chooses threat intelligence tools such as VirusTotal, MITRE ATT&CK, Sigma Rules, and AbuseIPDB for investigation.

## Technology Stack

### Backend
- **Framework**: FastAPI 0.118+
- **Runtime**: Python 3.14+
- **Database**: PostgreSQL 15+ (production), SQLite (development)
- **ORM**: SQLAlchemy 2.0+
- **Migrations**: Alembic 1.12+
- **Caching**: Redis 7+
- **Async Runtime**: Uvicorn
- **HTTP Client**: httpx 0.25+
- **Authentication**: JWT with python-jose
- **Password Hashing**: Passlib with bcrypt

### Frontend
- **Framework**: React 18+
- **Build Tool**: Vite
- **UI Components**: Custom components with Tailwind CSS
- **HTTP Client**: Fetch API
- **State Management**: React hooks (useState, useEffect)
- **Icons**: Lucide React

### External Integrations
- **Threat Intelligence**: VirusTotal, MITRE ATT&CK, Sigma Rules, AbuseIPDB
- **LLM Providers**: OpenAI, Ollama
- **SIEM**: Wazuh
- **Threat Intel**: MISP
- **OSINT**: Shodan

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     React Frontend (Vite)                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Security   │  │   IOC        │  │Investigation │          │
│  │  Dashboard   │  │   Viewer     │  │   Viewer     │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FastAPI Backend                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              API Gateway Layer                            │  │
│  │  Authentication, Rate Limiting, Security Headers          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Business Logic Layer                        │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │  │
│  │  │ Autonomous   │  │ Log Collector│  │ IOC Extractor │  │  │
│  │  │ SOC Analyst  │  │              │  │              │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │  │
│  │  │ Threat Intel │  │ Correlation  │  │ Risk Scoring │  │  │
│  │  │ Orchestrator │  │   Engine     │  │   Engine     │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Data Access Layer                            │  │
│  │  SQLAlchemy ORM, Database Models, Session Management       │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Data Layer                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ PostgreSQL   │  │   Redis      │  │  File Storage│          │
│  │   Database   │  │    Cache     │  │              │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  External Integrations                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ Windows  │ │ Virus    │ │ MITRE    │ │ Sigma    │          │
│  │   Logs   │ │  Total   │ │ ATT&CK   │ │  Rules   │          │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ AbuseIPDB│ │  Wazuh   │ │   MISP   │ │  Shodan  │          │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
│  ┌──────────┐ ┌──────────┐                                    │
│  │  OpenAI  │ │  Ollama  │                                    │
│  └──────────┘ └──────────┘                                    │
└─────────────────────────────────────────────────────────────────┘
```

## Module Design

### 1. Log Collection Module

#### Windows Log Collector
- **Purpose**: Collects Windows Event Logs, Sysmon logs, and Windows Defender logs
- **Components**:
  - `WindowsEventLogCollector`: Collects standard Windows Event Logs
  - `SysmonLogCollector`: Specialized collector for Sysmon logs
  - `DefenderLogCollector`: Specialized collector for Windows Defender logs
- **Features**:
  - Configurable time ranges
  - Real-time log collection
  - Structured parsing
  - Database storage
  - IOC candidate extraction

#### IOC Extractor
- **Purpose**: Extracts Indicators of Compromise from log data
- **Components**:
  - `IOCExtractor`: Main extraction engine
  - `IOCPrioritizer`: Prioritizes IOCs based on risk factors
- **IOC Types**:
  - IP addresses (IPv4, IPv6)
  - Domain names
  - URLs
  - Email addresses
  - File hashes (MD5, SHA1, SHA256)
  - Registry keys
  - File paths
  - Process names
  - User accounts
- **Features**:
  - Advanced regex pattern matching
  - Automatic deduplication
  - Risk-based prioritization
  - Summary statistics

### 2. Threat Intelligence Module

#### VirusTotal Client
- **Purpose**: Analyze IOCs against VirusTotal database
- **Features**:
  - File hash analysis
  - URL analysis
  - IP address analysis
  - Domain analysis
  - Batch analysis
  - Detection ratio calculation
  - Reputation scoring

#### MITRE ATT&CK Client
- **Purpose**: Map IOCs to MITRE ATT&CK techniques and tactics
- **Features**:
  - Technique retrieval
  - Tactic mapping
  - Threat group information
  - Software attribution
  - Mitigation recommendations
  - IOC-to-technique correlation

#### Sigma Client
- **Purpose**: Analyze logs against Sigma detection rules
- **Features**:
  - Rule retrieval
  - Log analysis against rules
  - Rule search
  - MITRE mapping
  - YAML rule conversion

#### AbuseIPDB Client
- **Purpose**: Check IP addresses against AbuseIPDB
- **Features**:
  - IP reputation checking
  - Bulk IP analysis
  - Blacklist retrieval
  - IP reporting
  - Risk assessment

#### Threat Intelligence Orchestrator
- **Purpose**: Coordinate between multiple threat intelligence sources
- **Features**:
  - Multi-source analysis
  - Result correlation
  - Risk aggregation
  - Recommendation generation
  - Performance optimization

### 3. Autonomous SOC Analyst Module

#### Autonomous SOC Analyst
- **Purpose**: Act as an autonomous SOC analyst for security investigations
- **Investigation Phases**:
  1. **Planning**: LLM-driven investigation planning
  2. **Evidence Collection**: Automated log collection
  3. **IOC Extraction**: Comprehensive IOC extraction
  4. **Threat Intel Analysis**: Multi-source threat intelligence
  5. **Correlation**: Cross-source correlation analysis
  6. **Risk Assessment**: Comprehensive risk scoring
  7. **Reporting**: Explainable incident reports
  8. **Action Recommendations**: AI-driven recommendations
- **Features**:
  - LLM-powered decision making
  - Evidence-based conclusions
  - Explainable AI
  - Progress tracking
  - State management

## Database Schema

### Core Tables

#### Windows Logs Table
```sql
CREATE TABLE windows_logs (
    id INTEGER PRIMARY KEY,
    log_source VARCHAR(50), -- windows_event, sysmon, defender
    log_name VARCHAR(255),
    event_id INTEGER,
    timestamp DATETIME,
    computer_name VARCHAR(255),
    source VARCHAR(255),
    category VARCHAR(255),
    event_type VARCHAR(50),
    record_number INTEGER,
    user VARCHAR(255),
    data JSON,
    xml_representation TEXT,
    processed BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### IOCs Table
```sql
CREATE TABLE iocs (
    id INTEGER PRIMARY KEY,
    ioc_type VARCHAR(50), -- ip_address, domain, url, email, file_hash, etc.
    ioc_value TEXT,
    ioc_subtype VARCHAR(50), -- MD5, SHA256 for hashes
    source_log_id INTEGER,
    confidence_score FLOAT DEFAULT 0.0,
    risk_level VARCHAR(20), -- critical, high, medium, low
    first_seen DATETIME,
    last_seen DATETIME,
    is_false_positive BOOLEAN DEFAULT FALSE,
    notes TEXT,
    metadata JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### Threat Intel Analysis Table
```sql
CREATE TABLE threat_intel_analyses (
    id INTEGER PRIMARY KEY,
    ioc_id INTEGER,
    source VARCHAR(50), -- virustotal, mitre_attack, sigma, abuseipdb
    analysis_result JSON,
    risk_level VARCHAR(20),
    confidence_score FLOAT DEFAULT 0.0,
    detection_ratio VARCHAR(50),
    positive_detections INTEGER DEFAULT 0,
    total_engines INTEGER DEFAULT 0,
    reputation_score INTEGER DEFAULT 0,
    first_seen DATETIME,
    last_seen DATETIME,
    categories JSON,
    tags JSON,
    raw_response TEXT,
    analysis_timestamp DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### Investigations Table
```sql
CREATE TABLE investigations (
    id INTEGER PRIMARY KEY,
    investigation_id VARCHAR(100) UNIQUE,
    title VARCHAR(255),
    description TEXT,
    status VARCHAR(50), -- planning, evidence_collection, etc.
    investigation_type VARCHAR(50),
    priority VARCHAR(20),
    risk_score FLOAT DEFAULT 0.0,
    risk_level VARCHAR(20),
    log_sources JSON,
    time_range_hours INTEGER,
    priority_areas JSON,
    ioc_focus JSON,
    hypotheses JSON,
    phases_completed JSON,
    key_findings JSON,
    evidence_summary JSON,
    threat_intel_summary JSON,
    correlation_summary JSON,
    executive_summary TEXT,
    attack_narrative TEXT,
    impact_assessment TEXT,
    recommendations JSON,
    created_by VARCHAR(255),
    assigned_to VARCHAR(255),
    start_time DATETIME,
    end_time DATETIME,
    llm_guidance JSON,
    llm_report_enhancement JSON,
    metadata JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### Investigation Phases Table
```sql
CREATE TABLE investigation_phases (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER,
    phase_name VARCHAR(100),
    phase_status VARCHAR(50),
    start_time DATETIME,
    end_time DATETIME,
    duration_seconds INTEGER,
    phase_result JSON,
    phase_summary TEXT,
    errors JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### Alerts Table
```sql
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    alert_id VARCHAR(100) UNIQUE,
    title VARCHAR(255),
    description TEXT,
    severity VARCHAR(20), -- critical, high, medium, low
    alert_type VARCHAR(100),
    source VARCHAR(100),
    status VARCHAR(50),
    detection_rule VARCHAR(255),
    iocs_involved JSON,
    affected_hosts JSON,
    affected_users JSON,
    investigation_id INTEGER,
    first_seen DATETIME,
    last_seen DATETIME,
    resolved_at DATETIME,
    false_positive BOOLEAN DEFAULT FALSE,
    false_positive_reason TEXT,
    notes TEXT,
    metadata JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## API Design

### Log Collection Endpoints

#### POST /api/log-analysis/collect-logs
Collects logs from Windows Event Logs, Sysmon, and Defender
```json
{
  "log_sources": ["windows_event", "sysmon", "defender"],
  "hours_back": 24,
  "save_to_db": true
}
```

#### POST /api/log-analysis/extract-iocs
Extracts IOCs from collected logs
```json
{
  "log_ids": [1, 2, 3],
  "hours_back": 24,
  "prioritize": true
}
```

### Threat Intelligence Endpoints

#### POST /api/log-analysis/threat-intel
Analyzes IOCs against threat intelligence sources
```json
{
  "ioc_ids": [1, 2, 3],
  "iocs": {
    "ip_addresses": ["192.168.1.1"],
    "domains": ["example.com"]
  },
  "sources": ["virustotal", "mitre_attack", "sigma", "abuseipdb"]
}
```

### Investigation Endpoints

#### POST /api/log-analysis/investigation/start
Starts an autonomous SOC investigation
```json
{
  "title": "Security Investigation",
  "description": "Investigate suspicious activity",
  "investigation_type": "malware",
  "log_sources": ["windows_event", "sysmon", "defender"],
  "time_range_hours": 24,
  "priority_areas": ["process_creation", "network_connections"],
  "ioc_focus": ["ip_addresses", "file_hashes"],
  "auto_start": true
}
```

#### GET /api/log-analysis/investigation/{id}
Gets investigation details

#### GET /api/log-analysis/investigation
Lists investigations with optional status filtering

### IOC Management Endpoints

#### GET /api/log-analysis/iocs
Lists IOCs with filtering
```
?skip=0&limit=50&ioc_type=ip_address&risk_level=high
```

### Alert Management Endpoints

#### GET /api/log-analysis/alerts
Lists security alerts with filtering
```
?skip=0&limit=50&severity=critical&status=open
```

### Dashboard Endpoints

#### GET /api/log-analysis/dashboard/stats
Gets dashboard statistics
```json
{
  "total_investigations": 150,
  "active_investigations": 5,
  "total_iocs": 2500,
  "high_risk_iocs": 150,
  "total_alerts": 75,
  "open_alerts": 20,
  "critical_alerts": 3,
  "logs_collected_24h": 50000
}
```

## Workflow

### Autonomous SOC Investigation Workflow

```
1. PLANNING PHASE
   ├─ LLM analyzes investigation parameters
   ├─ Determines log sources to collect
   ├─ Identifies priority areas
   ├─ Generates investigation hypotheses
   └─ Creates structured investigation plan

2. EVIDENCE COLLECTION PHASE
   ├─ Collects Windows Event Logs
   ├─ Collects Sysmon logs
   ├─ Collects Windows Defender logs
   ├─ Parses logs into structured format
   └─ Stores logs in database

3. IOC EXTRACTION PHASE
   ├─ Extracts IP addresses from logs
   ├─ Extracts domain names from logs
   ├─ Extracts URLs from logs
   ├─ Extracts file hashes from logs
   ├─ Extracts other IOC types
   ├─ Deduplicates IOCs
   └─ Prioritizes IOCs by risk

4. THREAT INTEL ANALYSIS PHASE
   ├─ Analyzes IOCs against VirusTotal
   ├─ Maps IOCs to MITRE ATT&CK
   ├─ Analyzes against Sigma rules
   ├─ Checks IPs against AbuseIPDB
   └─ Correlates findings across sources

5. CORRELATION PHASE
   ├─ Identifies cross-source matches
   ├─ Finds high-confidence findings
   ├─ Detects suspicious patterns
   ├─ Identifies threat actor indicators
   └─ LLM provides correlation insights

6. RISK ASSESSMENT PHASE
   ├─ Calculates overall risk score
   ├─ Determines risk level
   ├─ Identifies risk factors
   ├─ LLM validates risk assessment
   └─ Generates impact assessment

7. REPORTING PHASE
   ├─ Generates executive summary
   ├─ Creates attack narrative
   ├─ Documents key findings
   ├─ Provides evidence summary
   └─ LLM enhances report content

8. ACTION RECOMMENDATION PHASE
   ├─ Generates prioritized recommendations
   ├─ Determines action priority
   ├─ Provides containment steps
   ├─ Suggests investigation steps
   └─ Recommends prevention measures
```

## React Dashboard Layout

### Security Dashboard
```
┌─────────────────────────────────────────────────────────────────┐
│  Security Operations Center              [Collect Logs] [Start]  │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────┐│
│  │ Total Inv:   │ │ Active Inv:  │ │ Total IOCs:  │ │ High IOCs││
│  │     150      │ │      5       │ │    2500      │ │   150    ││
│  └──────────────┘ └──────────────┘ └──────────────┘ └─────────┘│
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────┐│
│  │ Total Alerts:│ │ Open Alerts: │ │ Critical:    │ │Logs(24h):││
│  │     75       │ │     20       │ │      3       │ │  50000   ││
│  └──────────────┘ └──────────────┘ └──────────────┘ └─────────┘│
├─────────────────────────────────────────────────────────────────┤
│  Recent Investigations                Recent Alerts               │
│  ┌─────────────────────────────────┐ ┌─────────────────────────┐ │
│  │ Malware Investigation #123     │ │ Critical: Suspicious    │ │
│  │ Status: completed               │ │ Process Execution       │ │
│  │ Risk: 85/100 (high)            │ │ Severity: critical      │ │
│  │ [View Details]                  │ │ [Investigate]           │ │
│  ├─────────────────────────────────┤ ├─────────────────────────┤ │
│  │ Network Analysis #124          │ │ High: Unusual Network   │ │
│  │ Status: in_progress            │ │ Traffic                 │ │
│  │ Risk: 65/100 (medium)          │ │ Severity: high          │ │
│  │ [View Details]                  │ │ [Investigate]           │ │
│  └─────────────────────────────────┘ └─────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│  Quick Actions                                                    │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐             │
│  │ Collect Logs │ │ Extract IOCs │ │ Threat Intel │             │
│  └──────────────┘ └──────────────┘ └──────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

### IOC Viewer
```
┌─────────────────────────────────────────────────────────────────┐
│  Indicators of Compromise                    [Analyze Selected]  │
├─────────────────────────────────────────────────────────────────┤
│  Filters:                                                          │
│  ┌──────────────────┐ ┌──────────────┐ ┌──────────────────┐     │
│  │ [Search IOCs...] │ │ [All Types ▼] │ │ [All Risks ▼]    │     │
│  └──────────────────┘ └──────────────┘ └──────────────────┘     │
│  [Clear Filters]                                                   │
├─────────────────────────────────────────────────────────────────┤
│  IOCs (150 / 2500)                                                │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ 🌐 192.168.1.1                            [High] [Analyze] ││
│  │    ip_address • First seen: 2024-01-15                      ││
│  ├─────────────────────────────────────────────────────────────┤│
│  │ 🌐 suspicious-domain.com                  [Critical] [Analyze]││
│  │    domain • First seen: 2024-01-14                         ││
│  ├─────────────────────────────────────────────────────────────┤│
│  │ 📄 MD5: 5d41402abc4b2a76b9719d911017c592   [High] [Analyze]││
│  │    file_hash (MD5) • First seen: 2024-01-13                ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Investigation Viewer
```
┌─────────────────────────────────────────────────────────────────┐
│  Security Investigations              [All Status ▼] [Refresh]    │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Malware Investigation #123               [Completed]         ││
│  │ Investigate suspicious malware activity detected on           ││
│  │ workstation endpoints                                         ││
│  │                                                               ││
│  │ ID: inv_20240115_143022    Type: malware    Priority: high  ││
│  │ Risk: 85/100 (high)       Created: 2024-01-15 14:30:22      ││
│  │                                                               ││
│  │                                    [View Details] [Report]   ││
│  ├─────────────────────────────────────────────────────────────┤│
│  │ Network Analysis #124                   [In Progress]        ││
│  │ Analyze unusual network traffic patterns                     ││
│  │                                                               ││
│  │ ID: inv_20240115_150000    Type: network    Priority: medium││
│  │ Risk: 65/100 (medium)     Created: 2024-01-15 15:00:00      ││
│  │                                                               ││
│  │                                    [View Details]            ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Deployment Architecture

### Docker Compose Deployment
```yaml
services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:password@db/security_copilot
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
      - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY}
    depends_on:
      - db
      - redis

  frontend:
    build: ./frontend
    ports:
      - "80:80"
    depends_on:
      - backend

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=security_copilot
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7
    ports:
      - "6379:6379"

  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

## Security Considerations

### Authentication & Authorization
- JWT-based authentication with refresh tokens
- Role-based access control (RBAC)
- Session management
- Audit logging

### Data Protection
- Input sanitization
- SQL injection prevention
- XSS protection
- CSRF protection
- Security headers (CSP, CORS, etc.)

### API Security
- Rate limiting
- Request size limits
- IP whitelisting/blacklisting
- API key management

### Log Security
- Sensitive data redaction
- Secure log storage
- Access controls
- Retention policies

## Performance Optimization

### Caching Strategy
- Redis for session caching
- Query result caching
- Threat intelligence response caching
- Static asset caching

### Database Optimization
- Connection pooling
- Index optimization
- Query optimization
- Database partitioning

### Async Processing
- Background task processing
- Async I/O operations
- Concurrent threat intelligence queries
- Batch processing

## Monitoring & Observability

### Metrics Collection
- Prometheus metrics
- Custom business metrics
- Performance metrics
- Security metrics

### Logging
- Structured JSON logging
- Log aggregation
- Log analysis
- Alert triggering

### Health Checks
- Application health endpoints
- Database health checks
- External service health checks
- Dependency monitoring

This architecture provides a comprehensive, enterprise-grade autonomous SOC platform that can automatically collect logs, extract IOCs, analyze threats, and generate actionable security intelligence.