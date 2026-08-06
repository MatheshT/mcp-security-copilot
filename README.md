# MCP Security Copilot v2.0 - Enterprise Edition

An enterprise-grade AI-powered Security Copilot with a React frontend and FastAPI backend. The backend can perform security investigation analysis, correlate tool outputs, and generate SOC-style investigation reports with per-tool visualizations and unified correlation analysis.

## 🚀 New Features - Autonomous SOC Analyst

### 🪟 Windows Log Collection
- **Automatic Log Collection**: Collects Windows Event Logs, Sysmon logs, and Windows Defender logs automatically
- **Real-time Analysis**: Supports real-time log collection and analysis with configurable time ranges
- **Structured Parsing**: Parses log data into structured format for IOC extraction and analysis
- **Database Storage**: Stores collected logs in PostgreSQL/SQLite for historical analysis

### 🔍 IOC Extraction & Analysis
- **Comprehensive IOC Extraction**: Extracts IP addresses, domains, URLs, email addresses, file hashes, registry keys, file paths, processes, and users
- **Smart Pattern Recognition**: Uses advanced regex patterns to identify IOCs in log data
- **IOC Prioritization**: Prioritizes IOCs based on risk factors and threat intelligence
- **Deduplication**: Automatically deduplicates IOCs to reduce false positives

### 🌐 Threat Intelligence Integration
- **VirusTotal Integration**: Analyze files, URLs, IPs, and domains against VirusTotal database
- **MITRE ATT&CK Mapping**: Maps IOCs to MITRE ATT&CK techniques and tactics
- **Sigma Rules Analysis**: Analyzes logs against Sigma detection rules
- **AbuseIPDB Integration**: Checks IP addresses against AbuseIPDB threat intelligence
- **Correlation Engine**: Correlates findings across multiple threat intelligence sources

### 🤖 Autonomous SOC Analyst
- **AI-Powered Investigation**: Acts as an autonomous SOC analyst with LLM-driven decision making
- **8-Phase Investigation Process**: Planning, Evidence Collection, IOC Extraction, Threat Intel Analysis, Correlation, Risk Assessment, Reporting, and Action Recommendations
- **Intelligent Planning**: Uses LLM to generate investigation plans based on parameters
- **Risk Scoring**: Calculates comprehensive risk scores based on multiple factors
- **Explainable Reports**: Generates detailed incident reports with executive summaries and recommendations

### 📊 New React Dashboard Components
- **Security Dashboard**: Real-time security monitoring with key metrics and statistics
- **IOC Viewer**: Interactive IOC viewing with filtering and threat intelligence analysis
- **Investigation Viewer**: Comprehensive investigation management with detailed views
- **Alert Management**: Security alert tracking and management interface

## 🚀 Enterprise Features

### 🔐 Authentication & Authorization
- **JWT-based Authentication**: Secure token-based authentication with refresh tokens
- **Role-Based Access Control (RBAC)**: Granular permissions for users and roles
- **Session Management**: Secure session tracking and management
- **Audit Logging**: Comprehensive audit trail for all security events

### 🗄️ Database Integration
- **Multi-Database Support**: SQLite (development), PostgreSQL (production)
- **ORM with SQLAlchemy**: Type-safe database operations
- **Migration Support**: Database schema management with Alembic
- **Connection Pooling**: Optimized database connection management

### 📊 Monitoring & Observability
- **Prometheus Metrics**: Comprehensive application metrics
- **Grafana Dashboards**: Pre-configured monitoring dashboards
- **Structured Logging**: JSON-formatted logs for better analysis
- **Health Checks**: Application health monitoring endpoints

### 🔒 Security Hardening
- **Input Sanitization**: Protection against SQL injection and XSS
- **Rate Limiting**: API rate limiting to prevent abuse
- **Security Headers**: Comprehensive security headers (CSP, CORS, etc.)
- **IP Whitelisting/Blacklisting**: Network access control
- **Request Size Limits**: Protection against large payload attacks

### 🧪 Testing Infrastructure
- **Unit Tests**: Backend testing with pytest
- **Integration Tests**: API testing with pytest-asyncio
- **Frontend Tests**: React component testing with Vitest
- **Coverage Reporting**: Code coverage tracking

### 🚀 Deployment & CI/CD
- **Docker Support**: Containerized application deployment
- **Kubernetes**: Production-ready K8s configurations
- **GitHub Actions**: Automated CI/CD pipeline
- **Environment Management**: Comprehensive configuration management

### 💾 Backup & Recovery
- **Automated Backups**: Scheduled database backups
- **Backup Management**: REST API for backup operations
- **Restore Capabilities**: Quick database restoration
- **Backup Cleanup**: Automatic old backup cleanup

### 🎯 Feature Flags
- **Dynamic Feature Toggles**: Runtime feature control
- **Gradual Rollouts**: Percentage-based feature rollout
- **User-based Rollouts**: Targeted feature deployment
- **Feature Management**: API for feature flag management

### 🔄 API Versioning
- **Multiple API Versions**: v1 and v2 API endpoints
- **Backward Compatibility**: Maintain older API versions
- **Version Deprecation**: Controlled API lifecycle management

### ⚡ Performance Optimization
- **Caching Layer**: Redis integration for performance
- **Connection Pooling**: Database connection optimization
- **Static Asset Caching**: Frontend asset optimization
- **Response Compression**: Reduced bandwidth usage

## 🏗️ Architecture

```
User Interface (React + Vite)
         │
         ▼
API Gateway (FastAPI)
         │
         ├── Authentication (JWT, RBAC)
         ├── Input Validation & Sanitization
         ├── Rate Limiting
         ├── Security Headers
         └── Request Logging
         │
         ▼
Business Logic Layer
         │
         ├── Autonomous SOC Analyst
         ├── Log Collection Service
         ├── IOC Extraction Service
         ├── Threat Intelligence Orchestrator
         ├── Investigation Service
         ├── Tool Orchestrator
         ├── Correlation Engine
         ├── Predictive Analytics
         ├── Neural Anomaly Detection
         └── Automated Response
         │
         ▼
Data Layer
         │
         ├── PostgreSQL/SQLite Database
         ├── Redis Cache
         └── File Storage
         │
         ▼
External Integrations
         │
         ├── Windows Event Logs
         ├── Sysmon Logs
         ├── Windows Defender Logs
         ├── VirusTotal
         ├── MITRE ATT&CK
         ├── Sigma Rules
         ├── AbuseIPDB
         ├── Wazuh SIEM
         ├── MISP Threat Intel
         ├── Shodan OSINT
         └── LLM Provider (OpenAI/Ollama)
```

## 📁 Folder Structure

```
MCP-Security-Copilot/
├── backend/
│   ├── app/
│   │   ├── log_collector/          # Windows log collection
│   │   │   ├── windows_log_collector.py
│   │   │   ├── ioc_extractor.py
│   │   │   └── models.py           # Database models
│   │   ├── threat_intel/           # Threat intelligence integration
│   │   │   ├── virustotal_client.py
│   │   │   ├── mitre_attack_client.py
│   │   │   ├── sigma_client.py
│   │   │   ├── abuseipdb_client.py
│   │   │   └── orchestrator.py
│   │   ├── soc_analyst/            # Autonomous SOC analyst
│   │   │   └── autonomous_analyst.py
│   │   ├── routes/
│   │   │   └── log_analysis/       # API endpoints
│   │   │       └── api.py
│   │   ├── auth/                   # Authentication & authorization
│   │   ├── monitoring/             # Monitoring & metrics
│   │   ├── middleware/             # API middleware
│   │   ├── services/               # Business logic services
│   │   ├── utils/                  # Utilities
│   │   ├── database.py             # Database configuration
│   │   ├── main.py                 # FastAPI application
│   │   └── schemas.py              # Pydantic schemas
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── security/           # Security components
│   │   │   │   ├── SecurityDashboard.jsx
│   │   │   │   ├── IOCViewer.jsx
│   │   │   │   └── InvestigationViewer.jsx
│   │   │   └── ui/                 # UI components
│   │   ├── services/               # API services
│   │   ├── styles/                 # Styles
│   │   ├── utils/                  # Utilities
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
├── .env.example
├── docker-compose.yml
└── README.md
```

## 📦 Installation

### Prerequisites
- Python 3.14+
- Node.js 20+
- PostgreSQL 15+ (for production)
- Redis 7+ (optional, for caching)

### Backend Setup

1. Create a Python virtual environment:
```bash
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1  # Windows
source .venv/bin/activate  # Linux/Mac
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Initialize the database:
```bash
python -c "from app.database import init_db; init_db()"
```

5. Start the backend:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend Setup

1. Install dependencies:
```bash
cd frontend
npm install
```

2. Start the development server:
```bash
npm run dev
```

3. Build for production:
```bash
npm run build
```

## 🐳 Docker Deployment

### Using Docker Compose

```bash
docker-compose up --build
```

This will start:
- Backend API (port 8000)
- Frontend (port 80)
- PostgreSQL database (port 5432)
- Redis cache (port 6379)
- Prometheus metrics (port 9090)
- Grafana dashboards (port 3001)

### Kubernetes Deployment

```bash
kubectl apply -f k8s-deployment.yaml
```

## 🔧 Configuration

### Environment Variables

#### Database Configuration
- `DATABASE_URL`: Database connection string
- `DATABASE_POOL_SIZE`: Database connection pool size
- `DATABASE_MAX_OVERFLOW`: Maximum overflow connections

#### Security Configuration
- `SECRET_KEY`: JWT secret key
- `ACCESS_TOKEN_EXPIRE_MINUTES`: Access token expiration
- `REFRESH_TOKEN_EXPIRE_DAYS`: Refresh token expiration

#### API Configuration
- `API_V1_PREFIX`: API v1 prefix
- `MAX_UPLOAD_SIZE`: Maximum file upload size
- `RATE_LIMIT_ENABLED`: Enable rate limiting
- `RATE_LIMIT_PER_MINUTE`: Requests per minute limit

#### Monitoring Configuration
- `PROMETHEUS_ENABLED`: Enable Prometheus metrics
- `PROMETHEUS_PORT`: Prometheus metrics port
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

#### Security Tools Integration
- `WAZUH_API_URL`: Wazuh API endpoint
- `WAZUH_API_KEY`: Wazuh API key
- `VIRUSTOTAL_API_KEY`: VirusTotal API key
- `MISP_API_URL`: MISP API endpoint
- `MISP_API_KEY`: MISP API key
- `SHODAN_API_KEY`: Shodan API key
- `ABUSEIPDB_API_KEY`: AbuseIPDB API key

#### LLM Configuration
- `LLM_PROVIDER`: LLM provider (free, ollama, openai)
- `OLLAMA_URL`: Ollama API endpoint
- `OPENAI_API_KEY`: OpenAI API key
- `OPENAI_MODEL`: OpenAI model name

## 📚 API Documentation

### Authentication Endpoints
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user
- `GET /api/auth/permissions` - Get user permissions

### Investigation Endpoints
- `POST /api/investigate` - Submit investigation query
- `POST /api/chat` - Chat-style investigation
- `POST /api/upload` - Upload file for analysis

### Log Analysis Endpoints
- `POST /api/log-analysis/collect-logs` - Collect Windows Event Logs, Sysmon, and Defender logs
- `POST /api/log-analysis/extract-iocs` - Extract IOCs from collected logs
- `POST /api/log-analysis/threat-intel` - Analyze IOCs against threat intelligence sources
- `POST /api/log-analysis/investigation/start` - Start autonomous SOC investigation
- `GET /api/log-analysis/investigation/{id}` - Get investigation details
- `GET /api/log-analysis/investigation` - List investigations
- `GET /api/log-analysis/iocs` - List IOCs with filtering
- `GET /api/log-analysis/alerts` - List security alerts
- `GET /api/log-analysis/dashboard/stats` - Get dashboard statistics

### User Management Endpoints
- `GET /api/users/` - List users
- `POST /api/users/` - Create user
- `GET /api/users/{id}` - Get user details
- `PUT /api/users/{id}` - Update user
- `DELETE /api/users/{id}` - Delete user
- `GET /api/users/roles/` - List roles
- `GET /api/users/permissions/` - List permissions

### Audit Logging Endpoints
- `GET /api/audit/` - List audit logs
- `GET /api/audit/actions` - List audit actions
- `GET /api/audit/resources` - List audit resources

### Backup Management Endpoints
- `POST /api/backup/create` - Create backup
- `GET /api/backup/list` - List backups
- `POST /api/backup/restore/{name}` - Restore backup
- `DELETE /api/backup/{name}` - Delete backup
- `POST /api/backup/cleanup` - Cleanup old backups

### Feature Flags Endpoints
- `GET /api/feature-flags/` - List feature flags
- `GET /api/feature-flags/{name}` - Get feature flag
- `PUT /api/feature-flags/{name}` - Update feature flag
- `GET /api/feature-flags/{name}/status` - Check flag status

### Monitoring Endpoints
- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics
- `GET /api/info` - System information
- `GET /api/status` - Full system status

## 🔐 Security Best Practices

1. **Change Default Credentials**: Always change the default admin password
2. **Use HTTPS**: Enable HTTPS in production
3. **Configure CORS**: Restrict CORS origins in production
4. **Enable Rate Limiting**: Protect against API abuse
5. **Regular Backups**: Schedule regular database backups
6. **Monitor Logs**: Regularly review audit logs
7. **Update Dependencies**: Keep dependencies updated
8. **Use Environment Variables**: Never commit secrets to code

## 🧪 Testing

### Backend Tests
```bash
cd backend
pytest --cov=app --cov-report=html
```

### Frontend Tests
```bash
cd frontend
npm test -- --coverage
```

## 📈 Monitoring

### Prometheus Metrics
Access metrics at `http://localhost:9090/metrics`

### Grafana Dashboards
Access Grafana at `http://localhost:3001` (default credentials: admin/admin)

## 🔄 CI/CD

The project includes a GitHub Actions workflow for:
- Automated testing
- Docker image building
- Deployment to Kubernetes

## 📝 License

This project is licensed under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## 📞 Support

For support, please open an issue in the GitHub repository or contact the development team.
