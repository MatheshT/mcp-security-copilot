# MCP Security Copilot

A prototype AI-powered Security Copilot with a React frontend and FastAPI backend. The backend can perform security investigation analysis, correlate tool outputs, and generate SOC-style investigation reports with per-tool visualizations and unified correlation analysis.

## 🚀 New Architecture

The Security Copilot now features a modular architecture with per-tool report generation and a unified correlation engine:

```
User Query
      │
      ▼
Intent Detection
      │
      ▼
Tool Planner
      │
      ├── VirusTotal
      ├── Wazuh
      ├── MISP
      └── Shodan
      │
      ▼
Each Tool Generates Its Own Report
      │
      ├── VirusTotal Report (with visualizations)
      ├── Wazuh Report (with attack chain)
      ├── MISP Report (with threat actor profile)
      └── Shodan Report (with exposure metrics)
      │
      ▼
Correlation Engine
      │
      ├── Security Score Calculation
      ├── Threat Timeline Generation
      ├── Attack Graph Mapping
      └── Threat Actor Profiling
      │
      ▼
Unified SOC Report
      │
      ▼
AI Summary
```

## ✨ Key Features

### 📊 Professional Dashboard
- **Real-time Statistics**: Overview of total investigations, severity breakdown, and active cases
- **Interactive Filtering**: Filter by severity, status, and sort by date or severity
- **Tool Status Monitoring**: Real-time status indicators for all integrated security tools
- **Investigation Table**: Professional table view with quick actions and detailed information
- **Responsive Design**: Works seamlessly on desktop, tablet, and mobile devices

### 🔧 Per-Tool Analysis Reports
- **VirusTotal**: Reputation scores, detection ratios, geographic data
- **Wazuh SIEM**: Alert details, severity levels, MITRE technique mapping
- **MISP Threat Intel**: Threat actor attribution, campaign tracking, galaxy clusters
- **Shodan OSINT**: Infrastructure exposure, vulnerability scanning, service enumeration

### 📊 Enhanced Visualizations
- **Progress bars** for detection ratios and threat scores
- **Attack chain visualization** showing kill chain progression
- **Risk badges** with color-coded severity levels
- **Score bars** for threat sophistication and exposure metrics
- **Dark mode support** for low-light environments
- **Interactive dashboard** with live statistics and tool status

### 🎯 Unique Security Features
- **Security Score Calculation**: Overall risk assessment based on all tool outputs
- **Threat Timeline**: Chronological view of security events across tools
- **Attack Graph**: Entity-relationship mapping of threats, actors, and targets
- **Threat Actor Profiling**: Detailed profiles including motivations and typical targets
- **Correlation Engine**: AI-powered analysis that combines insights from multiple sources

### 📎 File Upload Support
- Upload logs, images, screenshots, and configuration files
- Automatic hash extraction and IOC identification
- File analysis with security tool correlation
- Drag-and-drop interface with progress tracking

### 🎛️ Professional UI/UX
- **Collapsible Sidebar**: Space-efficient navigation with collapsible sidebar
- **View Switching**: Toggle between Chat and Dashboard views
- **Settings Modal**: Comprehensive settings for appearance, tools, and notifications
- **Advanced Filtering**: Multiple filter options for investigations
- **Sorting Options**: Sort by newest, oldest, or severity
- **Responsive Design**: Optimized for all screen sizes

## Repository structure

- `backend/` — FastAPI backend, MCP tool registry, security orchestration, reporting, and tool integration.
- `frontend/` — React + Vite application for submitting investigation queries and viewing results.

## Local development

### Backend

1. Create a Python virtual environment.
   ```bash
   cd backend
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
2. Set environment variables as needed.
3. Start the backend:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```
4. Verify health check:
   ```bash
   curl http://127.0.0.1:8000/health
   ```

### Frontend

1. Install dependencies.
   ```bash
   cd frontend
   npm install
   ```
2. Start Vite:
   ```bash
   npm run dev -- --host 0.0.0.0 --port 5173
   ```
3. Open the app in the browser at `http://127.0.0.1:5173`

## Environment variables

The backend uses the following variables:

- `LLM_PROVIDER` — `free`, `ollama`, or `openai` (default: `free`)
- `OLLAMA_URL` — local Ollama URL when using `ollama`
- `OPENAI_API_KEY` — OpenAI API key for `openai` provider
- `WAZUH_API_URL` — Wazuh API base URL
- `WAZUH_API_KEY` — Wazuh API key
- `VIRUSTOTAL_API_KEY` — VirusTotal API key
- `MISP_API_URL` — MISP API base URL
- `MISP_API_KEY` — MISP API key
- `SHODAN_API_KEY` — Shodan API key
- `DEFAULT_SECURITY_TOOLS` — comma-separated tool list, defaults to `Wazuh,VirusTotal,MISP,Shodan`

The frontend can override the API backend URL with:

- `VITE_API_URL` — backend API base URL for Vite proxy

## API endpoints

- `GET /health` — health check
- `POST /api/investigate` — analyze an investigation query
- `POST /api/chat` — analyze a chat-style investigation request
- `POST /api/upload` — upload and analyze files/images

### Example requests

**Investigation Query:**
```bash
curl -X POST http://127.0.0.1:8000/api/investigate \
  -H "Content-Type: application/json" \
  -d '{"query":"Investigate suspicious login attempt"}'
```

**File Upload:**
```bash
curl -X POST http://127.0.0.1:8000/api/upload \
  -F "file=@suspicious.log"
```

## Usage Examples

### Example 1: IP Lookup
**User:** Check IP 185.220.101.45

**Result:** Only VirusTotal is used for IOC lookup with detailed reputation analysis and visualization.

### Example 2: Incident Investigation
**User:** Investigate Alert 101

**Result:** 
- **Wazuh Report**: Alert details, severity, MITRE technique
- **VirusTotal Report**: IP reputation and detection ratios
- **MISP Report**: Threat actor attribution and campaign mapping
- **Shodan Report**: Infrastructure exposure and vulnerability scan
- **Unified Report**: Correlated analysis with security score and timeline

## Docker / Compose

Build and run the full stack using Docker Compose:

```bash
docker compose up --build
```

Then open the frontend at `http://127.0.0.1:5173`.

## Notes

- The backend includes fallback logic for LLM and tool calls if external integrations are unavailable.
- Update `.env` or environment variables to provide service credentials before using Wazuh, VirusTotal, MISP, or Shodan APIs.
- The correlation engine automatically generates security scores, timelines, and attack graphs based on available tool data.
- File upload supports various formats including logs, images, and configuration files for automated IOC extraction.
