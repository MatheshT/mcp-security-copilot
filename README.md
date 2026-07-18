# MCP Security Copilot

A prototype AI-powered Security Copilot with a React frontend and FastAPI backend. The backend can perform security investigation analysis, correlate tool outputs, and generate SOC-style investigation reports.

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
- `DEFAULT_SECURITY_TOOLS` — comma-separated tool list, defaults to `Wazuh,VirusTotal`

The frontend can override the API backend URL with:

- `VITE_API_URL` — backend API base URL for Vite proxy

## API endpoints

- `GET /health` — health check
- `POST /api/investigate` — analyze an investigation query
- `POST /api/chat` — analyze a chat-style investigation request

### Example request

```bash
curl -X POST http://127.0.0.1:8000/api/investigate \
  -H "Content-Type: application/json" \
  -d '{"query":"Investigate suspicious login attempt"}'
```

## Docker / Compose

Build and run the full stack using Docker Compose:

```bash
docker compose up --build
```

Then open the frontend at `http://127.0.0.1:5173`.

## Notes

- The backend includes fallback logic for LLM and tool calls if external integrations are unavailable.
- Update `.env` or environment variables to provide service credentials before using Wazuh or VirusTotal APIs.
