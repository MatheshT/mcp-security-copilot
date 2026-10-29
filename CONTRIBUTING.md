# Contributing to MCP Security Copilot

Thank you for your interest in contributing to **MCP Security Copilot**! We welcome bug reports, feature enhancements, documentation improvements, and security playbooks.

---

## Code of Conduct

All contributors and maintainers are expected to adhere to standard professional etiquette, respectful collaboration, and responsible security vulnerability disclosures.

---

## Development Setup

### 1. Prerequisites
- **Python**: 3.11+
- **Node.js**: 18.0+
- **Git**
- Optional: VirtualBox with Wazuh Manager VM for live SIEM telemetry.

### 2. Backend Setup
```bash
cd backend
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
pytest
```

### 3. Frontend Setup
```bash
cd frontend
npm install
npm test
npm run dev
```

---

## Branching & Commit Conventions

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` A new feature or MCP capability
- `fix:` A bug fix or error resolution
- `docs:` Documentation only changes
- `test:` Adding or updating test suites
- `refactor:` Code restructuring without behavior change
- `chore:` Dependency bumps, CI updates, or maintenance

### Pull Request Guidelines
1. Ensure all backend tests pass (`pytest backend/tests`).
2. Ensure frontend tests pass (`npm test`).
3. Maintain clear, single-purpose commits rather than squash-merging monolithic diffs.
4. Update corresponding documentation in `/docs` if MCP tools or API endpoints are added.
