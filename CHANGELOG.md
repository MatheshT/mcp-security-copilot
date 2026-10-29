# Changelog

All notable changes to **MCP Security Copilot** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1.0] - 2026-10-29

### Added
- **Free SOC Intelligence Tools**: Zero-cost integration with CISA KEV (Known Exploited Vulnerabilities), IP-API Geolocation, CIRCL CVE Search, and MITRE ATT&CK STIX 2.1 knowledge base.
- **SOAR Automated Containment**: Automated firewall IP blackholing via `netsh`, endpoint host isolation, and playbook orchestrations (`brute_force`, `ransomware`, `suspicious_process`).
- **Comprehensive Test Suites**:
  - `backend/tests/test_ml_threat_engine.py`: Unit tests for IsolationForest anomaly scoring and RandomForest classification.
  - `backend/tests/test_free_soc_tools.py`: Integration tests for zero-cost threat intel MCP tools.
  - `backend/tests/test_soar_defense.py`: Unit tests for automated containment and security playbooks.
  - `frontend/src/App.test.jsx`: Vitest smoke test suite for the React SOC Command Center.
- **Project Documentation**: Complete MCP tools catalog, ML engine architecture specification, and open-source contribution guidelines.

### Fixed
- Isolated CI tests to mock external dependencies and VirtualBox VM network bridges, eliminating test timeouts.
- Configured Vitest jsdom browser environment for React component rendering tests.

---

## [2.0.0] - 2026-10-25

### Added
- **Machine Learning Threat Detection Engine**:
  - Unsupervised `IsolationForest` anomaly detector with 8% contamination threshold.
  - Supervised `RandomForestClassifier` for automated Level-1 SOC alert triage (Low, Medium, High, Critical).
  - User and Entity Behavior Analytics (UEBA) calculating Z-Score deviations and off-hours activity.
- **Interactive SOC Command Center UI**: Modern React + Vite frontend with real-time threat feed, interactive charts, and instant SOAR action triggers.

---

## [1.5.0] - 2026-10-15

### Added
- **Wazuh SIEM Integration**: Parsing Wazuh `alerts.json` telemetry and agent health polling.
- **Windows Event Log Ingestion**: Native Security Event IDs (4625 brute force, 4672 privilege escalation, 4688 process execution) via Win32 API.
- **AI Investigation Workflows**: Natural language security queries mapped to MCP tools.

---

## [1.0.0] - 2026-09-01

### Added
- Initial release of **MCP Security Copilot**.
- Model Context Protocol (MCP) server foundation over JSON-RPC 2.0.
- Commercial Threat Intelligence MCP tools: VirusTotal, AbuseIPDB, AlienVault OTX, and Shodan.
- FastAPI asynchronous backend architecture.
