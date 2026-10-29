# Model Context Protocol (MCP) Security Tools Catalog

This document provides a comprehensive reference of all 16 Model Context Protocol (MCP) tools integrated into the **MCP-Security-Copilot** autonomous SOC platform.

---

## Architecture Overview

The MCP platform standardizes communication between Large Language Models (LLMs) and heterogeneous security data sources:

```
[ AI SOC Copilot / Claude / GPT / Ollama ]
                    |
              (JSON-RPC 2.0)
                    |
            [ MCP Registry ]
         /          |          \
   [Free Intel]  [API Key Intel] [Local Telemetry]
     - CISA KEV     - VirusTotal    - Wazuh SIEM
     - IP-API       - AbuseIPDB     - Windows Event Logs
     - CIRCL CVE    - AlienVault    - ML Threat Engine
     - MITRE ATT&CK - Shodan        - SOAR Automation
```

---

## 1. Zero-Cost / Free Intelligence Tools (No API Keys Required)

| Tool Name | Server | Description | Endpoint / Source |
|-----------|--------|-------------|-------------------|
| `cisa_kev_lookup` | Free SOC Tools | Queries CISA Known Exploited Vulnerabilities catalog | `cisa.gov/known-exploited-vulnerabilities-catalog` |
| `ip_geolocation` | Free SOC Tools | Resolves IP ASN, ISP, country, and city coordinates | `ip-api.com/json/{ip}` |
| `cve_search` | Free SOC Tools | Deep CVE vulnerability details, CVSS score & exploits | `cve.circl.lu/api/cve/{cve_id}` |
| `mitre_attack_technique` | Free SOC Tools | Maps MITRE ATT&CK TTP ID to tactics & mitigations | Internal STIX 2.1 ATT&CK Knowledge Base |

---

## 2. Commercial Threat Intelligence Tools (Optional API Keys)

| Tool Name | Server | Description | Key Configuration |
|-----------|--------|-------------|-------------------|
| `virustotal_lookup` | Threat Intel | IP, Domain, and File Hash reputation & sandbox reports | `VIRUSTOTAL_API_KEY` |
| `abuseipdb_check` | Threat Intel | Confidence score of abuse and malicious activity | `ABUSEIPDB_API_KEY` |
| `alienvault_otx_pulse` | Threat Intel | Open Threat Exchange community threat pulses & IOCs | `OTX_API_KEY` |
| `shodan_host_scan` | Threat Intel | Open ports, running banners, and vulnerability scans | `SHODAN_API_KEY` |

---

## 3. SIEM & Host Telemetry Tools

| Tool Name | Server | Description | Integration |
|-----------|--------|-------------|-------------|
| `wazuh_alerts_query` | Wazuh SIEM | Real-time and historical Wazuh alerts (JSON-based) | `C:\Program Files (x86)\ossec-agent` / VM |
| `wazuh_agent_status` | Wazuh SIEM | Status, IP, OS and registration state of agents | Wazuh REST API / Local Manager |
| `windows_event_lookup` | Windows Telemetry | Security (4625, 4672, 4688, 7045) & System event logs | `win32evtlog` / PowerShell CLI |
| `windows_live_processes`| Windows Telemetry | Enumerates running tasks, PIDs, parent PIDs, & hashes | `tasklist` / WMI / psutil |

---

## 4. Machine Learning Threat Analysis Tools

| Tool Name | Server | Model / Algorithm | Output |
|-----------|--------|-------------------|--------|
| `ml_detect_anomaly` | ML Threat Engine | `IsolationForest` (contamination=0.08) | Anomaly flag (-1/1), anomaly score (0-1) |
| `ml_predict_severity` | ML Threat Engine | `RandomForestClassifier` | Predicted severity (`low`, `medium`, `high`, `critical`) |
| `ml_analyze_ueba` | ML Threat Engine | User & Entity Behavior Z-Score Analysis | Off-hours flag, volume anomaly, UEBA risk score |

---

## 5. SOAR (Security Orchestration, Automation & Response) Tools

| Tool Name | Server | Action / Capability | Execution Target |
|-----------|--------|---------------------|------------------|
| `soar_block_ip` | SOAR Defense | Blackholes malicious IP via Windows Advanced Firewall | `netsh advfirewall firewall add rule` |
| `soar_isolate_host` | SOAR Defense | Disables external NIC traffic while maintaining SOC tunnel | PowerShell Network Adapter cmdlets |
| `soar_run_playbook` | SOAR Defense | Automated containment workflows (`brute_force`, `ransomware`) | Full orchestrated incident response |

---

## Testing & Verification

Run the automated integration test suite:

```bash
pytest backend/tests/test_free_soc_tools.py -v
pytest backend/tests/test_soar_defense.py -v
```
