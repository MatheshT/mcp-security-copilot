import logging
import re
from typing import Any, Dict, List
from .tool_server import BaseMCPServer, ToolRequest, ToolResponse

logger = logging.getLogger(__name__)


class SOARServer(BaseMCPServer):
    name = "SOAR"
    description = "SOAR Active Defense & Automated Countermeasure Server"
    supported_features = [
        "block_ip",
        "isolate_host",
        "quarantine_file",
        "run_playbook",
        "get_playbooks",
        "get_actions"
    ]

    def __init__(self):
        super().__init__()
        self.blocked_ips = set(["185.220.101.5", "194.26.29.112", "91.240.118.22"])
        self.isolated_hosts = set(["WS-FIN-04"])
        self.action_history = [
            {"action": "block_ip", "target": "185.220.101.5", "status": "executed", "timestamp": "2026-10-16 10:15:00", "rule_id": "FW-892"},
            {"action": "isolate_host", "target": "WS-FIN-04", "status": "executed", "timestamp": "2026-10-16 09:44:12", "rule_id": "ISO-041"},
        ]

    def block_ip(self, ip: str) -> ToolResponse:
        self.blocked_ips.add(ip)
        action_record = {
            "action": "block_ip",
            "target": ip,
            "status": "executed",
            "rule_id": f"FW-{len(self.action_history) + 900}",
            "message": f"Successfully blackholed IP {ip} across perimeter firewall cluster"
        }
        self.action_history.append(action_record)
        logger.info(f"[SOAR] Blackholed malicious IP: {ip}")
        return ToolResponse(
            tool_name=self.name,
            status="success",
            data={
                "action": "block_ip",
                "ip": ip,
                "status": "BLOCKED",
                "firewall_rule": action_record["rule_id"],
                "mitigation": "Ingress & Egress traffic dropped at perimeter gateway."
            },
            details=f"IP {ip} successfully blackholed and dropped across all edge firewalls."
        )

    def isolate_host(self, host: str) -> ToolResponse:
        self.isolated_hosts.add(host)
        action_record = {
            "action": "isolate_host",
            "target": host,
            "status": "executed",
            "rule_id": f"ISO-{len(self.action_history) + 100}",
            "message": f"Host {host} network isolation enforced via Wazuh active-response"
        }
        self.action_history.append(action_record)
        logger.info(f"[SOAR] Network isolation enforced on host: {host}")
        return ToolResponse(
            tool_name=self.name,
            status="success",
            data={
                "action": "isolate_host",
                "host": host,
                "status": "ISOLATED",
                "containment": "Network adapter isolated. Management channel preserved for forensics."
            },
            details=f"Host {host} has been placed into network quarantine."
        )

    def run_playbook(self, playbook_name: str) -> ToolResponse:
        playbooks = {
            "malware": "Malware Containment & C2 Blackhole Playbook",
            "ransomware": "Anti-Ransomware Snapshot & VSS Defense Playbook",
            "ddos": "DDoS Cloud Scrubbing & Rate Limiting Playbook",
            "credential_theft": "Credential Revocation & Token Flush Playbook"
        }
        selected = playbooks.get(playbook_name.lower(), f"Custom Playbook: {playbook_name}")
        return ToolResponse(
            tool_name=self.name,
            status="success",
            data={
                "playbook": selected,
                "status": "COMPLETED",
                "steps_executed": [
                    "Threat signal validated against SIEM baseline",
                    "Target indicators extracted and correlated",
                    "Automated containment rule injected into firewall cluster",
                    "Host memory snapshot preserved for forensic timeline",
                    "Threat mitigated with zero system downtime"
                ]
            },
            details=f"SOAR Playbook '{selected}' executed successfully."
        )

    def get_playbooks(self) -> ToolResponse:
        return ToolResponse(
            tool_name=self.name,
            status="success",
            data={
                "available_playbooks": [
                    {"id": "malware", "name": "Malware Containment Playbook", "type": "Autonomous"},
                    {"id": "ransomware", "name": "Ransomware Defense Playbook", "type": "Autonomous"},
                    {"id": "ddos", "name": "DDoS Mitigation Playbook", "type": "Automated"},
                    {"id": "credential_theft", "name": "Credential Revocation Playbook", "type": "Active"}
                ]
            },
            details="Retrieved list of active SOAR defense playbooks."
        )

    def handle_request(self, request: ToolRequest) -> ToolResponse:
        query = request.query.lower().strip()

        # Block IP
        if "block" in query:
            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', query)
            target_ip = ip_match.group(0) if ip_match else "185.220.101.5"
            return self.block_ip(target_ip)

        # Isolate Host
        elif "isolate" in query or "quarantine" in query:
            parts = query.split()
            host = parts[-1] if len(parts) > 1 and parts[-1] not in ["host", "endpoint", "system"] else "Windows11"
            return self.isolate_host(host)

        # Run Playbook
        elif "playbook" in query or "mitigate" in query:
            for pb in ["ransomware", "malware", "ddos", "credential"]:
                if pb in query:
                    return self.run_playbook(pb)
            return self.run_playbook("malware")

        # Default: list playbooks
        return self.get_playbooks()
