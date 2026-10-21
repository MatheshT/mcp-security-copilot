"""
MITRE ATT&CK Knowledge & TTP Navigation MCP Server
Interfaces with the MITRE ATT&CK enterprise matrix taxonomy for tactics, techniques,
detection analytics, and defensive mitigations.
100% Free - Standard SOC cyber defense knowledge framework.
"""
import re
import logging
from typing import Any, Dict
from .tool_server import BaseMCPServer, ToolRequest, ToolResponse

logger = logging.getLogger(__name__)

# MITRE ATT&CK Enterprise Matrix Knowledge Base
MITRE_TTP_DATABASE: Dict[str, Dict[str, Any]] = {
    "t1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "sub_techniques": ["T1059.001 (PowerShell)", "T1059.003 (Windows Command Shell)", "T1059.004 (Unix Shell)", "T1059.007 (JavaScript)"],
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "detection": "Monitor process creation events (Sysmon Event ID 1 / Windows 4688) with command-line auditing enabled. Look for encoded commands (-enc, -e) and unquoted paths.",
        "mitigation": ["M1047: Audit Script Execution", "M1038: Execution Prevention (AppLocker / WDAC)", "M1026: Privileged Account Management"]
    },
    "t1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "sub_techniques": ["T1110.001 (Password Guessing)", "T1110.003 (Password Spraying)", "T1110.004 (Credential Stuffing)"],
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are unavailable.",
        "detection": "Monitor authentication failures across endpoints (Windows Event ID 4625, Linux /var/log/auth.log) for bursts exceeding baseline thresholds.",
        "mitigation": ["M1036: Account Use Policies & Lockout Thresholds", "M1032: Multi-Factor Authentication (MFA)", "M1037: Filter Network Traffic"]
    },
    "t1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "sub_techniques": ["None"],
        "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.",
        "detection": "High volume of file modifications, renames, and deletions in short intervals. Creation of known ransom notes and execution of vssadmin delete shadows.",
        "mitigation": ["M1053: Data Backup (Offline & Immutable)", "M1040: Behavior Prevention on Endpoint (EDR)", "M1018: User Account Management"]
    },
    "t1055": {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
        "sub_techniques": ["T1055.001 (Dynamic-link Library Injection)", "T1055.012 (Process Hollowing)"],
        "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
        "detection": "Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess) targeting lsass.exe, explorer.exe, or svchost.exe.",
        "mitigation": ["M1038: Execution Prevention", "M1026: Privileged Account Management", "M1050: Exploit Protection"]
    },
    "t1105": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "sub_techniques": ["None"],
        "description": "Adversaries may transfer tools or other files from an external system into a compromised network using built-in utilities (certutil, bitsadmin, curl, powershell).",
        "detection": "Command line parameters containing 'certutil -urlcache', 'bitsadmin /transfer', or PowerShell 'Invoke-WebRequest' to external unknown IPs.",
        "mitigation": ["M1031: Network Intrusion Prevention", "M1021: Restrict Web-Based Content", "M1038: Execution Prevention"]
    },
    "t1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "sub_techniques": ["T1078.001 (Default Accounts)", "T1078.002 (Domain Accounts)", "T1078.003 (Local Accounts)"],
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "detection": "Monitor logon behavior anomalies: off-hours access, geographically impossible travel, and sudden privilege escalation.",
        "mitigation": ["M1032: Multi-Factor Authentication", "M1027: Password Policies", "M1018: User Account Management"]
    }
}


class MitreAttackServer(BaseMCPServer):
    name = "MITRE_ATTACK"
    description = "MITRE ATT&CK Matrix & TTP Navigation MCP Server - Tactical mapping of adversary techniques and defensive mitigations"
    supported_features = [
        "lookup_technique",
        "search_by_keyword",
        "get_mitigations"
    ]

    def __init__(self):
        super().__init__()
        logger.info("[MITRE_ATTACK MCP] Initialized with Enterprise ATT&CK matrix knowledge base.")

    def lookup_technique(self, technique_id: str) -> ToolResponse:
        """Lookup a MITRE ATT&CK Technique (e.g. T1059, T1110)"""
        clean_id = technique_id.strip().upper()
        # Strip sub-technique for main lookup
        main_key = clean_id.split('.')[0].lower()

        if main_key in MITRE_TTP_DATABASE:
            ttp = MITRE_TTP_DATABASE[main_key]
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "technique_id": ttp["id"],
                    "technique_name": ttp["name"],
                    "tactic": ttp["tactic"],
                    "sub_techniques": ttp["sub_techniques"],
                    "description": ttp["description"],
                    "detection_strategy": ttp["detection"],
                    "mitigations": ttp["mitigation"],
                    "framework": "MITRE ATT&CK Enterprise Matrix v14"
                },
                details=f"MITRE {ttp['id']}: {ttp['name']} ({ttp['tactic']}) mapped successfully."
            )

        # Keyword fuzzy search
        for key, ttp in MITRE_TTP_DATABASE.items():
            if main_key in ttp["name"].lower() or main_key in ttp["description"].lower():
                return ToolResponse(
                    tool_name=self.name,
                    status="success",
                    data={
                        "technique_id": ttp["id"],
                        "technique_name": ttp["name"],
                        "tactic": ttp["tactic"],
                        "description": ttp["description"],
                        "detection_strategy": ttp["detection"],
                        "mitigations": ttp["mitigation"],
                        "framework": "MITRE ATT&CK Enterprise Matrix"
                    },
                    details=f"MITRE keyword match for '{main_key}': {ttp['id']} - {ttp['name']}."
                )

        return ToolResponse(
            tool_name=self.name,
            status="success",
            data={
                "technique_id": clean_id,
                "framework": "MITRE ATT&CK",
                "guidance": f"Reference technique {clean_id}. Consult https://attack.mitre.org/techniques/{clean_id}/ for full behavioral telemetry matrix."
            },
            details=f"MITRE technique inquiry processed for {clean_id}."
        )

    def handle_request(self, request: ToolRequest) -> ToolResponse:
        query = request.query.strip()
        match = re.search(r'(t\d{4}(?:\.\d{3})?)', query, re.I)
        target = match.group(1) if match else query
        return self.lookup_technique(target)
