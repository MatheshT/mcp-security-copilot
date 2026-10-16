"""
Cyber Range & Attack Scenario Simulator Router
Enables on-demand simulation of realistic cybersecurity attacks, generating
real-time telemetry, alerts, AI correlation, and automated SOAR playbooks.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid
import logging

from ..database import SessionLocal
from ..log_collector.models import Alert, RiskLevel, Investigation, InvestigationStatus
from ..predictive_analytics import PredictiveSecurityEngine
from ..threat_actor_persona import ThreatActorPersonaEngine
from ..automated_response import AutomatedResponseOrchestrator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v2/simulator", tags=["attack simulator"])

predictive_engine = PredictiveSecurityEngine()
persona_engine = ThreatActorPersonaEngine()
soar_orchestrator = AutomatedResponseOrchestrator()

# Pre-configured Attack Scenarios
SCENARIOS = {
    "ransomware_lockbit": {
        "id": "ransomware_lockbit",
        "title": "LockBit 3.0 Ransomware Emulation",
        "category": "Ransomware & Extortion",
        "threat_actor": "LockBit Supporter / FIN7 Affiliate",
        "severity": "critical",
        "description": "Simulates ransomware intrusion starting with malicious macro payload, shadow copy deletion (vssadmin), file encryption staging, and C2 beaconing.",
        "kill_chain_steps": [
            {"phase": "Initial Access", "technique": "T1566.001 - Spearphishing Attachment", "details": "Invoice_PO_9921.xlsm executed by user jdoe"},
            {"phase": "Execution", "technique": "T1059.001 - PowerShell In-Memory Payload", "details": "powershell.exe -enc SQBFAFgA... downloaded stager"},
            {"phase": "Defense Evasion", "technique": "T1562.001 - Disable Security Tools", "details": "Attempted to stop WinDefend and shadow copies via vssadmin.exe delete shadows /all /quiet"},
            {"phase": "Command & Control", "technique": "T1071.001 - HTTPS C2 Beaconing", "details": "Outbound beacons to 185.220.101.5 on port 443 at 30s intervals"},
            {"phase": "Impact", "technique": "T1486 - Data Encrypted for Impact", "details": "Staged file renaming with .lockbit extension detected on C:\\Shares\\Finance"}
        ],
        "iocs": [
            {"type": "ip", "value": "185.220.101.5", "reputation": "Malicious (VirusTotal 58/70)", "role": "C2 Server"},
            {"type": "domain", "value": "sync-cloud-updater.com", "reputation": "Suspicious / Newly Registered", "role": "Payload Delivery"},
            {"type": "hash", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "reputation": "LockBit 3.0 Encryptor", "role": "Malware Sample"},
            {"type": "process", "value": "vssadmin.exe", "reputation": "System Binary (Misused)", "role": "Defense Evasion"}
        ],
        "affected_host": "WS-FIN-04 (192.168.10.45)",
        "affected_user": "corp\\jdoe (Finance Analyst)"
    },
    "ad_kerberoast": {
        "id": "ad_kerberoast",
        "title": "Active Directory Kerberoasting & Lateral Movement",
        "category": "Credential Access & Identity",
        "threat_actor": "APT29 (Cozy Bear) TTPs",
        "severity": "high",
        "description": "Adversary requests Service Principal Names (SPN) Kerberos TGS tickets for offline password cracking, followed by lateral movement over SMB.",
        "kill_chain_steps": [
            {"phase": "Reconnaissance", "technique": "T1087.002 - Domain Account Discovery", "details": "Querying domain controllers for active SPNs registered to privileged accounts"},
            {"phase": "Credential Access", "technique": "T1558.003 - Kerberoasting", "details": "TGS request with RC4 encryption (Event ID 4769) for SPN MSSQLSvc/db01.corp:1433"},
            {"phase": "Lateral Movement", "technique": "T1021.002 - SMB/Windows Admin Shares", "details": "Connection to DC01.corp admin$ share using extracted service ticket hash"},
            {"phase": "Persistence", "technique": "T1078.002 - Domain Admin Account Access", "details": "svc_sql_admin logged in outside of normal maintenance window"}
        ],
        "iocs": [
            {"type": "ip", "value": "192.168.10.88", "reputation": "Internal Compromised Host", "role": "Pivot Workstation"},
            {"type": "account", "value": "svc_sql_admin", "reputation": "High Privilege Account", "role": "Compromised Identity"},
            {"type": "ticket", "value": "MSSQLSvc/db01.corp:1433", "reputation": "TGS RC4 Request", "role": "Kerberoast Target"}
        ],
        "affected_host": "DC-PRIMARY-01 (192.168.1.10)",
        "affected_user": "corp\\svc_sql_admin (Database Service)"
    },
    "webshell_rce": {
        "id": "webshell_rce",
        "title": "Web Shell Injection & Remote Code Execution",
        "category": "Web Exploitation",
        "threat_actor": "Unknown Web-based Exploit Kit",
        "severity": "critical",
        "description": "Simulates exploitation of public-facing web server via file upload vulnerability, dropping a persistent web shell (c99.php), and establishing root reverse shell.",
        "kill_chain_steps": [
            {"phase": "Initial Access", "technique": "T1190 - Exploit Public-Facing Application", "details": "POST /api/upload bypassed file extension filter to upload shell.aspx"},
            {"phase": "Persistence", "technique": "T1505.003 - Web Shell", "details": "Web shell deployed in /wwwroot/assets/uploads/shell.aspx"},
            {"phase": "Execution", "technique": "T1059.003 - Windows Command Shell", "details": "w3wp.exe spawned cmd.exe running whoami /all and net localgroup administrators"},
            {"phase": "Exfiltration", "technique": "T1048 - Exfiltration Over Alternative Protocol", "details": "Customer database backup archive sent via DNS tunneling to ns1.data-leak-sink.org"}
        ],
        "iocs": [
            {"type": "ip", "value": "45.142.195.12", "reputation": "Known Malicious Scanner (AbuseIPDB 100%)", "role": "Attacker IP"},
            {"type": "file", "value": "shell.aspx", "reputation": "Antiy-AVL: WebShell.Generic", "role": "Web Shell Artifact"},
            {"type": "domain", "value": "data-leak-sink.org", "reputation": "DNS Exfiltration Sinkhole", "role": "Exfiltration Endpoint"}
        ],
        "affected_host": "WEB-SRV-PROD01 (172.16.20.15)",
        "affected_user": "IIS_IUSRS (Web Service Account)"
    },
    "apt29_cozybear": {
        "id": "apt29_cozybear",
        "title": "APT29 Nation-State Identity & Cloud Exfiltration",
        "category": "Advanced Persistent Threat",
        "threat_actor": "APT29 (Cozy Bear)",
        "severity": "critical",
        "description": "Emulates sophisticated nation-state espionage with password spray, OAuth consent grant abuse, and stealthy mail exfiltration.",
        "kill_chain_steps": [
            {"phase": "Credential Access", "technique": "T1110.003 - Password Spraying", "details": "1 login attempt per account across 250 users targeting Entra ID / M365"},
            {"phase": "Defense Evasion", "technique": "T1098.005 - Device Registration Hijack", "details": "Bypassed MFA by registering rogue secondary device from VPN IP"},
            {"phase": "Collection", "technique": "T1114.002 - Remote Email Collection", "details": "Graph API read permissions utilized to extract executive mailbox archives"},
            {"phase": "Exfiltration", "technique": "T1567.002 - Exfiltration to Cloud Storage", "details": "Data synced to legitimate cloud storage bucket to evade egress detection"}
        ],
        "iocs": [
            {"type": "ip", "value": "91.240.118.172", "reputation": "Tor Exit Node / Bulletproof Hosting", "role": "Password Spray Source"},
            {"type": "client_id", "value": "398102a9-11f2-4bc3-a9d1-0182741982aa", "reputation": "Illegitimate OAuth App", "role": "Data Exfiltration App"}
        ],
        "affected_host": "M365-TENANT-PROD",
        "affected_user": "exec.assistant@corp.com"
    },
    "brute_force_ssh": {
        "id": "brute_force_ssh",
        "title": "Distributed SSH / RDP Brute Force Attack",
        "category": "Credential Stuffing",
        "threat_actor": "Automated Botnet (Mirai Variant)",
        "severity": "high",
        "description": "Massive credential stuffing and brute force attempts against exposed SSH/RDP services triggering threshold detection rules.",
        "kill_chain_steps": [
            {"phase": "Reconnaissance", "technique": "T1046 - Network Service Scanning", "details": "Port scan detected targeting ports 22, 3389, and 445 across DMZ"},
            {"phase": "Credential Access", "technique": "T1110.001 - Password Guessing", "details": "1,420 failed authentication attempts within 5 minutes against root, admin, support"},
            {"phase": "Defense Evasion", "technique": "T1070.004 - File Deletion", "details": "Attempted deletion of /var/log/auth.log via script payload"}
        ],
        "iocs": [
            {"type": "ip", "value": "194.26.29.112", "reputation": "Hostile Botnet C2 (AbuseIPDB 98%)", "role": "Scanner Node"},
            {"type": "ip", "value": "89.208.107.50", "reputation": "Distributed Botnet Node", "role": "Brute Force Source"}
        ],
        "affected_host": "EDGE-GATEWAY-01 (10.0.0.1)",
        "affected_user": "root, admin, devops"
    }
}

class LaunchSimulationRequest(BaseModel):
    scenario_id: str
    auto_remediate: Optional[bool] = False

@router.get("/scenarios")
async def get_scenarios():
    """List all available cyber range attack simulation scenarios"""
    return {
        "status": "success",
        "total_scenarios": len(SCENARIOS),
        "scenarios": list(SCENARIOS.values())
    }

@router.post("/launch")
async def launch_simulation(req: LaunchSimulationRequest):
    """
    Launch a live cyber attack simulation.
    Injects alerts, triggers AI threat actor analysis, predicts posture impact,
    and constructs automated SOAR containment playbooks.
    """
    scenario = SCENARIOS.get(req.scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{req.scenario_id}' not found.")
    
    sim_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.utcnow()
    
    # 1. Generate Alerts in DB
    db = SessionLocal()
    created_alert_ids = []
    try:
        for idx, step in enumerate(scenario["kill_chain_steps"]):
            alert_id = f"ALT-{uuid.uuid4().hex[:6].upper()}"
            sev_enum = RiskLevel.CRITICAL if scenario["severity"] == "critical" else RiskLevel.HIGH
            
            db_alert = Alert(
                alert_id=alert_id,
                title=f"[{scenario['category']}] {step['technique']}",
                description=f"{step['details']} (Host: {scenario['affected_host']}, User: {scenario['affected_user']})",
                severity=sev_enum,
                alert_type=step["phase"],
                source="CyberRange Simulator",
                status="active",
                detection_rule=step["technique"],
                iocs_involved=[ioc["value"] for ioc in scenario["iocs"]],
                affected_hosts=[scenario["affected_host"]],
                affected_users=[scenario["affected_user"]],
                first_seen=timestamp,
                last_seen=timestamp,
                alert_metadata={"simulation_id": sim_id, "scenario": req.scenario_id}
            )
            db.add(db_alert)
            created_alert_ids.append(alert_id)
        
        # Create an Investigation record
        inv_record = Investigation(
            investigation_id=sim_id,
            title=f"Incident Response: {scenario['title']}",
            description=scenario["description"],
            status=InvestigationStatus.COMPLETED,
            investigation_type=scenario["category"],
            priority=scenario["severity"],
            risk_score=94.5 if scenario["severity"] == "critical" else 78.0,
            risk_level=RiskLevel.CRITICAL if scenario["severity"] == "critical" else RiskLevel.HIGH,
            log_sources=["Sysmon", "Windows Security", "Wazuh Agent", "CyberRange Engine"],
            key_findings=[step["details"] for step in scenario["kill_chain_steps"]],
            executive_summary=(
                f"Autonomous SOC Copilot detected an active {scenario['title']} operation targeting {scenario['affected_host']}. "
                f"Threat actor behaviors strongly align with {scenario['threat_actor']}. "
                f"Extracted {len(scenario['iocs'])} high-confidence IOCs and mapped {len(scenario['kill_chain_steps'])} MITRE ATT&CK techniques. "
                f"Containment playbooks have been staged for remediation."
            ),
            recommendations=[
                f"Immediately isolate host {scenario['affected_host']} from enterprise subnet",
                f"Block malicious indicator {scenario['iocs'][0]['value']} at edge perimeter firewall",
                f"Revoke all active sessions and rotate credentials for {scenario['affected_user']}",
                "Perform full forensic memory dump and sweep endpoints for secondary persistence"
            ],
            created_by="Autonomous SOC Copilot"
        )
        db.add(inv_record)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to record simulation alerts: {e}")
    finally:
        db.close()
    
    # 2. Predictive Analytics & Persona Engine Analysis
    attack_data = {
        "tools": [ioc["value"] for ioc in scenario["iocs"]],
        "techniques": [step["technique"].split(" - ")[0] for step in scenario["kill_chain_steps"]],
        "targets": ["government", "enterprise", "finance"],
        "target_industries": ["banking", "technology"],
        "uses_custom_malware": scenario["severity"] == "critical",
        "uses_zero_day": "Zero-Day" in str(scenario),
        "uses_encryption": "Ransomware" in scenario["category"],
        "uses_anti_forensics": True,
        "uses_opsec": True
    }
    
    actor_analysis = persona_engine.analyze_actor_persona(attack_data)
    
    # 3. Automated SOAR Response Plan
    incident_assessment = {
        "severity": scenario["severity"],
        "affected_assets": [scenario["affected_host"]],
        "data_sensitivity": "critical" if scenario["severity"] == "critical" else "high",
        "operational_impact": "high"
    }
    soar_plan = soar_orchestrator.initiate_automated_response(
        incident_assessment,
        playbook_id="malware" if "Ransomware" in scenario["category"] else "data_breach",
        auto_approve=req.auto_remediate
    )
    
    return {
        "status": "success",
        "simulation_id": sim_id,
        "scenario": scenario,
        "timestamp": timestamp.isoformat(),
        "alerts_generated": len(created_alert_ids),
        "alert_ids": created_alert_ids,
        "threat_actor_attribution": {
            "attributed_actor": actor_analysis.get("actor_identification", {}).get("actor_name", scenario["threat_actor"]),
            "confidence": f"{actor_analysis.get('confidence_level', 88)}%",
            "motivation": actor_analysis.get("persona_profile", {}).get("motivation", {}).get("primary_motivation", "financial_extortion"),
            "operational_style": actor_analysis.get("persona_profile", {}).get("operational_style", "Aggressive, automated persistence")
        },
        "soar_remediation": {
            "response_id": soar_plan.get("response_id"),
            "playbook": soar_plan.get("playbook_name"),
            "actions_automated": soar_plan.get("actions_automated"),
            "actions_requiring_approval": soar_plan.get("actions_requiring_approval"),
            "containment_actions": [
                {
                    "id": f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    "action": "Subnet & Network Host Isolation",
                    "target": scenario["affected_host"],
                    "status": "Executed" if req.auto_remediate else "Pending Approval",
                    "risk_level": "Low Impact on other hosts",
                    "auto_approved": req.auto_remediate
                },
                {
                    "id": f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    "action": "Perimeter IP Block (Firewall)",
                    "target": scenario["iocs"][0]["value"],
                    "status": "Executed" if req.auto_remediate else "Pending Approval",
                    "risk_level": "Safe (External Malicious IP)",
                    "auto_approved": True
                },
                {
                    "id": f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    "action": "Session Revocation & Password Reset",
                    "target": scenario["affected_user"],
                    "status": "Executed" if req.auto_remediate else "Pending Approval",
                    "risk_level": "Account Lockout Required",
                    "auto_approved": False
                }
            ]
        },
        "ai_soc_verdict": {
            "risk_score": 96 if scenario["severity"] == "critical" else 82,
            "threat_level": "CRITICAL - IMMEDIATE INTERVENTION REQUIRED",
            "summary": (
                f"SentinelAI X detected active execution of {scenario['title']}. "
                f"Multi-stage correlation confirmed malicious intent with {len(scenario['kill_chain_steps'])} mapped ATT&CK techniques. "
                f"All IOCs have been cross-referenced against VirusTotal and AbuseIPDB. Playbook {soar_plan.get('playbook_name')} has been initialized."
            )
        }
    }

@router.post("/reset")
async def reset_simulations():
    """Clear simulated alerts from active store"""
    db = SessionLocal()
    try:
        deleted = db.query(Alert).filter(Alert.source == "CyberRange Simulator").delete()
        db.commit()
        return {"status": "success", "message": f"Cleared {deleted} simulation alerts."}
    except Exception as e:
        db.rollback()
        return {"status": "error", "message": str(e)}
    finally:
        db.close()
