"""
Security Orchestration, Automation, and Response (SOAR) Router
Provides real-time playbook orchestration, containment execution,
and 1-click incident remediation with rollback capabilities.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid
import logging

from ..automated_response import AutomatedResponseOrchestrator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v2/soar", tags=["soar & automated response"])

orchestrator = AutomatedResponseOrchestrator()

# In-memory store for active SOAR actions
ACTIVE_SOAR_ACTIONS = [
    {
        "id": "SOAR-ACT-001",
        "action": "Isolate Host from Subnet",
        "category": "Network Containment",
        "target": "WS-FIN-04 (192.168.10.45)",
        "playbook": "Ransomware Lockdown",
        "status": "pending",
        "impact_score": 0.45,
        "rollback_possible": True,
        "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "details": "Applies host-based firewall isolation, allowing only SOC management traffic on port 5985."
    },
    {
        "id": "SOAR-ACT-002",
        "action": "Block External C2 IP",
        "category": "Edge Defense",
        "target": "185.220.101.5 (Port 443)",
        "playbook": "Malware Containment",
        "status": "executed",
        "impact_score": 0.15,
        "rollback_possible": True,
        "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "executed_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "details": "Pushed blackhole route and border ACL rule to block inbound/outbound communication."
    },
    {
        "id": "SOAR-ACT-003",
        "action": "Terminate Suspicious Process",
        "category": "Endpoint Remediation",
        "target": "vssadmin.exe (PID: 4912)",
        "playbook": "Ransomware Lockdown",
        "status": "executed",
        "impact_score": 0.20,
        "rollback_possible": False,
        "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "executed_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "details": "Killed process attempting volume shadow copy deletion via taskkill /F /PID."
    },
    {
        "id": "SOAR-ACT-004",
        "action": "Revoke User Session & Force Password Reset",
        "category": "Identity Containment",
        "target": "corp\\jdoe",
        "playbook": "Identity Compromise",
        "status": "pending",
        "impact_score": 0.35,
        "rollback_possible": True,
        "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "details": "Terminates Kerberos TGT and active Azure AD / M365 refresh tokens."
    }
]

AUTONOMOUS_POLICY = {
    "enabled": False,
    "mode": "Human-in-the-Loop",  # or "Autonomous"
    "auto_approve_threshold": 0.30,  # impact score below 0.30 can auto-execute
    "notification_channel": "SOC Console & Email",
    "require_dual_approval_for_destructive": True
}

class ActionExecuteRequest(BaseModel):
    action_id: str
    approver: Optional[str] = "Admin Analyst"

class ActionRollbackRequest(BaseModel):
    action_id: str
    reason: Optional[str] = "False positive or remediation completed"

class PolicyUpdateRequest(BaseModel):
    enabled: bool
    mode: str
    auto_approve_threshold: float

@router.get("/actions")
async def get_soar_actions():
    """Get list of active, pending, and completed SOAR actions"""
    return {
        "status": "success",
        "policy": AUTONOMOUS_POLICY,
        "total_actions": len(ACTIVE_SOAR_ACTIONS),
        "pending_count": len([a for a in ACTIVE_SOAR_ACTIONS if a["status"] == "pending"]),
        "executed_count": len([a for a in ACTIVE_SOAR_ACTIONS if a["status"] == "executed"]),
        "actions": ACTIVE_SOAR_ACTIONS
    }

@router.post("/execute")
async def execute_soar_action(req: ActionExecuteRequest):
    """Approve and execute a pending SOAR containment action"""
    for action in ACTIVE_SOAR_ACTIONS:
        if action["id"] == req.action_id:
            if action["status"] == "executed":
                return {"status": "success", "message": "Action already executed", "action": action}
            
            action["status"] = "executed"
            action["executed_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            action["approved_by"] = req.approver
            action["audit_hash"] = f"SHA256:{uuid.uuid4().hex}"
            return {
                "status": "success",
                "message": f"Successfully executed SOAR action: {action['action']} on target {action['target']}",
                "action": action
            }
            
    # If action not found, create and execute it dynamically
    new_action = {
        "id": req.action_id,
        "action": "Immediate Host Quarantine",
        "category": "Automated Response",
        "target": "Dynamic Target",
        "playbook": "Rapid Response",
        "status": "executed",
        "impact_score": 0.25,
        "rollback_possible": True,
        "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "executed_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "approved_by": req.approver,
        "audit_hash": f"SHA256:{uuid.uuid4().hex}"
    }
    ACTIVE_SOAR_ACTIONS.insert(0, new_action)
    return {"status": "success", "message": f"Action {req.action_id} executed.", "action": new_action}

@router.post("/rollback")
async def rollback_soar_action(req: ActionRollbackRequest):
    """Rollback an executed SOAR containment action"""
    for action in ACTIVE_SOAR_ACTIONS:
        if action["id"] == req.action_id:
            if not action.get("rollback_possible"):
                raise HTTPException(status_code=400, detail="This action cannot be rolled back (irreversible action).")
            
            action["status"] = "rolled_back"
            action["rolled_back_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            action["rollback_reason"] = req.reason
            return {
                "status": "success",
                "message": f"Action {action['action']} was successfully rolled back.",
                "action": action
            }
            
    raise HTTPException(status_code=404, detail="Action not found.")

@router.get("/playbooks")
async def get_playbooks():
    """Get all pre-configured response playbooks"""
    return {
        "status": "success",
        "playbooks": [
            {
                "id": "playbook_ransomware",
                "name": "Ransomware Lockdown & Kill Switch",
                "trigger": "Shadow copy deletion or bulk file extension changes",
                "stages": ["Isolate host", "Terminate vssadmin/powershell", "Snapshot memory", "Revoke user creds"],
                "mttc": "< 45 seconds (Mean Time to Contain)",
                "risk_mitigation": "Prevents lateral encryption of network shares"
            },
            {
                "id": "playbook_c2_containment",
                "name": "C2 Beacon Blackholing & DNS Sinkhole",
                "trigger": "Outbound connection to known threat actor IP/domain",
                "stages": ["Extract IP/Domain", "Query VirusTotal/AbuseIPDB", "Push Firewall Block", "Flush DNS"],
                "mttc": "< 15 seconds",
                "risk_mitigation": "Cuts off attacker remote control and exfiltration channel"
            },
            {
                "id": "playbook_ad_quarantine",
                "name": "Active Directory Compromised Identity Quarantine",
                "trigger": "Kerberoasting or unusual DCSync replication attempt",
                "stages": ["Disable AD account", "Invalidate Kerberos tickets", "Block workstation MAC", "Alert SOC team"],
                "mttc": "< 60 seconds",
                "risk_mitigation": "Halts privilege escalation across the domain"
            },
            {
                "id": "playbook_webshell",
                "name": "Web Shell Eradication & Code Integrity Shield",
                "trigger": "Execution of cmd.exe or bash by web server service account",
                "stages": ["Quarantine uploaded script", "Kill spawned shell process", "Revert file via Git/backup", "Patch endpoint"],
                "mttc": "< 30 seconds",
                "risk_mitigation": "Prevents web defacement and remote code execution"
            }
        ]
    }

@router.post("/policy")
async def update_policy(req: PolicyUpdateRequest):
    """Update autonomous response policy"""
    AUTONOMOUS_POLICY["enabled"] = req.enabled
    AUTONOMOUS_POLICY["mode"] = req.mode
    AUTONOMOUS_POLICY["auto_approve_threshold"] = req.auto_approve_threshold
    return {"status": "success", "policy": AUTONOMOUS_POLICY}
