from pydantic import BaseModel
from typing import Any, Dict, List, Literal, Optional
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    """Severity levels for alerts"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class InvestigationStatus(str, Enum):
    """Status of investigations"""
    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    RESOLVED = "Resolved"
    PENDING = "Pending"
    ESCALATED = "Escalated"


class DashboardStats(BaseModel):
    """Dashboard statistics"""
    total_alerts: int
    critical: int
    high: int
    medium: int
    low: int
    investigated: int
    total_investigations: int
    pending: Optional[int] = 0
    resolved: Optional[int] = 0
    in_progress: Optional[int] = 0


class Investigation(BaseModel):
    """Investigation model"""
    id: Optional[int] = None
    alert_id: str
    severity: str
    attack_type: str
    host: str
    timestamp: datetime
    status: str
    ioc: Optional[List[str]] = []
    summary: Optional[str] = ""
    description: Optional[str] = ""
    analyst: Optional[str] = "System"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    duration_minutes: Optional[int] = None


class SearchResult(BaseModel):
    """Search result model"""
    alert_id: str
    severity: str
    attack_type: str
    host: str
    timestamp: datetime
    status: str
    ioc: Optional[List[str]] = []
    summary: Optional[str] = ""


class SearchRequest(BaseModel):
    """Advanced search request"""
    alert_id: Optional[str] = None
    hostname: Optional[str] = None
    attack_type: Optional[str] = None
    ioc: Optional[str] = None
    severity: Optional[str] = None
    limit: Optional[int] = 50


class SearchResponse(BaseModel):
    """Search response"""
    results: List[SearchResult]
    total: int


class ReportData(BaseModel):
    """Report data model"""
    alert_id: str
    severity: str
    attack_type: str
    host: str
    timestamp: str
    status: str
    ioc: Optional[List[str]] = []
    summary: Optional[str] = ""
    analyst: Optional[str] = "System"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    ai_analysis: Optional[str] = None
    threat_intelligence: Optional[Dict[str, Any]] = {}
    mitre_mapping: Optional[Dict[str, Any]] = {}
    recommendations: Optional[List[str]] = []


class InvestigationQuery(BaseModel):
    """Model for investigation query requests"""
    query: str
    user_id: Optional[str] = None


class ChatRequest(BaseModel):
    """Model for chat requests"""
    message: str
    analyst: Optional[str] = None


class UnifiedInvestigation(BaseModel):
    """Model for unified investigation results"""
    severity: str
    ioc: str
    confidence: str
    summary: str
    details: Dict[str, Any]


class InvestigationResponse(BaseModel):
    """Model for investigation responses"""
    required_tools: List[str]
    query_type: Literal[
        'incident_investigation',
        'threat_hunting',
        'vulnerability_assessment',
        'policy_review',
        'other'
    ]
    intent: str
    recommendation: Optional[str] = None
    tool_responses: Optional[List[Dict[str, Any]]] = None
    unified_investigation: Optional[UnifiedInvestigation] = None
    report_json: Optional[Dict[str, Any]] = None
    report_html: Optional[str] = None
    ai_answer: Optional[str] = None  # ✅ NEW: Natural language AI response

    class Config:
        schema_extra = {
            "example": {
                "required_tools": ["Wazuh", "VirusTotal"],
                "query_type": "incident_investigation",
                "intent": "investigate_alert",
                "recommendation": "Check alert details and threat intelligence",
                "tool_responses": [
                    {
                        "tool_name": "Wazuh",
                        "data": {"alerts": [{"id": "101", "severity": "Critical"}]}
                    }
                ],
                "unified_investigation": {
                    "severity": "Critical",
                    "ioc": "185.220.101.45",
                    "confidence": "95%",
                    "summary": "2 alert(s) correlated with IOC 185.220.101.45",
                    "details": {
                        "tools": ["Wazuh", "VirusTotal"],
                        "relationships": [
                            {
                                "ioc": "185.220.101.45",
                                "related_alerts": ["101"],
                                "description": "IOC 185.220.101.45 is related to 1 alert(s)."
                            }
                        ]
                    }
                },
                "report_json": {
                    "alert_id": "101",
                    "timestamp": "2026-07-18 09:41:00 UTC",
                    "severity": "Critical",
                    "attack_type": "Multiple Failed Login Attempts",
                    "affected_host": "Finance-PC",
                    "source_ip": "185.220.101.45",
                    "destination_ip": "192.168.1.10",
                    "mitre_technique": "T1110",
                    "status": "Open",
                    "confidence": "95%",
                    "indicators_of_compromise": ["185.220.101.45"],
                    "threat_intelligence": [
                        "Reputation: Malicious",
                        "Country: Russia",
                        "Detections: 18",
                        "Confidence: 95%"
                    ],
                    "investigation_summary": "2 alert(s) correlated with IOC 185.220.101.45",
                    "recommendations": [
                        "Block Source IP",
                        "Reset User Password",
                        "Enable MFA",
                        "Monitor Endpoint"
                    ]
                },
                "report_html": "<html><body><h1>Investigation Report</h1>...</body></html>",
                "ai_answer": "**Investigation Summary**\n\nThis investigation (Alert ID: 101) identified a **Critical** severity incident involving **Multiple Failed Login Attempts** targeting **Finance-PC**.\n\n**Technical Details:**\n**Source IP:** 185.220.101.45\n**Destination IP:** 192.168.1.10\n**MITRE Technique:** T1110\n**Status:** Open\n**Confidence:** 95%\n\n**Primary Indicator of Compromise:** `185.220.101.45`\n\n**Summary:** 2 alert(s) correlated with IOC 185.220.101.45.\n\n**Threat Intelligence Findings:**\n• Reputation: Malicious\n• Country: Russia\n• Detections: 18\n• Confidence: 95%\n\n**Recommended Actions:**\n• Block Source IP\n• Reset User Password\n• Enable MFA\n• Monitor Endpoint\n\n**Next Steps:**\n• 🚨 IMMEDIATE: Escalate to incident response team\n• 🚨 IMMEDIATE: Isolate affected systems from the network\n• Continue monitoring for additional alerts\n• Document all findings and actions taken"
            }
        }