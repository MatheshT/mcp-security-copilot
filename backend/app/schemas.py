from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    """Severity levels for alerts"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class InvestigationStatus(str, Enum):
    """Status of investigations"""
    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    RESOLVED = "Resolved"
    PENDING = "Pending"
    ESCALATED = "Escalated"
    INFORMATIONAL = "Informational"


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
    message: Optional[str] = None
    query: Optional[str] = None
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
    query_type: str
    intent: str
    recommendation: Optional[str] = None
    tool_responses: Optional[List[Dict[str, Any]]] = None
    unified_investigation: Optional[Dict[str, Any]] = None
    report_json: Optional[Dict[str, Any]] = None
    report_html: Optional[str] = None
    ai_answer: Optional[str] = None