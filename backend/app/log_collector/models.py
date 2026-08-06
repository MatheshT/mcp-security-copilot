"""
Database models for log collection and IOC storage
"""
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Float, ForeignKey, Boolean, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
from ..database import Base
import enum


class LogSourceType(str, enum.Enum):
    """Log source types"""
    WINDOWS_EVENT = "windows_event"
    SYSMON = "sysmon"
    DEFENDER = "defender"
    CUSTOM = "custom"


class IOCType(str, enum.Enum):
    """IOC types"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_HASH = "file_hash"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"
    PROCESS = "process"
    USER = "user"


class RiskLevel(str, enum.Enum):
    """Risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class InvestigationStatus(str, enum.Enum):
    """Investigation status"""
    PLANNING = "planning"
    EVIDENCE_COLLECTION = "evidence_collection"
    IOC_EXTRACTION = "ioc_extraction"
    THREAT_INTEL = "threat_intel_analysis"
    CORRELATION = "correlation_analysis"
    RISK_ASSESSMENT = "risk_assessment"
    REPORTING = "reporting"
    ACTION_RECOMMENDATION = "action_recommendation"
    COMPLETED = "completed"
    FAILED = "failed"


class WindowsLog(Base):
    """Windows Event Log storage"""
    __tablename__ = "windows_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    log_source = Column(SQLEnum(LogSourceType), default=LogSourceType.WINDOWS_EVENT)
    log_name = Column(String(255), index=True)
    event_id = Column(Integer, index=True)
    timestamp = Column(DateTime, index=True)
    computer_name = Column(String(255))
    source = Column(String(255))
    category = Column(String(255))
    event_type = Column(String(50), index=True)
    record_number = Column(Integer)
    user = Column(String(255))
    data = Column(JSON)
    xml_representation = Column(Text)
    processed = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    iocs = relationship("IOC", back_populates="source_log", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<WindowsLog(id={self.id}, log_name={self.log_name}, event_id={self.event_id})>"


class IOC(Base):
    """Indicators of Compromise storage"""
    __tablename__ = "iocs"
    
    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(SQLEnum(IOCType), index=True)
    ioc_value = Column(Text, index=True)
    ioc_subtype = Column(String(50))  # e.g., MD5, SHA256 for hashes
    source_log_id = Column(Integer, ForeignKey("windows_logs.id"), nullable=True)
    confidence_score = Column(Float, default=0.0)
    risk_level = Column(SQLEnum(RiskLevel), default=RiskLevel.LOW, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow, index=True)
    last_seen = Column(DateTime, default=datetime.utcnow, index=True)
    is_false_positive = Column(Boolean, default=False)
    notes = Column(Text)
    ioc_metadata = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    source_log = relationship("WindowsLog", back_populates="iocs")
    threat_intel_analyses = relationship("ThreatIntelAnalysis", back_populates="ioc", cascade="all, delete-orphan")
    investigation_iocs = relationship("InvestigationIOC", back_populates="ioc", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<IOC(id={self.id}, type={self.ioc_type}, value={self.ioc_value})>"


class ThreatIntelSource(str, enum.Enum):
    """Threat intelligence sources"""
    VIRUSTOTAL = "virustotal"
    MITRE_ATTACK = "mitre_attack"
    SIGMA = "sigma"
    ABUSEIPDB = "abuseipdb"
    CUSTOM = "custom"


class ThreatIntelAnalysis(Base):
    """Threat intelligence analysis results"""
    __tablename__ = "threat_intel_analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id"), nullable=True)
    source = Column(SQLEnum(ThreatIntelSource), index=True)
    analysis_result = Column(JSON)
    risk_level = Column(SQLEnum(RiskLevel), default=RiskLevel.LOW, index=True)
    confidence_score = Column(Float, default=0.0)
    detection_ratio = Column(String(50))  # e.g., "5/70"
    positive_detections = Column(Integer, default=0)
    total_engines = Column(Integer, default=0)
    reputation_score = Column(Integer, default=0)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    categories = Column(JSON)
    tags = Column(JSON)
    raw_response = Column(Text)
    analysis_timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    ioc = relationship("IOC", back_populates="threat_intel_analyses")
    
    def __repr__(self):
        return f"<ThreatIntelAnalysis(id={self.id}, source={self.source}, ioc_id={self.ioc_id})>"


class Investigation(Base):
    """Security investigation records"""
    __tablename__ = "investigations"
    
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(String(100), unique=True, index=True)
    title = Column(String(255))
    description = Column(Text)
    status = Column(SQLEnum(InvestigationStatus), default=InvestigationStatus.PLANNING, index=True)
    investigation_type = Column(String(50), index=True)
    priority = Column(String(20), default="medium")
    risk_score = Column(Float, default=0.0, index=True)
    risk_level = Column(SQLEnum(RiskLevel), default=RiskLevel.LOW, index=True)
    
    # Investigation parameters
    log_sources = Column(JSON)
    time_range_hours = Column(Integer)
    priority_areas = Column(JSON)
    ioc_focus = Column(JSON)
    hypotheses = Column(JSON)
    
    # Investigation results
    phases_completed = Column(JSON)
    key_findings = Column(JSON)
    evidence_summary = Column(JSON)
    threat_intel_summary = Column(JSON)
    correlation_summary = Column(JSON)
    
    # Report data
    executive_summary = Column(Text)
    attack_narrative = Column(Text)
    impact_assessment = Column(Text)
    recommendations = Column(JSON)
    
    # Additional data
    created_by = Column(String(255))
    assigned_to = Column(String(255))
    start_time = Column(DateTime, default=datetime.utcnow, index=True)
    end_time = Column(DateTime, index=True)
    llm_guidance = Column(JSON)
    llm_report_enhancement = Column(JSON)
    investigation_metadata = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    iocs = relationship("InvestigationIOC", back_populates="investigation", cascade="all, delete-orphan")
    phases = relationship("InvestigationPhase", back_populates="investigation", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Investigation(id={self.id}, investigation_id={self.investigation_id}, status={self.status})>"


class InvestigationIOC(Base):
    """IOCs associated with investigations"""
    __tablename__ = "investigation_iocs"
    
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"), nullable=False)
    ioc_id = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    priority_level = Column(SQLEnum(RiskLevel), default=RiskLevel.MEDIUM)
    was_investigated = Column(Boolean, default=False)
    investigation_notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    investigation = relationship("Investigation", back_populates="iocs")
    ioc = relationship("IOC", back_populates="investigation_iocs")
    
    def __repr__(self):
        return f"<InvestigationIOC(id={self.id}, investigation_id={self.investigation_id}, ioc_id={self.ioc_id})>"


class InvestigationPhase(Base):
    """Investigation phase tracking"""
    __tablename__ = "investigation_phases"
    
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"), nullable=False)
    phase_name = Column(String(100), index=True)
    phase_status = Column(String(50), default="pending")
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    duration_seconds = Column(Integer)
    phase_result = Column(JSON)
    phase_summary = Column(Text)
    errors = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    investigation = relationship("Investigation", back_populates="phases")
    
    def __repr__(self):
        return f"<InvestigationPhase(id={self.id}, phase={self.phase_name}, status={self.phase_status})>"


class ThreatIntelConfig(Base):
    """Threat intelligence configuration"""
    __tablename__ = "threat_intel_config"
    
    id = Column(Integer, primary_key=True, index=True)
    source = Column(SQLEnum(ThreatIntelSource), unique=True, index=True)
    api_key = Column(String(255))
    api_endpoint = Column(String(255))
    is_enabled = Column(Boolean, default=True, index=True)
    rate_limit_per_minute = Column(Integer, default=30)
    last_successful_call = Column(DateTime)
    last_failed_call = Column(DateTime)
    failure_count = Column(Integer, default=0)
    configuration = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<ThreatIntelConfig(id={self.id}, source={self.source}, enabled={self.is_enabled})>"


class LogCollectionConfig(Base):
    """Log collection configuration"""
    __tablename__ = "log_collection_config"
    
    id = Column(Integer, primary_key=True, index=True)
    log_source = Column(SQLEnum(LogSourceType), unique=True, index=True)
    is_enabled = Column(Boolean, default=True, index=True)
    collection_interval_minutes = Column(Integer, default=60)
    log_paths = Column(JSON)
    event_filters = Column(JSON)
    retention_days = Column(Integer, default=30)
    max_log_size_mb = Column(Integer, default=1000)
    last_collection_time = Column(DateTime)
    last_successful_collection = Column(DateTime)
    collection_errors = Column(JSON)
    configuration = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<LogCollectionConfig(id={self.id}, source={self.log_source}, enabled={self.is_enabled})>"


class Alert(Base):
    """Security alerts generated from log analysis"""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(100), unique=True, index=True)
    title = Column(String(255))
    description = Column(Text)
    severity = Column(SQLEnum(RiskLevel), default=RiskLevel.MEDIUM, index=True)
    alert_type = Column(String(100), index=True)
    source = Column(String(100))
    status = Column(String(50), default="open", index=True)
    
    # Alert details
    detection_rule = Column(String(255))
    iocs_involved = Column(JSON)
    affected_hosts = Column(JSON)
    affected_users = Column(JSON)
    
    # Investigation link
    investigation_id = Column(Integer, ForeignKey("investigations.id"), nullable=True)
    
    # Timestamps
    first_seen = Column(DateTime, default=datetime.utcnow, index=True)
    last_seen = Column(DateTime, default=datetime.utcnow, index=True)
    resolved_at = Column(DateTime)
    
    # Analysis
    false_positive = Column(Boolean, default=False)
    false_positive_reason = Column(Text)
    notes = Column(Text)
    alert_metadata = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    investigation = relationship("Investigation")
    
    def __repr__(self):
        return f"<Alert(id={self.id}, alert_id={self.alert_id}, severity={self.severity})>"