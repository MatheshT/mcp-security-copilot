"""
API endpoints for log collection and analysis
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel
import os
import uuid
from dotenv import load_dotenv

from ...database import SessionLocal, get_db
from ...log_collector.windows_log_collector import WindowsLogCollector
from ...log_collector.ioc_extractor import IOCExtractor, IOCPrioritizer
from ...threat_intel.orchestrator import ThreatIntelOrchestrator
from ...soc_analyst.autonomous_analyst import AutonomousSOCAnalyst
from ...log_collector.models import (
    WindowsLog, IOC, Investigation, InvestigationStatus, 
    ThreatIntelConfig, LogCollectionConfig, Alert
)
from ...utils.logger import get_logger

load_dotenv()

logger = get_logger(__name__)
router = APIRouter(prefix="/log-analysis", tags=["Log Analysis"])


def generate_investigation_id(now: Optional[datetime] = None) -> str:
    """Create a unique investigation ID that remains readable and avoids same-second collisions."""
    current_time = now or datetime.utcnow()
    return f"inv_{current_time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"


# Pydantic models for requests/responses
class LogCollectionRequest(BaseModel):
    log_sources: List[str] = ["windows_event", "sysmon", "defender"]
    hours_back: int = 24
    save_to_db: bool = True


class IOCExtractionRequest(BaseModel):
    log_ids: Optional[List[int]] = None
    hours_back: int = 24
    prioritize: bool = True


class ThreatIntelRequest(BaseModel):
    ioc_ids: Optional[List[int]] = None
    iocs: Optional[Dict[str, List[str]]] = None
    sources: List[str] = ["virustotal", "mitre_attack", "sigma", "abuseipdb"]


class InvestigationRequest(BaseModel):
    title: str
    description: Optional[str] = ""
    investigation_type: str = "general"
    log_sources: List[str] = ["windows_event", "sysmon", "defender"]
    time_range_hours: int = 24
    priority_areas: Optional[List[str]] = None
    ioc_focus: Optional[List[str]] = None
    auto_start: bool = True


class RiskAssessmentRequest(BaseModel):
    investigation_id: int


# Endpoints
@router.post("/collect-logs")
async def collect_logs(
    request: LogCollectionRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Collect logs from Windows Event Logs, Sysmon, and Defender"""
    try:
        logger.info(f"Starting log collection from {request.log_sources}")
        
        collector = WindowsLogCollector()
        results = {}
        
        for source in request.log_sources:
            try:
                log_data = await collector.collect_specific_source(source, request.hours_back)
                results[source] = log_data
                
                # Save to database if requested
                if request.save_to_db:
                    background_tasks.add_task(save_logs_to_db, log_data, db)
                    
            except Exception as e:
                logger.error(f"Error collecting from {source}: {e}")
                results[source] = {"error": str(e)}
        
        return {
            "status": "success",
            "message": "Log collection completed",
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Log collection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/extract-iocs")
async def extract_iocs(request: IOCExtractionRequest, db: Session = Depends(get_db)):
    """Extract IOCs from collected logs"""
    try:
        logger.info("Starting IOC extraction")
        
        extractor = IOCExtractor()
        
        # Get logs from database or collect recent logs
        if request.log_ids:
            logs = db.query(WindowsLog).filter(WindowsLog.id.in_(request.log_ids)).all()
            log_data = [log_to_dict(log) for log in logs]
        else:
            # Collect recent logs
            collector = WindowsLogCollector()
            all_results = await collector.collect_all_logs(request.hours_back)
            log_data = []
            for source, data in all_results.items():
                if "logs" in data:
                    log_data.extend(data["logs"])
        
        # Extract IOCs
        iocs = extractor.extract_iocs(log_data)
        
        # Prioritize IOCs if requested
        if request.prioritize:
            prioritizer = IOCPrioritizer()
            prioritized_iocs = prioritizer.prioritize_iocs(iocs)
            iocs["prioritized"] = prioritized_iocs
        
        return {
            "status": "success",
            "message": "IOC extraction completed",
            "iocs": iocs,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"IOC extraction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/threat-intel")
async def analyze_threat_intel(request: ThreatIntelRequest, db: Session = Depends(get_db)):
    """Analyze IOCs against threat intelligence sources"""
    try:
        logger.info(f"Starting threat intelligence analysis with sources: {request.sources}")
        
        # Get IOCs from request or database
        if request.ioc_ids:
            iocs = db.query(IOC).filter(IOC.id.in_(request.ioc_ids)).all()
            ioc_data = iocs_to_dict(iocs)
        elif request.iocs:
            ioc_data = request.iocs
        else:
            raise HTTPException(status_code=400, detail="No IOCs provided")
        
        # Configure threat intelligence orchestrator
        config = {
            "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY"),
            "abuseipdb_api_key": os.getenv("ABUSEIPDB_API_KEY")
        }
        
        orchestrator = ThreatIntelOrchestrator(config)
        results = await orchestrator.analyze_iocs(ioc_data)
        await orchestrator.close()
        
        return {
            "status": "success",
            "message": "Threat intelligence analysis completed",
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Threat intelligence analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigation/start")
async def start_investigation(
    request: InvestigationRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Start an autonomous SOC investigation"""
    try:
        logger.info(f"Starting investigation: {request.title}")

        for attempt in range(3):
            try:
                investigation = Investigation(
                    investigation_id=generate_investigation_id(),
                    title=request.title,
                    description=request.description,
                    investigation_type=request.investigation_type,
                    status=InvestigationStatus.PLANNING,
                    log_sources=request.log_sources,
                    time_range_hours=request.time_range_hours,
                    priority_areas=request.priority_areas,
                    ioc_focus=request.ioc_focus
                )

                db.add(investigation)
                db.commit()
                db.refresh(investigation)
                break
            except IntegrityError:
                db.rollback()
                if attempt == 2:
                    raise

        if request.auto_start:
            background_tasks.add_task(run_investigation, investigation.id, request.dict())

        return {
            "status": "success",
            "message": "Investigation created",
            "investigation_id": investigation.investigation_id,
            "id": investigation.id,
            "auto_started": request.auto_start
        }

    except Exception as e:
        logger.error(f"Investigation creation failed: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/investigation/{investigation_id}")
async def get_investigation(investigation_id: int, db: Session = Depends(get_db)):
    """Get investigation details"""
    try:
        investigation = db.query(Investigation).filter(
            Investigation.id == investigation_id
        ).first()
        
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")
        
        return {
            "status": "success",
            "investigation": investigation_to_dict(investigation)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting investigation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/investigation")
async def list_investigations(
    skip: int = 0,
    limit: int = 50,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List investigations"""
    try:
        query = db.query(Investigation)
        
        if status:
            query = query.filter(Investigation.status == status)
        
        investigations = query.order_by(Investigation.created_at.desc()).offset(skip).limit(limit).all()
        
        return {
            "status": "success",
            "investigations": [investigation_to_dict(inv) for inv in investigations],
            "total": len(investigations)
        }
        
    except Exception as e:
        logger.error(f"Error listing investigations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/iocs")
async def list_iocs(
    skip: int = 0,
    limit: int = 50,
    ioc_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List IOCs with filtering"""
    try:
        query = db.query(IOC)
        
        if ioc_type:
            query = query.filter(IOC.ioc_type == ioc_type)
        
        if risk_level:
            query = query.filter(IOC.risk_level == risk_level)
        
        iocs = query.order_by(IOC.last_seen.desc()).offset(skip).limit(limit).all()
        
        return {
            "status": "success",
            "iocs": [ioc_to_dict(ioc) for ioc in iocs],
            "total": len(iocs)
        }
        
    except Exception as e:
        logger.error(f"Error listing IOCs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts")
async def list_alerts(
    skip: int = 0,
    limit: int = 50,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List security alerts"""
    try:
        query = db.query(Alert)
        
        if severity:
            query = query.filter(Alert.severity == severity)
        
        if status:
            query = query.filter(Alert.status == status)
        
        alerts = query.order_by(Alert.first_seen.desc()).offset(skip).limit(limit).all()
        
        return {
            "status": "success",
            "alerts": [alert_to_dict(alert) for alert in alerts],
            "total": len(alerts)
        }
        
    except Exception as e:
        logger.error(f"Error listing alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/stats")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics"""
    try:
        stats = {
            "total_investigations": db.query(Investigation).count(),
            "active_investigations": db.query(Investigation).filter(
                Investigation.status.in_([
                    InvestigationStatus.PLANNING,
                    InvestigationStatus.EVIDENCE_COLLECTION,
                    InvestigationStatus.IOC_EXTRACTION,
                    InvestigationStatus.THREAT_INTEL,
                    InvestigationStatus.CORRELATION,
                    InvestigationStatus.RISK_ASSESSMENT
                ])
            ).count(),
            "total_iocs": db.query(IOC).count(),
            "high_risk_iocs": db.query(IOC).filter(IOC.risk_level.in_(["critical", "high"])).count(),
            "total_alerts": db.query(Alert).count(),
            "open_alerts": db.query(Alert).filter(Alert.status == "open").count(),
            "critical_alerts": db.query(Alert).filter(
                Alert.severity == "critical",
                Alert.status == "open"
            ).count(),
            "logs_collected_24h": db.query(WindowsLog).filter(
                WindowsLog.created_at >= datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            ).count()
        }
        
        return {
            "status": "success",
            "stats": stats,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Helper functions
def save_logs_to_db(log_data: Dict[str, Any], db: Session):
    """Save logs to database in background, extract IOCs, and generate alerts"""
    try:
        from ...log_collector.models import LogSourceType, IOCType, RiskLevel
        from ...log_collector.ioc_extractor import IOCExtractor
        extractor = IOCExtractor()
        
        logs = log_data.get("logs", [])
        logger.info(f"Processing {len(logs)} logs for database storage, IOC extraction, and alert generation...")
        
        saved_count = 0
        ioc_count = 0
        alert_count = 0
        
        for log_entry in logs:
            # 1. Create and save log
            db_log = WindowsLog(
                log_source=log_entry.get("log_source"),
                log_name=log_entry.get("log_name"),
                event_id=log_entry.get("event_id"),
                timestamp=datetime.fromisoformat(log_entry.get("timestamp", "")) if log_entry.get("timestamp") else None,
                computer_name=log_entry.get("computer_name"),
                source=log_entry.get("source"),
                category=log_entry.get("category"),
                event_type=log_entry.get("type"),
                record_number=log_entry.get("record_number"),
                user=log_entry.get("user"),
                data=log_entry.get("data"),
                xml_representation=log_entry.get("xml_representation")
            )
            db.add(db_log)
            db.flush()  # Populate db_log.id
            saved_count += 1
            
            # 2. Extract IOCs from this log entry
            log_iocs = extractor._extract_from_log(log_entry)
            
            # Save extracted IOCs
            extracted_iocs_for_log = []
            
            # Handle IP addresses
            for ip in log_iocs.get("ip_addresses", []):
                if ip not in ["127.0.0.1", "0.0.0.0", "255.255.255.255"]:
                    db_ioc = IOC(
                        ioc_type=IOCType.IP_ADDRESS,
                        ioc_value=ip,
                        source_log_id=db_log.id,
                        confidence_score=0.7,
                        risk_level=RiskLevel.MEDIUM,
                        notes=f"Extracted from Event ID {db_log.event_id} on {db_log.computer_name}"
                    )
                    db.add(db_ioc)
                    extracted_iocs_for_log.append(ip)
                    ioc_count += 1
            
            # Handle Domains
            for domain in log_iocs.get("domains", []):
                db_ioc = IOC(
                    ioc_type=IOCType.DOMAIN,
                    ioc_value=domain,
                    source_log_id=db_log.id,
                    confidence_score=0.7,
                    risk_level=RiskLevel.MEDIUM,
                    notes=f"Extracted from Event ID {db_log.event_id} on {db_log.computer_name}"
                )
                db.add(db_ioc)
                extracted_iocs_for_log.append(domain)
                ioc_count += 1
                
            # Handle File Paths
            for path in log_iocs.get("file_paths", []):
                db_ioc = IOC(
                    ioc_type=IOCType.FILE_PATH,
                    ioc_value=path,
                    source_log_id=db_log.id,
                    confidence_score=0.8,
                    risk_level=RiskLevel.LOW,
                    notes=f"Extracted from Event ID {db_log.event_id} on {db_log.computer_name}"
                )
                db.add(db_ioc)
                extracted_iocs_for_log.append(path)
                ioc_count += 1

            # Handle File Hashes
            for hash_type, hashes in log_iocs.get("file_hashes", {}).items():
                for h in hashes:
                    db_ioc = IOC(
                        ioc_type=IOCType.FILE_HASH,
                        ioc_value=h,
                        ioc_subtype=hash_type,
                        source_log_id=db_log.id,
                        confidence_score=0.9,
                        risk_level=RiskLevel.MEDIUM,
                        notes=f"Extracted from Event ID {db_log.event_id} on {db_log.computer_name}"
                    )
                    db.add(db_ioc)
                    extracted_iocs_for_log.append(h)
                    ioc_count += 1

            # 3. Check for alerting rules
            is_alert = False
            alert_title = ""
            alert_desc = ""
            alert_severity = RiskLevel.MEDIUM
            alert_rule = "Generic Log Alert"
            
            ev_id = db_log.event_id
            log_src = db_log.log_source
            
            if log_src == LogSourceType.WINDOWS_EVENT or log_src == "windows_event":
                if ev_id == 4625:
                    is_alert = True
                    alert_title = "Failed Logon Attempt"
                    alert_desc = f"Failed logon attempt detected on host '{db_log.computer_name}' for user '{db_log.user or 'Unknown'}'. Source network address: {log_entry.get('data', {}).get('strings', ['N/A'])[0] if log_entry.get('data', {}).get('strings') else 'N/A'}."
                    alert_severity = RiskLevel.HIGH
                    alert_rule = "Windows Security: Account Logon Failed"
                elif ev_id == 4720:
                    is_alert = True
                    alert_title = "User Account Created"
                    alert_desc = f"A new local user account was created on host '{db_log.computer_name}' by user '{db_log.user or 'System'}'. Target account: {log_entry.get('data', {}).get('strings', ['N/A'])[0] if log_entry.get('data', {}).get('strings') else 'N/A'}."
                    alert_severity = RiskLevel.HIGH
                    alert_rule = "Windows Security: Local User Account Created"
                elif ev_id == 4732:
                    is_alert = True
                    alert_title = "User Added to Security-Enabled Local Group"
                    alert_desc = f"A user was added to a privileged security group (e.g. Administrators) on host '{db_log.computer_name}'."
                    alert_severity = RiskLevel.CRITICAL
                    alert_rule = "Windows Security: Privileged Group Modification"
                elif ev_id == 4740:
                    is_alert = True
                    alert_title = "User Account Locked Out"
                    alert_desc = f"A user account '{db_log.user or 'Unknown'}' was locked out on host '{db_log.computer_name}' due to multiple authentication failures."
                    alert_severity = RiskLevel.HIGH
                    alert_rule = "Windows Security: Account Lockout"
                elif ev_id == 7045:
                    is_alert = True
                    alert_title = "New System Service Installed"
                    service_name = log_entry.get('data', {}).get('strings', ['N/A'])[0] if log_entry.get('data', {}).get('strings') else 'N/A'
                    alert_desc = f"A new service '{service_name}' was registered on host '{db_log.computer_name}'. This can indicate persistence installation."
                    alert_severity = RiskLevel.HIGH
                    alert_rule = "Windows System: New Service Installation"
            
            elif log_src == LogSourceType.DEFENDER or log_src == "defender":
                is_alert = True
                alert_title = f"Windows Defender: {log_entry.get('threat_name', 'Threat Detected')}"
                alert_desc = f"Windows Defender Antivirus detected a threat: '{log_entry.get('threat_name')}' ({log_entry.get('threat_type')}) on host '{db_log.computer_name}'. File path: {log_entry.get('file_path') or 'N/A'}. Action taken: {log_entry.get('action_taken') or 'Quarantine'}."
                alert_severity = RiskLevel.CRITICAL if log_entry.get('severity') == "Critical" else RiskLevel.HIGH
                alert_rule = "Windows Defender: Antivirus Threat Detection"
                
            elif log_src == LogSourceType.SYSMON or log_src == "sysmon":
                if ev_id == 1:
                    cmd_line = ""
                    if log_entry.get("data") and log_entry.get("data").get("strings"):
                        cmd_line = str(log_entry.get("data").get("strings"))
                    suspicious_keywords = ["powershell -ep bypass", "bypass -c", "certutil -urlcache", "whoami", "mimikatz", "vssadmin delete shadows", "schtasks /create"]
                    if any(kw in cmd_line.lower() for kw in suspicious_keywords):
                        is_alert = True
                        alert_title = f"Sysmon: Suspicious Process Created"
                        alert_desc = f"A highly suspicious process execution was detected on host '{db_log.computer_name}': {cmd_line[:300]}"
                        alert_severity = RiskLevel.HIGH
                        alert_rule = "Sysmon: Suspicious Command Line Execution"
                elif ev_id in [8, 10]:
                    is_alert = True
                    alert_title = f"Sysmon: Unauthorized Process Access"
                    alert_desc = f"Sysmon detected potential process injection / memory access (Event ID {ev_id}) on host '{db_log.computer_name}'."
                    alert_severity = RiskLevel.HIGH
                    alert_rule = "Sysmon: Process Injection or Tampering"

            if is_alert:
                import random
                alert_id_str = f"ALERT-REAL-{random.randint(1000, 9999)}"
                db_alert = Alert(
                    alert_id=alert_id_str,
                    title=alert_title,
                    description=alert_desc,
                    severity=alert_severity,
                    alert_type=alert_title,
                    source=str(db_log.log_source.value),
                    status="open",
                    detection_rule=alert_rule,
                    iocs_involved=extracted_iocs_for_log,
                    affected_hosts=[db_log.computer_name],
                    affected_users=[db_log.user] if db_log.user else []
                )
                db.add(db_alert)
                alert_count += 1
        
        db.commit()
        logger.info(f"Successfully processed logs: Saved {saved_count} logs, extracted {ioc_count} IOCs, and generated {alert_count} alerts in DB.")
        
    except Exception as e:
        logger.error(f"Error processing logs in database: {e}")
        db.rollback()


async def run_investigation(investigation_id: int, params: Dict[str, Any]):
    """Run investigation in background"""
    db = SessionLocal()
    investigation = None
    try:
        investigation = db.query(Investigation).filter(Investigation.id == investigation_id).first()
        if not investigation:
            logger.error(f"Investigation {investigation_id} not found")
            return
        
        # Configure autonomous analyst
        config = {
            "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY"),
            "abuseipdb_api_key": os.getenv("ABUSEIPDB_API_KEY"),
            "llm_provider": os.getenv("LLM_PROVIDER", "free"),
            "ollama_url": os.getenv("OLLAMA_URL"),
            "openai_api_key": os.getenv("OPENAI_API_KEY"),
            "openai_model": os.getenv("OPENAI_MODEL")
        }
        
        analyst = AutonomousSOCAnalyst(config)
        
        # Run investigation
        result = await analyst.conduct_investigation(params)
        
        # Update investigation with results
        investigation.status = InvestigationStatus.COMPLETED if result.get("status") == "completed" else InvestigationStatus.FAILED
        investigation.risk_score = result.get("phases", [{}])[-1].get("risk_assessment", {}).get("overall_risk_score", 0)
        investigation.end_time = datetime.now()
        
        if result.get("final_report"):
            investigation.executive_summary = result["final_report"].get("executive_summary")
            investigation.recommendations = result["final_report"].get("recommendations")
        
        db.commit()
        
        await analyst.close()
        
        logger.info(f"Investigation {investigation_id} completed")
        
    except Exception as e:
        logger.error(f"Investigation {investigation_id} failed: {e}")
        if investigation:
            investigation.status = InvestigationStatus.FAILED
            db.commit()
    finally:
        db.close()


def log_to_dict(log: WindowsLog) -> Dict[str, Any]:
    """Convert log object to dictionary"""
    return {
        "id": log.id,
        "log_source": log.log_source,
        "log_name": log.log_name,
        "event_id": log.event_id,
        "timestamp": log.timestamp.isoformat() if log.timestamp else None,
        "computer_name": log.computer_name,
        "source": log.source,
        "category": log.category,
        "event_type": log.event_type,
        "record_number": log.record_number,
        "user": log.user,
        "data": log.data,
        "xml_representation": log.xml_representation
    }


def iocs_to_dict(iocs: List[IOC]) -> Dict[str, List[str]]:
    """Convert IOC objects to dictionary format"""
    result = {
        "ip_addresses": [],
        "domains": [],
        "urls": [],
        "email_addresses": [],
        "file_hashes": {},
        "registry_keys": [],
        "file_paths": [],
        "processes": [],
        "users": []
    }
    
    for ioc in iocs:
        ioc_type = ioc.ioc_type
        value = ioc.ioc_value
        
        if ioc_type == "ip_address":
            result["ip_addresses"].append(value)
        elif ioc_type == "domain":
            result["domains"].append(value)
        elif ioc_type == "url":
            result["urls"].append(value)
        elif ioc_type == "email":
            result["email_addresses"].append(value)
        elif ioc_type == "file_hash":
            if ioc.ioc_subtype not in result["file_hashes"]:
                result["file_hashes"][ioc.ioc_subtype] = []
            result["file_hashes"][ioc.ioc_subtype].append(value)
        elif ioc_type == "registry_key":
            result["registry_keys"].append(value)
        elif ioc_type == "file_path":
            result["file_paths"].append(value)
        elif ioc_type == "process":
            result["processes"].append(value)
        elif ioc_type == "user":
            result["users"].append(value)
    
    return result


def ioc_to_dict(ioc: IOC) -> Dict[str, Any]:
    """Convert IOC object to dictionary"""
    return {
        "id": ioc.id,
        "ioc_type": ioc.ioc_type,
        "ioc_value": ioc.ioc_value,
        "ioc_subtype": ioc.ioc_subtype,
        "confidence_score": ioc.confidence_score,
        "risk_level": ioc.risk_level,
        "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
        "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
        "is_false_positive": ioc.is_false_positive,
        "notes": ioc.notes,
        "metadata": ioc.metadata
    }


def investigation_to_dict(investigation: Investigation) -> Dict[str, Any]:
    """Convert investigation object to dictionary"""
    return {
        "id": investigation.id,
        "investigation_id": investigation.investigation_id,
        "title": investigation.title,
        "description": investigation.description,
        "status": investigation.status,
        "investigation_type": investigation.investigation_type,
        "priority": investigation.priority,
        "risk_score": investigation.risk_score,
        "risk_level": investigation.risk_level,
        "log_sources": investigation.log_sources,
        "time_range_hours": investigation.time_range_hours,
        "priority_areas": investigation.priority_areas,
        "ioc_focus": investigation.ioc_focus,
        "executive_summary": investigation.executive_summary,
        "recommendations": investigation.recommendations,
        "created_by": investigation.created_by,
        "assigned_to": investigation.assigned_to,
        "start_time": investigation.start_time.isoformat() if investigation.start_time else None,
        "end_time": investigation.end_time.isoformat() if investigation.end_time else None,
        "created_at": investigation.created_at.isoformat() if investigation.created_at else None,
        "updated_at": investigation.updated_at.isoformat() if investigation.updated_at else None
    }


def alert_to_dict(alert: Alert) -> Dict[str, Any]:
    """Convert alert object to dictionary"""
    return {
        "id": alert.id,
        "alert_id": alert.alert_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "alert_type": alert.alert_type,
        "source": alert.source,
        "status": alert.status,
        "iocs_involved": alert.iocs_involved,
        "affected_hosts": alert.affected_hosts,
        "affected_users": alert.affected_users,
        "first_seen": alert.first_seen.isoformat() if alert.first_seen else None,
        "last_seen": alert.last_seen.isoformat() if alert.last_seen else None,
        "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
        "false_positive": alert.false_positive,
        "notes": alert.notes
    }