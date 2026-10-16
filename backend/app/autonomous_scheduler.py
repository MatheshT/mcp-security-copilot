"""
Autonomous Security Scheduler
Provides continuous log collection, automated threat hunting, and real-time investigation
"""
import asyncio
import schedule
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from enum import Enum
import logging

from .log_collector.windows_log_collector import WindowsLogCollector
from .log_collector.ioc_extractor import IOCExtractor, IOCPrioritizer
from .threat_intel.orchestrator import ThreatIntelOrchestrator
from .soc_analyst.autonomous_analyst import AutonomousSOCAnalyst
from .correlation_engine import CorrelationEngine
from .database import get_db, SessionLocal
from .log_collector.models import WindowsLog, IOC, Alert, Investigation, InvestigationStatus
from .utils.logger import get_logger

logger = get_logger(__name__)


class ScheduleType(str, Enum):
    """Types of automated schedules"""
    CONTINUOUS = "continuous"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    ON_DEMAND = "on_demand"


class AutonomousScheduler:
    """Autonomous scheduler for security operations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.log_collector = WindowsLogCollector()
        self.ioc_extractor = IOCExtractor()
        self.ioc_prioritizer = IOCPrioritizer()
        self.threat_intel_orchestrator = ThreatIntelOrchestrator(config)
        self.correlation_engine = CorrelationEngine()
        self.soc_analyst = AutonomousSOCAnalyst(config)
        
        self.running = False
        self.scheduler_tasks = []
        self.investigation_queue = []
        
        # Thresholds for automated actions
        self.auto_investigation_threshold = config.get("auto_investigation_threshold", 3)
        self.critical_alert_threshold = config.get("critical_alert_threshold", 2)
        self.ioc_risk_threshold = config.get("ioc_risk_threshold", 0.8)
        
    async def start(self):
        """Start the autonomous scheduler"""
        logger.info("Starting Autonomous Security Scheduler")
        self.running = True
        
        # Schedule continuous log collection
        schedule.every(15).minutes.do(self._collect_logs_continuous)
        
        # Schedule hourly threat hunting
        schedule.every().hour.do(self._automated_threat_hunting)
        
        # Schedule daily comprehensive analysis
        schedule.every().day.at("02:00").do(self._daily_comprehensive_analysis)
        
        # Schedule weekly IOC refresh
        schedule.every().monday.at("03:00").do(self._weekly_ioc_refresh)
        
        # Start the scheduler loop
        await self._run_scheduler()
        
    async def stop(self):
        """Stop the autonomous scheduler"""
        logger.info("Stopping Autonomous Security Scheduler")
        self.running = False
        schedule.clear()
        
    async def _run_scheduler(self):
        """Main scheduler loop"""
        while self.running:
            schedule.run_pending()
            await asyncio.sleep(60)  # Check every minute
            
    def _collect_logs_continuous(self):
        """Continuous log collection task"""
        try:
            logger.info("Starting continuous log collection")
            
            # Collect logs from all sources
            results = asyncio.run(self.log_collector.collect_all_logs(hours_back=1))
            
            # Process and store logs
            total_logs = 0
            total_iocs = 0
            total_alerts = 0
            
            for source, data in results.items():
                if "logs" in data:
                    logs = data["logs"]
                    total_logs += len(logs)
                    
                    # Store logs and extract IOCs
                    with SessionLocal() as db:
                        for log_entry in logs:
                            # Store log
                            db_log = self._store_log(log_entry, db)
                            
                            # Extract IOCs
                            iocs = self.ioc_extractor._extract_from_log(log_entry)
                            total_iocs += self._store_iocs(iocs, db_log.id, db)
                            
                            # Check for alerts
                            if self._check_alert_conditions(log_entry):
                                total_alerts += self._create_alert(log_entry, db)
            
            logger.info(f"Continuous collection completed: {total_logs} logs, {total_iocs} IOCs, {total_alerts} alerts")
            
            # Trigger auto-investigation if threshold met
            if total_alerts >= self.auto_investigation_threshold:
                logger.info(f"Alert threshold met ({total_alerts}), triggering auto-investigation")
                asyncio.run(self._trigger_auto_investigation("continuous_alert_spike"))
                
        except Exception as e:
            logger.error(f"Continuous log collection failed: {e}")
            
    def _automated_threat_hunting(self):
        """Automated threat hunting task"""
        try:
            logger.info("Starting automated threat hunting")
            
            with SessionLocal() as db:
                # Get recent high-risk IOCs
                recent_iocs = db.query(IOC).filter(
                    IOC.risk_level.in_(["critical", "high"]),
                    IOC.created_at >= datetime.now() - timedelta(hours=24)
                ).limit(50).all()
                
                if not recent_iocs:
                    logger.info("No recent high-risk IOCs found for threat hunting")
                    return
                
                # Analyze against threat intelligence
                ioc_data = self._iocs_to_dict(recent_iocs)
                threat_intel_results = asyncio.run(
                    self.threat_intel_orchestrator.analyze_iocs(ioc_data)
                )
                
                # Correlate findings
                correlation_results = self.correlation_engine.correlate_threat_intel(
                    threat_intel_results
                )
                
                # Create hunts for high-confidence findings
                high_confidence = correlation_results.get("high_confidence_findings", [])
                for finding in high_confidence:
                    if finding.get("confidence", 0) > 0.8:
                        self._create_threat_hunt(finding, db)
                
                logger.info(f"Threat hunting completed: {len(high_confidence)} high-confidence findings")
                
        except Exception as e:
            logger.error(f"Automated threat hunting failed: {e}")
            
    def _daily_comprehensive_analysis(self):
        """Daily comprehensive security analysis"""
        try:
            logger.info("Starting daily comprehensive analysis")
            
            # Start comprehensive investigation
            investigation_params = {
                "title": f"Daily Security Analysis - {datetime.now().strftime('%Y-%m-%d')}",
                "description": "Automated daily comprehensive security analysis",
                "investigation_type": "comprehensive",
                "log_sources": ["windows_event", "sysmon", "defender"],
                "time_range_hours": 24,
                "priority_areas": ["all_security_events"],
                "ioc_focus": ["ip_addresses", "domains", "file_hashes", "processes"],
                "auto_start": True
            }
            
            with SessionLocal() as db:
                investigation = Investigation(
                    investigation_id=f"daily_{datetime.now().strftime('%Y%m%d')}",
                    title=investigation_params["title"],
                    description=investigation_params["description"],
                    investigation_type=investigation_params["investigation_type"],
                    status=InvestigationStatus.PLANNING,
                    log_sources=investigation_params["log_sources"],
                    time_range_hours=investigation_params["time_range_hours"],
                    priority_areas=investigation_params["priority_areas"],
                    ioc_focus=investigation_params["ioc_focus"]
                )
                
                db.add(investigation)
                db.commit()
                db.refresh(investigation)
                
                # Run investigation in background
                asyncio.run(self.soc_analyst.conduct_investigation(investigation_params))
                
            logger.info("Daily comprehensive analysis started")
            
        except Exception as e:
            logger.error(f"Daily comprehensive analysis failed: {e}")
            
    def _weekly_ioc_refresh(self):
        """Weekly IOC refresh and re-analysis"""
        try:
            logger.info("Starting weekly IOC refresh")
            
            with SessionLocal() as db:
                # Get all active IOCs
                active_iocs = db.query(IOC).filter(
                    IOC.is_false_positive == False
                ).all()
                
                # Re-analyze against threat intelligence
                ioc_data = self._iocs_to_dict(active_iocs)
                threat_intel_results = asyncio.run(
                    self.threat_intel_orchestrator.analyze_iocs(ioc_data)
                )
                
                # Update IOC risk levels based on new intel
                updated_count = 0
                for ioc in active_iocs:
                    new_risk = self._calculate_updated_risk(ioc, threat_intel_results)
                    if new_risk != ioc.risk_level:
                        ioc.risk_level = new_risk
                        updated_count += 1
                
                db.commit()
                logger.info(f"Weekly IOC refresh completed: {updated_count} IOCs updated")
                
        except Exception as e:
            logger.error(f"Weekly IOC refresh failed: {e}")
            
    async def _trigger_auto_investigation(self, trigger_reason: str):
        """Trigger automatic investigation based on conditions"""
        try:
            investigation_params = {
                "title": f"Auto-Investigation: {trigger_reason}",
                "description": f"Automatically triggered investigation due to: {trigger_reason}",
                "investigation_type": "automated_response",
                "log_sources": ["windows_event", "sysmon", "defender"],
                "time_range_hours": 6,
                "priority_areas": ["recent_alerts", "high_risk_activities"],
                "ioc_focus": ["ip_addresses", "domains", "file_hashes"],
                "auto_start": True
            }
            
            with SessionLocal() as db:
                investigation = Investigation(
                    investigation_id=f"auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    title=investigation_params["title"],
                    description=investigation_params["description"],
                    investigation_type=investigation_params["investigation_type"],
                    status=InvestigationStatus.PLANNING,
                    log_sources=investigation_params["log_sources"],
                    time_range_hours=investigation_params["time_range_hours"],
                    priority_areas=investigation_params["priority_areas"],
                    ioc_focus=investigation_params["ioc_focus"]
                )
                
                db.add(investigation)
                db.commit()
                
                # Run investigation
                result = await self.soc_analyst.conduct_investigation(investigation_params)
                
                # Update investigation with results
                investigation.status = InvestigationStatus.COMPLETED if result.get("status") == "completed" else InvestigationStatus.FAILED
                investigation.risk_score = result.get("final_report", {}).get("risk_assessment", {}).get("overall_risk_score", 0)
                db.commit()
                
            logger.info(f"Auto-investigation completed: {investigation.investigation_id}")
            
        except Exception as e:
            logger.error(f"Auto-investigation failed: {e}")
            
    def _store_log(self, log_entry: Dict[str, Any], db) -> WindowsLog:
        """Store log entry in database"""
        from .log_collector.models import LogSourceType
        
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
        db.flush()
        return db_log
        
    def _store_iocs(self, iocs: Dict[str, List[str]], log_id: int, db) -> int:
        """Store extracted IOCs in database"""
        from .log_collector.models import IOCType, RiskLevel
        
        count = 0
        for ip in iocs.get("ip_addresses", []):
            if ip not in ["127.0.0.1", "0.0.0.0", "255.255.255.255"]:
                db_ioc = IOC(
                    ioc_type=IOCType.IP_ADDRESS,
                    ioc_value=ip,
                    source_log_id=log_id,
                    confidence_score=0.7,
                    risk_level=RiskLevel.MEDIUM
                )
                db.add(db_ioc)
                count += 1
                
        for domain in iocs.get("domains", []):
            db_ioc = IOC(
                ioc_type=IOCType.DOMAIN,
                ioc_value=domain,
                source_log_id=log_id,
                confidence_score=0.7,
                risk_level=RiskLevel.MEDIUM
            )
            db.add(db_ioc)
            count += 1
            
        return count
        
    def _check_alert_conditions(self, log_entry: Dict[str, Any]) -> bool:
        """Check if log entry meets alert conditions"""
        event_id = log_entry.get("event_id")
        critical_events = [4625, 4720, 4732, 4740, 7045]  # Failed login, user creation, privilege escalation, etc.
        return event_id in critical_events
        
    def _create_alert(self, log_entry: Dict[str, Any], db) -> int:
        """Create security alert from log entry"""
        from .log_collector.models import RiskLevel
        
        event_id = log_entry.get("event_id")
        alert_titles = {
            4625: "Failed Logon Attempt",
            4720: "User Account Created",
            4732: "Privileged Group Modification",
            4740: "Account Lockout",
            7045: "New Service Installation"
        }
        
        alert = Alert(
            alert_id=f"alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{event_id}",
            title=alert_titles.get(event_id, "Security Event Detected"),
            description=f"Critical security event {event_id} detected on {log_entry.get('computer_name')}",
            severity=RiskLevel.HIGH,
            alert_type="log_based",
            source="windows_logs",
            status="open",
            detection_rule=f"Event ID {event_id}",
            first_seen=datetime.now(),
            last_seen=datetime.now()
        )
        
        db.add(alert)
        db.commit()
        return 1
        
    def _create_threat_hunt(self, finding: Dict[str, Any], db):
        """Create threat hunt from high-confidence finding"""
        hunt = Investigation(
            investigation_id=f"hunt_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            title=f"Threat Hunt: {finding.get('pattern', 'Unknown Pattern')}",
            description=f"Automated threat hunt based on high-confidence finding: {finding.get('description', '')}",
            investigation_type="threat_hunt",
            status=InvestigationStatus.PLANNING,
            log_sources=["windows_event", "sysmon"],
            time_range_hours=48,
            priority_areas=[finding.get("pattern", "general")],
            ioc_focus=finding.get("ioc_types", ["ip_addresses", "domains"])
        )
        db.add(hunt)
        db.commit()
        
    def _iocs_to_dict(self, iocs: List[IOC]) -> Dict[str, List[str]]:
        """Convert IOC objects to dictionary format"""
        result = {
            "ip_addresses": [],
            "domains": [],
            "file_hashes": [],
            "urls": []
        }
        
        for ioc in iocs:
            if ioc.ioc_type.value == "ip_address":
                result["ip_addresses"].append(ioc.ioc_value)
            elif ioc.ioc_type.value == "domain":
                result["domains"].append(ioc.ioc_value)
            elif ioc.ioc_type.value == "file_hash":
                result["file_hashes"].append(ioc.ioc_value)
                
        return result
        
    def _calculate_updated_risk(self, ioc: IOC, threat_intel_results: Dict[str, Any]) -> str:
        """Calculate updated risk level based on threat intelligence"""
        from .log_collector.models import RiskLevel
        
        # Simple risk calculation - can be enhanced
        base_risk = ioc.risk_level
        
        # Check if IOC was flagged in recent threat intel
        ioc_value = ioc.ioc_value
        for source, results in threat_intel_results.items():
            if isinstance(results, dict) and "analyses" in results:
                if ioc_value in results["analyses"]:
                    analysis = results["analyses"][ioc_value]
                    if analysis.get("risk_level") in ["critical", "high"]:
                        return RiskLevel.CRITICAL
                    elif analysis.get("risk_level") == "medium":
                        return RiskLevel.HIGH
                        
        return base_risk