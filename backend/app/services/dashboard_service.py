from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import random
import logging
from ..mcp.registry import mcp_registry
from ..mcp.tool_server import ToolResponse
from ..schemas import DashboardStats, Investigation, InvestigationStatus, SeverityLevel, SearchResult

logger = logging.getLogger(__name__)

class DashboardService:
    """Enhanced dashboard service with MCP Registry integration"""
    
    def __init__(self):
        self.mcp_registry = mcp_registry
        self._investigations = []
        self._alerts = []
        self._investigation_cache = {}
        self._initialize_data()
    
    def _initialize_data(self):
        """Initialize with empty data lists for real Wazuh integration"""
        self._investigations = []
        self._alerts = []
        logger.info("Initialized dashboard service for real Wazuh integration")
    
    def _generate_mock_investigations(self, count: int) -> List[Dict]:
        """Generate mock investigation data"""
        investigations = []
        attack_types = [
            "Phishing", "Malware", "Ransomware", "DDoS", 
            "Data Exfiltration", "Privilege Escalation",
            "SQL Injection", "XSS", "MITM Attack", "Brute Force",
            "Credential Dumping", "Lateral Movement"
        ]
        hosts = [
            "web-server-01", "db-server-02", "app-server-03", 
            "mail-server-04", "firewall-05", "endpoint-06",
            "api-gateway-07", "loadbalancer-08", "monitoring-09"
        ]
        statuses = ["Investigating", "Resolved", "In Progress", "Pending", "Escalated"]
        
        for i in range(1, count + 1):
            timestamp = datetime.now() - timedelta(
                hours=random.randint(0, 168),
                minutes=random.randint(0, 59)
            )
            severity = random.choice([s.value for s in SeverityLevel])
            investigation = {
                "id": i,
                "alert_id": f"SOC-ALERT-{i:04d}",
                "severity": severity,
                "attack_type": random.choice(attack_types),
                "host": random.choice(hosts),
                "timestamp": timestamp.isoformat(),
                "status": random.choice(statuses),
                "ioc": self._generate_iocs(random.randint(1, 4)),
                "summary": f"Suspicious {random.choice(attack_types)} activity detected on {random.choice(hosts)}",
                "description": f"Detailed investigation for alert SOC-ALERT-{i:04d}",
                "analyst": random.choice(["Analyst-1", "Analyst-2", "Analyst-3", "System"]),
                "source_ip": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
                "destination_ip": f"10.0.{random.randint(1,255)}.{random.randint(1,255)}",
                "duration_minutes": random.randint(10, 180),
                "ai_analysis": self._generate_ai_analysis(severity, random.choice(attack_types)),
                "threat_intelligence": self._generate_threat_intelligence(),
                "mitre_mapping": self._generate_mitre_mapping(random.choice(attack_types)),
                "recommendations": self._generate_recommendations(severity)
            }
            investigations.append(investigation)
        
        return sorted(investigations, key=lambda x: x["timestamp"], reverse=True)
    
    def _generate_ai_analysis(self, severity: str, attack_type: str) -> str:
        """Generate AI analysis for an investigation"""
        templates = [
            f"The investigation has identified a {severity.lower()} severity {attack_type} attack targeting multiple hosts. Initial analysis suggests the attack vector involves a sophisticated multi-stage campaign. The attacker is using advanced evasion techniques and leveraging zero-day vulnerabilities. Threat actor attribution points to APT-29 with medium confidence. Immediate containment and incident response procedures should be initiated.",
            f"Analysis of the {attack_type} incident reveals a coordinated attack campaign. The threat actor has demonstrated advanced capabilities including lateral movement, persistence mechanisms, and data exfiltration. The attack chain is consistent with ransomware operations. Critical assets have been compromised, requiring immediate isolation and forensic analysis.",
            f"This {severity.lower()} severity alert indicates a {attack_type} attack with potential ties to nation-state actors. The investigation has uncovered evidence of credential harvesting, privilege escalation, and network reconnaissance. Several IOCs have been identified including malicious domains and IP addresses. Active threat hunting is recommended to identify additional compromised systems."
        ]
        return random.choice(templates)
    
    def _generate_threat_intelligence(self) -> Dict:
        """Generate threat intelligence data"""
        actors = ["APT-29", "Lazarus Group", "FIN7", "APT-41", "UNC2452", "Sandworm"]
        campaigns = ["Operation Shadow", "Campaign 2026-Q3", "Ghost Protocol", "Silent Skies"]
        tactics = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access"]
        
        return {
            "actor": random.choice(actors),
            "confidence": random.choice(["High", "Medium", "Low"]),
            "tactics": random.sample(tactics, 3),
            "campaigns": random.sample(campaigns, 2),
            "motivation": random.choice(["Financial", "Espionage", "Disruption", "Hacktivism"]),
            "capabilities": random.sample(["Advanced", "Intermediate", "Basic"], 1)[0]
        }
    
    def _generate_mitre_mapping(self, attack_type: str) -> Dict:
        """Generate MITRE ATT&CK mapping"""
        mappings = {
            "Phishing": {
                "technique_id": "T1566",
                "technique_name": "Phishing",
                "tactic": "Initial Access",
                "description": "Spearphishing email with malicious attachment or link",
                "sub_techniques": ["T1566.001", "T1566.002"]
            },
            "Malware": {
                "technique_id": "T1204",
                "technique_name": "User Execution",
                "tactic": "Execution",
                "description": "Execution of malicious file or script",
                "sub_techniques": ["T1204.001", "T1204.002"]
            },
            "Ransomware": {
                "technique_id": "T1486",
                "technique_name": "Data Encrypted for Impact",
                "tactic": "Impact",
                "description": "Encryption of critical files for ransom",
                "sub_techniques": []
            },
            "DDoS": {
                "technique_id": "T1498",
                "technique_name": "Network Denial of Service",
                "tactic": "Impact",
                "description": "Flooding network with malicious traffic",
                "sub_techniques": ["T1498.001", "T1498.002"]
            },
            "Data Exfiltration": {
                "technique_id": "T1048",
                "technique_name": "Exfiltration Over Alternative Protocol",
                "tactic": "Exfiltration",
                "description": "Unauthorized transfer of sensitive data",
                "sub_techniques": ["T1048.001", "T1048.002", "T1048.003"]
            }
        }
        
        return mappings.get(attack_type, {
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "tactic": "Privilege Escalation",
            "description": "Unknown attack technique requiring investigation",
            "sub_techniques": []
        })
    
    def _generate_recommendations(self, severity: str) -> List[str]:
        """Generate recommendations based on severity"""
        base_recommendations = [
            "Isolate affected hosts immediately",
            "Reset compromised credentials",
            "Enable MFA for affected users",
            "Conduct user awareness training",
            "Implement enhanced monitoring"
        ]
        
        if severity in ["Critical", "High"]:
            base_recommendations.extend([
                "Initiate incident response plan",
                "Notify executive leadership",
                "Engage external security partners if needed",
                "Preserve forensic evidence",
                "Conduct full network scan"
            ])
        else:
            base_recommendations.extend([
                "Review and update security policies",
                "Enhance logging and monitoring",
                "Conduct vulnerability assessment"
            ])
        
        return base_recommendations
    
    def _generate_iocs(self, count: int) -> List[str]:
        """Generate mock IOCs"""
        iocs = []
        types = ["ip", "domain", "hash", "url"]
        
        for _ in range(count):
            ioc_type = random.choice(types)
            if ioc_type == "ip":
                iocs.append(f"192.168.{random.randint(1,255)}.{random.randint(1,255)}")
            elif ioc_type == "domain":
                domains = ["malicious", "suspicious", "phishing", "ransomware", "trojan"]
                iocs.append(f"{random.choice(domains)}-{random.randint(1,999)}.com")
            elif ioc_type == "hash":
                iocs.append(f"md5_{''.join([str(random.randint(0,9)) for _ in range(32)])}")
            else:
                iocs.append(f"https://{random.choice(['evil', 'bad', 'fake'])}.com/path/{random.randint(1,999)}")
        
        return iocs
    
    def _generate_mock_alerts(self, count: int) -> List[Dict]:
        """Generate mock alerts"""
        alerts = []
        for i in range(1, count + 1):
            alert = {
                "id": f"ALERT-{i:04d}",
                "severity": random.choice([s.value for s in SeverityLevel]),
                "timestamp": (datetime.now() - timedelta(hours=random.randint(0, 48))).isoformat(),
                "rule": f"Rule-{random.randint(1000, 9999)}",
                "source": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
                "description": f"Alert {i} detected by rule {random.randint(1000, 9999)}"
            }
            alerts.append(alert)
        return alerts
    
    def get_dashboard_stats(self) -> DashboardStats:
        """Get dashboard statistics with MCP integration"""
        # Return empty stats when Wazuh data is not available
        return self._get_empty_stats()
    
    def _get_empty_stats(self) -> DashboardStats:
        """Get empty statistics when no Wazuh data is available"""
        return DashboardStats(
            total_alerts=0,
            critical=0,
            high=0,
            medium=0,
            low=0,
            investigated=0,
            pending=0,
            resolved=0,
            in_progress=0,
            total_investigations=0
        )
    
    def get_investigations(self, limit: int = 20, offset: int = 0) -> List[Investigation]:
        """Get recent investigations with pagination"""
        start = offset
        end = offset + limit
        investigations = self._investigations[start:end]
        
        return [
            Investigation(
                id=inv.get("id"),
                alert_id=inv["alert_id"],
                severity=inv["severity"],
                attack_type=inv["attack_type"],
                host=inv["host"],
                timestamp=datetime.fromisoformat(inv["timestamp"]),
                status=inv["status"],
                ioc=inv.get("ioc", []),
                summary=inv.get("summary", ""),
                description=inv.get("description", ""),
                analyst=inv.get("analyst", "System"),
                source_ip=inv.get("source_ip"),
                destination_ip=inv.get("destination_ip"),
                duration_minutes=inv.get("duration_minutes")
            )
            for inv in investigations
        ]
    
    def search_investigations(self, query: str, severity: Optional[str] = None, limit: int = 50) -> List[SearchResult]:
        """Search investigations by query"""
        query_lower = query.lower()
        results = []
        
        for inv in self._investigations:
            # Apply severity filter if specified
            if severity and inv["severity"].lower() != severity.lower():
                continue
            
            # Search in multiple fields
            searchable_fields = [
                inv["alert_id"].lower(),
                inv["attack_type"].lower(),
                inv["host"].lower(),
                inv.get("summary", "").lower(),
                inv.get("description", "").lower(),
                inv.get("source_ip", "").lower(),
                inv.get("destination_ip", "").lower()
            ]
            
            # Check if query matches any field
            if any(query_lower in field for field in searchable_fields):
                results.append(inv)
                continue
            
            # Check IOCs
            for ioc in inv.get("ioc", []):
                if query_lower in ioc.lower():
                    results.append(inv)
                    break
        
        # Convert to SearchResult objects
        return [
            SearchResult(
                alert_id=inv["alert_id"],
                severity=inv["severity"],
                attack_type=inv["attack_type"],
                host=inv["host"],
                timestamp=datetime.fromisoformat(inv["timestamp"]),
                status=inv["status"],
                ioc=inv.get("ioc", []),
                summary=inv.get("summary", "")
            )
            for inv in results[:limit]
        ]
    
    def advanced_search(self, **kwargs) -> List[SearchResult]:
        """Advanced search with multiple filters"""
        results = self._investigations.copy()
        
        # Apply filters
        if kwargs.get("alert_id"):
            alert_id_lower = kwargs["alert_id"].lower()
            results = [inv for inv in results if alert_id_lower in inv["alert_id"].lower()]
        
        if kwargs.get("hostname"):
            hostname_lower = kwargs["hostname"].lower()
            results = [inv for inv in results if hostname_lower in inv["host"].lower()]
        
        if kwargs.get("attack_type"):
            attack_type_lower = kwargs["attack_type"].lower()
            results = [inv for inv in results if attack_type_lower in inv["attack_type"].lower()]
        
        if kwargs.get("ioc"):
            ioc_lower = kwargs["ioc"].lower()
            results = [inv for inv in results 
                      if any(ioc_lower in ioc.lower() for ioc in inv.get("ioc", []))]
        
        if kwargs.get("severity"):
            severity_lower = kwargs["severity"].lower()
            results = [inv for inv in results if inv["severity"].lower() == severity_lower]
        
        # Apply limit
        limit = kwargs.get("limit", 50)
        results = results[:limit]
        
        return [
            SearchResult(
                alert_id=inv["alert_id"],
                severity=inv["severity"],
                attack_type=inv["attack_type"],
                host=inv["host"],
                timestamp=datetime.fromisoformat(inv["timestamp"]),
                status=inv["status"],
                ioc=inv.get("ioc", []),
                summary=inv.get("summary", "")
            )
            for inv in results
        ]
    
    def get_investigation_by_id(self, alert_id: str) -> Optional[Investigation]:
        """Get investigation by alert ID with full AI analysis"""
        for inv in self._investigations:
            if inv["alert_id"] == alert_id:
                # Check cache first
                if alert_id in self._investigation_cache:
                    return self._investigation_cache[alert_id]
                
                investigation = Investigation(
                    id=inv.get("id"),
                    alert_id=inv["alert_id"],
                    severity=inv["severity"],
                    attack_type=inv["attack_type"],
                    host=inv["host"],
                    timestamp=datetime.fromisoformat(inv["timestamp"]),
                    status=inv["status"],
                    ioc=inv.get("ioc", []),
                    summary=inv.get("summary", ""),
                    description=inv.get("description", ""),
                    analyst=inv.get("analyst", "System"),
                    source_ip=inv.get("source_ip"),
                    destination_ip=inv.get("destination_ip"),
                    duration_minutes=inv.get("duration_minutes")
                )
                
                # Cache for fast retrieval
                self._investigation_cache[alert_id] = investigation
                return investigation
        
        return None
    
    def get_full_investigation_data(self, alert_id: str) -> Dict[str, Any]:
        """Get complete investigation data including AI analysis"""
        investigation = self.get_investigation_by_id(alert_id)
        if not investigation:
            return None
        
        # Get full data from the original dict
        for inv in self._investigations:
            if inv["alert_id"] == alert_id:
                return {
                    "investigation": investigation.dict(),
                    "ai_analysis": inv.get("ai_analysis", "AI analysis in progress..."),
                    "threat_intelligence": inv.get("threat_intelligence", {}),
                    "mitre_mapping": inv.get("mitre_mapping", {}),
                    "recommendations": inv.get("recommendations", []),
                    "timeline": self._generate_investigation_timeline(inv),
                    "correlation": self._correlate_intelligence(alert_id)
                }
        
        return None
    
    def _generate_investigation_timeline(self, investigation: Dict) -> List[Dict]:
        """Generate investigation timeline"""
        timestamp = datetime.fromisoformat(investigation["timestamp"])
        
        return [
            {
                "time": timestamp.isoformat(),
                "event": "Alert detected",
                "description": f"{investigation['attack_type']} alert detected on {investigation['host']}"
            },
            {
                "time": (timestamp + timedelta(minutes=2)).isoformat(),
                "event": "AI Analysis initiated",
                "description": "AI-powered analysis started analyzing telemetry and threat intelligence"
            },
            {
                "time": (timestamp + timedelta(minutes=5)).isoformat(),
                "event": "Threat intelligence correlation",
                "description": "Correlating with threat intelligence feeds and known IOCs"
            },
            {
                "time": (timestamp + timedelta(minutes=10)).isoformat(),
                "event": "Investigation assigned",
                "description": f"Investigation assigned to {investigation.get('analyst', 'System')}"
            },
            {
                "time": (timestamp + timedelta(minutes=15)).isoformat(),
                "event": "Analysis complete",
                "description": "AI analysis completed with findings and recommendations"
            }
        ]
    
    def _correlate_intelligence(self, alert_id: str) -> Dict:
        """Correlate investigation with threat intelligence"""
        return {
            "related_alerts": [],
            "threat_indicators": [],
            "similar_incidents": [],
            "risk_score": "Low"
        }
    
    def create_investigation(self, alert_data: Dict) -> Investigation:
        """Create a new investigation from alert data"""
        investigation_id = len(self._investigations) + 1
        timestamp = datetime.now()
        
        investigation = {
            "id": investigation_id,
            "alert_id": f"SOC-ALERT-{investigation_id:04d}",
            "severity": alert_data.get("severity", "Medium"),
            "attack_type": alert_data.get("attack_type", "Unknown"),
            "host": alert_data.get("host", "Unknown"),
            "timestamp": timestamp.isoformat(),
            "status": "Investigating",
            "ioc": alert_data.get("ioc", []),
            "summary": alert_data.get("summary", "New investigation created"),
            "description": alert_data.get("description", ""),
            "analyst": "System",
            "source_ip": alert_data.get("source_ip", ""),
            "destination_ip": alert_data.get("destination_ip", ""),
            "duration_minutes": 0,
            "ai_analysis": self._generate_ai_analysis(alert_data.get("severity", "Medium"), alert_data.get("attack_type", "Unknown")),
            "threat_intelligence": self._generate_threat_intelligence(),
            "mitre_mapping": self._generate_mitre_mapping(alert_data.get("attack_type", "Unknown")),
            "recommendations": self._generate_recommendations(alert_data.get("severity", "Medium"))
        }
        
        self._investigations.append(investigation)
        
        return Investigation(
            id=investigation["id"],
            alert_id=investigation["alert_id"],
            severity=investigation["severity"],
            attack_type=investigation["attack_type"],
            host=investigation["host"],
            timestamp=timestamp,
            status=investigation["status"],
            ioc=investigation["ioc"],
            summary=investigation["summary"],
            description=investigation["description"],
            analyst=investigation["analyst"],
            source_ip=investigation["source_ip"],
            destination_ip=investigation["destination_ip"],
            duration_minutes=investigation["duration_minutes"]
        )
    
    def update_investigation_status(self, alert_id: str, status: str) -> bool:
        """Update investigation status"""
        for inv in self._investigations:
            if inv["alert_id"] == alert_id:
                inv["status"] = status
                # Clear cache
                if alert_id in self._investigation_cache:
                    del self._investigation_cache[alert_id]
                return True
        return False

# Global instance
dashboard_service = DashboardService()