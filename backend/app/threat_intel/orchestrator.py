"""
Threat Intelligence Orchestrator
Coordinates between multiple threat intelligence sources
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
from .virustotal_client import VirusTotalClient
from .mitre_attack_client import MITREAttackClient
from .sigma_client import SigmaClient
from .abuseipdb_client import AbuseIPDBClient
from ..utils.logger import get_logger

logger = get_logger(__name__)


class ThreatIntelOrchestrator:
    """Orchestrates threat intelligence collection and analysis"""
    
    def __init__(self, config: Dict[str, str]):
        self.config = config
        self.clients = {}
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Initialize threat intelligence clients"""
        try:
            if self.config.get("virustotal_api_key"):
                self.clients["virustotal"] = VirusTotalClient(
                    self.config["virustotal_api_key"]
                )
                logger.info("VirusTotal client initialized")
            
            self.clients["mitre_attack"] = MITREAttackClient()
            logger.info("MITRE ATT&CK client initialized")
            
            self.clients["sigma"] = SigmaClient()
            logger.info("Sigma client initialized")
            
            if self.config.get("abuseipdb_api_key"):
                self.clients["abuseipdb"] = AbuseIPDBClient(
                    self.config["abuseipdb_api_key"]
                )
                logger.info("AbuseIPDB client initialized")
                
        except Exception as e:
            logger.error(f"Error initializing clients: {e}")
    
    async def analyze_iocs(self, iocs: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze IOCs using all available threat intelligence sources"""
        results = {
            "analysis_timestamp": datetime.now().isoformat(),
            "ioc_summary": iocs.get("summary", {}),
            "threat_intel_results": {},
            "correlation_analysis": {},
            "risk_assessment": {},
            "recommended_actions": []
        }
        
        # Analyze with VirusTotal
        if "virustotal" in self.clients:
            try:
                vt_results = await self.clients["virustotal"].batch_analyze(iocs)
                results["threat_intel_results"]["virustotal"] = vt_results
                logger.info("VirusTotal analysis completed")
            except Exception as e:
                logger.error(f"VirusTotal analysis failed: {e}")
                results["threat_intel_results"]["virustotal"] = {"error": str(e)}
        
        # Analyze with AbuseIPDB for IPs
        if "abuseipdb" in self.clients and iocs.get("ip_addresses"):
            try:
                ip_results = await self.clients["abuseipdb"].check_bulk_ips(
                    iocs["ip_addresses"]
                )
                results["threat_intel_results"]["abuseipdb"] = ip_results
                logger.info("AbuseIPDB analysis completed")
            except Exception as e:
                logger.error(f"AbuseIPDB analysis failed: {e}")
                results["threat_intel_results"]["abuseipdb"] = {"error": str(e)}
        
        # Map to MITRE ATT&CK
        if "mitre_attack" in self.clients:
            try:
                mitre_mapping = await self.clients["mitre_attack"].map_iocs_to_techniques(iocs)
                results["threat_intel_results"]["mitre_attack"] = mitre_mapping
                logger.info("MITRE ATT&CK mapping completed")
            except Exception as e:
                logger.error(f"MITRE ATT&CK mapping failed: {e}")
                results["threat_intel_results"]["mitre_attack"] = {"error": str(e)}
        
        # Analyze against Sigma rules
        if "sigma" in self.clients:
            try:
                # Note: This would require the actual log data
                # For now, we'll search for relevant rules
                sigma_rules = await self.clients["sigma"].search_rules("malware")
                results["threat_intel_results"]["sigma"] = sigma_rules
                logger.info("Sigma analysis completed")
            except Exception as e:
                logger.error(f"Sigma analysis failed: {e}")
                results["threat_intel_results"]["sigma"] = {"error": str(e)}
        
        # Perform correlation analysis
        results["correlation_analysis"] = self._correlate_results(
            results["threat_intel_results"]
        )
        
        # Calculate overall risk assessment
        results["risk_assessment"] = self._calculate_risk_assessment(
            results["threat_intel_results"],
            results["correlation_analysis"]
        )
        
        # Generate recommended actions
        results["recommended_actions"] = self._generate_recommendations(
            results["risk_assessment"],
            results["threat_intel_results"]
        )
        
        return results
    
    def _correlate_results(self, threat_intel_results: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate results from different threat intelligence sources"""
        correlation = {
            "cross_source_matches": [],
            "high_confidence_findings": [],
            "suspicious_patterns": [],
            "threat_actor_indicators": []
        }
        
        # Correlate VirusTotal and AbuseIPDB for IPs
        if "virustotal" in threat_intel_results and "abuseipdb" in threat_intel_results:
            vt_results = threat_intel_results["virustotal"]
            abuse_results = threat_intel_results["abuseipdb"]
            
            # Find IPs that are flagged by both sources
            vt_malicious = self._extract_malicious_iocs(vt_results, "ip")
            abuse_malicious = self._extract_malicious_iocs(abuse_results, "ip")
            
            common_malicious = set(vt_malicious) & set(abuse_malicious)
            if common_malicious:
                correlation["cross_source_matches"].extend([
                    {"type": "ip", "value": ip, "sources": ["virustotal", "abuseipdb"]}
                    for ip in common_malicious
                ])
        
        # Correlate MITRE techniques with VirusTotal findings
        if "mitre_attack" in threat_intel_results and "virustotal" in threat_intel_results:
            mitre_techniques = threat_intel_results["mitre_attack"].get("techniques", [])
            vt_detections = threat_intel_results["virustotal"].get("analyses", {})
            
            # Look for patterns that might indicate specific threat actors
            if len(mitre_techniques) > 3 and any(
                "malicious" in str(vt_detections).lower()
            ):
                correlation["threat_actor_indicators"].append({
                    "description": "Multiple MITRE techniques combined with malware detections",
                    "confidence": "medium",
                    "techniques": [t.get("name", "") for t in mitre_techniques[:5]]
                })
        
        # Identify high-confidence findings
        for source, results in threat_intel_results.items():
            if isinstance(results, dict) and "analyses" in results:
                for ioc_key, analysis in results["analyses"].items():
                    if self._is_high_confidence(analysis):
                        correlation["high_confidence_findings"].append({
                            "ioc": ioc_key,
                            "source": source,
                            "analysis": analysis
                        })
        
        return correlation
    
    def _extract_malicious_iocs(self, results: Dict[str, Any], ioc_type: str) -> List[str]:
        """Extract malicious IOCs from analysis results"""
        malicious_iocs = []
        
        if "analyses" in results:
            for ioc_key, analysis in results["analyses"].items():
                if (isinstance(analysis, dict) and 
                    analysis.get("risk_level") in ["critical", "high"] and
                    analysis.get("ioc_type") == ioc_type):
                    malicious_iocs.append(analysis.get("value", ioc_key))
        
        return malicious_iocs
    
    def _is_high_confidence(self, analysis: Dict[str, Any]) -> bool:
        """Check if analysis result is high confidence"""
        if not isinstance(analysis, dict):
            return False
        
        risk_level = analysis.get("risk_level", "")
        positive_detections = analysis.get("positive_detections", 0)
        
        return risk_level in ["critical", "high"] or positive_detections > 5
    
    def _calculate_risk_assessment(self, threat_intel_results: Dict[str, Any],
                                  correlation_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk assessment"""
        risk_score = 0
        risk_factors = []
        
        # Assess VirusTotal results
        if "virustotal" in threat_intel_results:
            vt_results = threat_intel_results["virustotal"]
            successful = vt_results.get("successful", 0)
            failed = vt_results.get("failed", 0)
            
            if successful > 0:
                # Check for malicious detections
                malicious_count = 0
                for analysis in vt_results.get("analyses", {}).values():
                    if isinstance(analysis, dict) and analysis.get("positive_detections", 0) > 0:
                        malicious_count += 1
                
                if malicious_count > 0:
                    risk_score += min(malicious_count * 20, 60)
                    risk_factors.append(f"VirusTotal: {malicious_count} malicious detections")
        
        # Assess AbuseIPDB results
        if "abuseipdb" in threat_intel_results:
            abuse_results = threat_intel_results["abuseipdb"]
            malicious_count = abuse_results.get("malicious_count", 0)
            suspicious_count = abuse_results.get("suspicious_count", 0)
            
            if malicious_count > 0:
                risk_score += min(malicious_count * 25, 75)
                risk_factors.append(f"AbuseIPDB: {malicious_count} malicious IPs")
            if suspicious_count > 0:
                risk_score += min(suspicious_count * 10, 30)
                risk_factors.append(f"AbuseIPDB: {suspicious_count} suspicious IPs")
        
        # Assess MITRE ATT&CK mapping
        if "mitre_attack" in threat_intel_results:
            mitre_results = threat_intel_results["mitre_attack"]
            technique_count = len(mitre_results.get("techniques", []))
            
            if technique_count > 3:
                risk_score += min(technique_count * 5, 25)
                risk_factors.append(f"MITRE ATT&CK: {technique_count} techniques mapped")
        
        # Assess correlation analysis
        cross_source_matches = len(correlation_analysis.get("cross_source_matches", []))
        if cross_source_matches > 0:
            risk_score += min(cross_source_matches * 15, 45)
            risk_factors.append(f"Correlation: {cross_source_matches} cross-source matches")
        
        # Cap risk score at 100
        risk_score = min(risk_score, 100)
        
        # Determine risk level
        if risk_score >= 75:
            risk_level = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "overall_risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "requires_immediate_action": risk_level in ["critical", "high"],
            "requires_investigation": risk_level in ["medium", "high", "critical"]
        }
    
    def _generate_recommendations(self, risk_assessment: Dict[str, Any],
                                 threat_intel_results: Dict[str, Any]) -> List[str]:
        """Generate recommended actions based on risk assessment"""
        recommendations = []
        risk_level = risk_assessment.get("risk_level", "low")
        
        if risk_level == "critical":
            recommendations.extend([
                "IMMEDIATE ACTION REQUIRED",
                "Isolate affected systems from the network",
                "Block all identified malicious IOCs at perimeter",
                "Escalate to incident response team",
                "Preserve forensic evidence",
                "Initiate full incident response process"
            ])
        elif risk_level == "high":
            recommendations.extend([
                "Urgent action required",
                "Block malicious IP addresses and domains",
                "Scan affected systems for malware",
                "Review user activity on affected systems",
                "Monitor for additional suspicious activity",
                "Consider isolating high-risk systems"
            ])
        elif risk_level == "medium":
            recommendations.extend([
                "Investigation recommended",
                "Monitor network traffic to suspicious IOCs",
                "Review system logs for related activity",
                "Update security signatures",
                "Educate users on potential threats"
            ])
        else:
            recommendations.extend([
                "Continue normal monitoring",
                "Document findings for future reference",
                "Ensure security controls are up to date"
            ])
        
        # Add specific recommendations based on threat intel results
        if "virustotal" in threat_intel_results:
            vt_results = threat_intel_results["virustotal"]
            if vt_results.get("successful", 0) > 0:
                recommendations.append("Review VirusTotal detections for additional context")
        
        if "mitre_attack" in threat_intel_results:
            mitre_results = threat_intel_results["mitre_attack"]
            if mitre_results.get("techniques"):
                recommendations.append("Review MITRE ATT&CK techniques for defense recommendations")
        
        return recommendations
    
    async def close(self):
        """Close all client connections"""
        for client_name, client in self.clients.items():
            try:
                if hasattr(client, 'close'):
                    await client.close()
                logger.info(f"Closed {client_name} client")
            except Exception as e:
                logger.error(f"Error closing {client_name} client: {e}")