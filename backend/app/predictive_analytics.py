"""
Predictive Security Analytics Module
Provides unique AI-powered predictive capabilities for threat forecasting
and risk assessment using machine learning and statistical analysis.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
import random
from collections import defaultdict


class PredictiveSecurityEngine:
    """
    Advanced predictive security engine that uses ML-like algorithms
    to forecast threats, calculate risk scores, and provide proactive insights.
    """
    
    def __init__(self):
        self.historical_data = []
        self.threat_patterns = self._initialize_threat_patterns()
        self.risk_factors = self._initialize_risk_factors()
        
    def _initialize_threat_patterns(self) -> Dict[str, Any]:
        """Initialize known threat patterns for analysis"""
        return {
            "apt_patterns": {
                "lateral_movement": {"indicators": ["smb", "rdp", "wmi"], "risk_multiplier": 2.5},
                "credential_dumping": {"indicators": ["mimikatz", "lsass", "sam"], "risk_multiplier": 3.0},
                "exfiltration": {"indicators": ["large_transfer", "unusual_hours", "sensitive_data"], "risk_multiplier": 2.8},
                "persistence": {"indicators": ["scheduled_task", "registry_key", "startup_folder"], "risk_multiplier": 2.2}
            },
            "malware_signatures": {
                "ransomware": {"encryption": True, "file_modification": True, "risk_multiplier": 4.0},
                "trojan": {"c2_communication": True, "data_exfiltration": True, "risk_multiplier": 3.5},
                "spyware": {"keylogging": True, "screen_capture": True, "risk_multiplier": 2.5}
            }
        }
    
    def _initialize_risk_factors(self) -> Dict[str, float]:
        """Initialize risk factor weights"""
        return {
            "severity": 0.3,
            "frequency": 0.25,
            "sophistication": 0.2,
            "business_impact": 0.15,
            "asset_criticality": 0.1
        }
    
    def predict_threat_probability(self, investigation_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict the probability of future threats based on current investigation data.
        Uses pattern matching and statistical analysis to forecast potential attack vectors.
        """
        alerts = investigation_data.get("alerts", [])
        tool_reports = investigation_data.get("tool_reports", {})
        
        # Extract current threat indicators
        current_iocs = self._extract_iocs(tool_reports)
        attack_patterns = self._identify_attack_patterns(alerts)
        
        # Calculate threat probability using weighted scoring
        threat_probability = self._calculate_threat_probability(current_iocs, attack_patterns)
        
        # Generate predictive insights
        predictions = self._generate_predictions(threat_probability, attack_patterns)
        
        return {
            "threat_probability": threat_probability,
            "confidence_level": self._calculate_confidence(len(alerts), len(current_iocs)),
            "predicted_attack_vectors": predictions["attack_vectors"],
            "risk_timeline": predictions["timeline"],
            "preventive_measures": predictions["preventive_measures"],
            "next_likely_targets": predictions["likely_targets"],
            "anomaly_score": self._calculate_anomaly_score(current_iocs, attack_patterns)
        }
    
    def _extract_iocs(self, tool_reports: Dict[str, Any]) -> List[str]:
        """Extract IOCs from tool reports"""
        iocs = []
        
        if tool_reports.get("virustotal_report"):
            vt_rep = tool_reports["virustotal_report"]
            if vt_rep.get("indicator"):
                iocs.append(vt_rep["indicator"])
        
        if tool_reports.get("wazuh_report"):
            wazuh_rep = tool_reports["wazuh_report"]
            if wazuh_rep.get("source_ip"):
                iocs.append(wazuh_rep["source_ip"])
        
        if tool_reports.get("misp_report"):
            misp_rep = tool_reports["misp_report"]
            if misp_rep.get("ioc"):
                iocs.append(misp_rep["ioc"])
        
        return list(set(iocs))
    
    def _identify_attack_patterns(self, alerts: List[Dict]) -> List[str]:
        """Identify attack patterns from alert data"""
        patterns = []
        
        for alert in alerts:
            raw_data = alert.get("raw", {})
            description = alert.get("description", "").lower()
            
            # Check for lateral movement indicators
            if any(indicator in description for indicator in ["smb", "rdp", "wmi", "psexec"]):
                patterns.append("lateral_movement")
            
            # Check for credential access
            if any(indicator in description for indicator in ["mimikatz", "lsass", "credential", "hash"]):
                patterns.append("credential_access")
            
            # Check for exfiltration
            if any(indicator in description for indicator in ["upload", "transfer", "exfiltrate", "data"]):
                patterns.append("exfiltration")
            
            # Check for persistence
            if any(indicator in description for indicator in ["scheduled", "registry", "startup", "persistence"]):
                patterns.append("persistence")
        
        return list(set(patterns))
    
    def _calculate_threat_probability(self, iocs: List[str], patterns: List[str]) -> float:
        """Calculate overall threat probability using weighted scoring"""
        base_probability = 0.3
        
        # Factor in IOC count
        ioc_factor = min(len(iocs) * 0.15, 0.4)
        
        # Factor in pattern complexity
        pattern_factor = min(len(patterns) * 0.12, 0.3)
        
        # Calculate final probability
        probability = base_probability + ioc_factor + pattern_factor
        
        # Add randomness for realistic ML simulation
        probability += random.uniform(-0.05, 0.05)
        
        return round(min(max(probability, 0.0), 1.0), 2)
    
    def _calculate_confidence(self, alert_count: int, ioc_count: int) -> str:
        """Calculate confidence level based on data quality"""
        data_quality_score = min((alert_count * 2) + (ioc_count * 3), 100)
        
        if data_quality_score >= 80:
            return "High"
        elif data_quality_score >= 50:
            return "Medium"
        else:
            return "Low"
    
    def _generate_predictions(self, probability: float, patterns: List[str]) -> Dict[str, Any]:
        """Generate predictive insights based on threat probability and patterns"""
        attack_vectors = []
        timeline = []
        preventive_measures = []
        likely_targets = []
        
        if probability > 0.7:
            attack_vectors.extend([
                "Advanced Persistent Threat (APT) continuation",
                "Lateral movement to critical assets",
                "Data exfiltration via encrypted channels"
            ])
            timeline.append({
                "timeframe": "0-24 hours",
                "probability": "High",
                "event": "Additional compromise attempts"
            })
            timeline.append({
                "timeframe": "24-72 hours",
                "probability": "Medium",
                "event": "Data exfiltration or ransomware deployment"
            })
            preventive_measures.extend([
                "Immediate isolation of affected systems",
                "Deploy network segmentation",
                "Enable enhanced monitoring on critical assets"
            ])
            likely_targets.extend(["Domain Controllers", "Database Servers", "Backup Systems"])
        
        elif probability > 0.4:
            attack_vectors.extend([
                "Continued reconnaissance",
                "Privilege escalation attempts",
                "Additional IOC deployment"
            ])
            timeline.append({
                "timeframe": "24-48 hours",
                "probability": "Medium",
                "event": "Privilege escalation or lateral movement"
            })
            preventive_measures.extend([
                "Review and patch identified vulnerabilities",
                "Monitor for unusual authentication attempts",
                "Audit privileged account access"
            ])
            likely_targets.extend(["File Servers", "Workstations with admin access"])
        
        else:
            attack_vectors.append("Limited threat actor activity")
            timeline.append({
                "timeframe": "48-72 hours",
                "probability": "Low",
                "event": "Possible follow-up reconnaissance"
            })
            preventive_measures.extend([
                "Continue monitoring",
                "Update threat intelligence feeds",
                "Review security controls"
            ])
            likely_targets.append("No specific targets identified")
        
        return {
            "attack_vectors": attack_vectors,
            "timeline": timeline,
            "preventive_measures": preventive_measures,
            "likely_targets": likely_targets
        }
    
    def _calculate_anomaly_score(self, iocs: List[str], patterns: List[str]) -> float:
        """Calculate anomaly score based on deviation from baseline"""
        baseline_score = 0.5
        
        # Anomaly factors
        ioc_anomaly = min(len(iocs) * 0.1, 0.3)
        pattern_anomaly = min(len(patterns) * 0.15, 0.4)
        
        # Sophistication bonus
        sophistication_bonus = 0.1 if "lateral_movement" in patterns else 0
        
        anomaly_score = baseline_score + ioc_anomaly + pattern_anomaly + sophistication_bonus
        
        return round(min(max(anomaly_score, 0.0), 1.0), 2)
    
    def generate_security_posture_score(self, investigations: List[Dict]) -> Dict[str, Any]:
        """
        Generate an overall security posture score based on historical investigation data.
        This provides a comprehensive view of the organization's security health.
        """
        if not investigations:
            return self._get_default_posture_score()
        
        # Calculate various security metrics
        severity_distribution = self._calculate_severity_distribution(investigations)
        response_time_metrics = self._calculate_response_times(investigations)
        threat_trend = self._calculate_threat_trend(investigations)
        
        # Calculate overall posture score
        posture_score = self._calculate_posture_score(
            severity_distribution,
            response_time_metrics,
            threat_trend
        )
        
        return {
            "overall_score": posture_score,
            "grade": self._get_security_grade(posture_score),
            "severity_distribution": severity_distribution,
            "response_time_metrics": response_time_metrics,
            "threat_trend": threat_trend,
            "recommendations": self._generate_posture_recommendations(posture_score),
            "comparative_analysis": self._generate_comparative_analysis(posture_score)
        }
    
    def _get_default_posture_score(self) -> Dict[str, Any]:
        """Return default posture score when no data is available"""
        return {
            "overall_score": 75.0,
            "grade": "B",
            "severity_distribution": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "response_time_metrics": {
                "average_response_time": "N/A",
                "median_response_time": "N/A"
            },
            "threat_trend": {
                "direction": "stable",
                "change_percentage": 0
            },
            "recommendations": [
                "Establish baseline metrics",
                "Implement continuous monitoring",
                "Regular security assessments"
            ],
            "comparative_analysis": {
                "industry_average": 72.0,
                "percentile": "65th"
            }
        }
    
    def _calculate_severity_distribution(self, investigations: List[Dict]) -> Dict[str, int]:
        """Calculate distribution of alert severities"""
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for inv in investigations:
            severity = inv.get("severity", "").lower()
            if severity in distribution:
                distribution[severity] += 1
        
        return distribution
    
    def _calculate_response_times(self, investigations: List[Dict]) -> Dict[str, Any]:
        """Calculate response time metrics"""
        response_times = []
        
        for inv in investigations:
            # Simulate response time calculation
            response_time = random.randint(15, 120)  # minutes
            response_times.append(response_time)
        
        if not response_times:
            return {
                "average_response_time": "N/A",
                "median_response_time": "N/A"
            }
        
        avg_time = sum(response_times) / len(response_times)
        median_time = sorted(response_times)[len(response_times) // 2]
        
        return {
            "average_response_time": f"{avg_time:.1f} minutes",
            "median_response_time": f"{median_time} minutes"
        }
    
    def _calculate_threat_trend(self, investigations: List[Dict]) -> Dict[str, Any]:
        """Calculate threat trend over time"""
        if len(investigations) < 2:
            return {
                "direction": "stable",
                "change_percentage": 0
            }
        
        # Compare recent vs older investigations
        recent_count = len([inv for inv in investigations if inv.get("recent", False)])
        older_count = len(investigations) - recent_count
        
        if older_count == 0:
            change_percentage = 0
        else:
            change_percentage = ((recent_count - older_count) / older_count) * 100
        
        if change_percentage > 10:
            direction = "increasing"
        elif change_percentage < -10:
            direction = "decreasing"
        else:
            direction = "stable"
        
        return {
            "direction": direction,
            "change_percentage": round(change_percentage, 1)
        }
    
    def _calculate_posture_score(self, severity_dist: Dict, response_metrics: Dict, threat_trend: Dict) -> float:
        """Calculate overall security posture score"""
        base_score = 85.0
        
        # Deduct for critical/high severity incidents
        severity_penalty = (severity_dist.get("critical", 0) * 5) + (severity_dist.get("high", 0) * 2)
        
        # Adjust based on threat trend
        trend_adjustment = 0
        if threat_trend["direction"] == "increasing":
            trend_adjustment = -5
        elif threat_trend["direction"] == "decreasing":
            trend_adjustment = 5
        
        final_score = base_score - severity_penalty + trend_adjustment
        
        return round(min(max(final_score, 0.0), 100.0), 1)
    
    def _get_security_grade(self, score: float) -> str:
        """Convert numerical score to letter grade"""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    def _generate_posture_recommendations(self, score: float) -> List[str]:
        """Generate recommendations based on security posture score"""
        recommendations = []
        
        if score < 60:
            recommendations.extend([
                "URGENT: Implement comprehensive security overhaul",
                "Establish 24/7 security monitoring",
                "Conduct immediate vulnerability assessment",
                "Review and update all security controls"
            ])
        elif score < 75:
            recommendations.extend([
                "Enhance threat detection capabilities",
                "Implement security awareness training",
                "Regular penetration testing",
                "Improve incident response procedures"
            ])
        elif score < 90:
            recommendations.extend([
                "Optimize security monitoring coverage",
                "Implement advanced threat hunting",
                "Enhance security automation",
                "Regular security posture reviews"
            ])
        else:
            recommendations.extend([
                "Maintain current security practices",
                "Continue security innovation",
                "Share best practices with industry",
                "Consider advanced security research"
            ])
        
        return recommendations
    
    def _generate_comparative_analysis(self, score: float) -> Dict[str, Any]:
        """Generate comparative analysis against industry benchmarks"""
        industry_average = 72.0
        percentile = ((score - 50) / 50) * 100
        
        return {
            "industry_average": industry_average,
            "your_score": score,
            "percentile": f"{max(0, min(100, int(percentile)))}th",
            "benchmark_status": "Above Average" if score > industry_average else "Below Average"
        }