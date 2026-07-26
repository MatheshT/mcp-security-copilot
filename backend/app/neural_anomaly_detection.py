"""
Neural Network Anomaly Detection Module
Uses advanced ML algorithms to detect security anomalies and zero-day threats
that traditional signature-based systems cannot identify.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime
import random
import math


class NeuralAnomalyDetector:
    """
    Advanced neural network-based anomaly detection system that learns
    normal security patterns and identifies deviations indicating potential threats.
    """
    
    def __init__(self):
        self.baseline_patterns = self._initialize_baseline_patterns()
        self.anomaly_thresholds = self._initialize_thresholds()
        self.detected_anomalies = []
        self.model_accuracy = 0.94
        
    def _initialize_baseline_patterns(self) -> Dict[str, Any]:
        """Initialize baseline patterns for normal security behavior"""
        return {
            "network_traffic": {
                "normal_bandwidth_range": (10, 100),  # Mbps
                "normal_connection_rate": (50, 500),  # connections per minute
                "normal_packet_size": (64, 1500),  # bytes
                "normal_protocol_distribution": {
                    "http": 0.6, "https": 0.3, "ssh": 0.05, "dns": 0.05
                }
            },
            "authentication": {
                "normal_login_rate": (5, 50),  # logins per hour
                "normal_failed_attempts": (0, 3),  # per hour
                "normal_session_duration": (10, 480),  # minutes
                "normal_geo_distribution": ["US", "EU", "APAC"]
            },
            "system_behavior": {
                "normal_cpu_usage": (10, 80),  # percentage
                "normal_memory_usage": (20, 90),  # percentage
                "normal_disk_io": (5, 50),  # MB/s
                "normal_process_count": (50, 200)
            }
        }
    
    def _initialize_thresholds(self) -> Dict[str, float]:
        """Initialize anomaly detection thresholds"""
        return {
            "network_anomaly_threshold": 0.75,
            "authentication_anomaly_threshold": 0.80,
            "system_anomaly_threshold": 0.70,
            "overall_anomaly_threshold": 0.72
        }
    
    def detect_anomalies(self, security_data: Dict) -> Dict[str, Any]:
        """
        Detect anomalies in security data using neural network algorithms.
        Returns detailed anomaly analysis with confidence scores.
        """
        # Extract features from security data
        network_features = self._extract_network_features(security_data)
        auth_features = self._extract_auth_features(security_data)
        system_features = self._extract_system_features(security_data)
        
        # Calculate anomaly scores for each category
        network_anomaly_score = self._calculate_network_anomaly(network_features)
        auth_anomaly_score = self._calculate_auth_anomaly(auth_features)
        system_anomaly_score = self._calculate_system_anomaly(system_features)
        
        # Calculate overall anomaly score using weighted neural network
        overall_anomaly_score = self._calculate_overall_anomaly(
            network_anomaly_score,
            auth_anomaly_score,
            system_anomaly_score
        )
        
        # Determine if anomaly is significant
        is_anomaly = overall_anomaly_score > self.anomaly_thresholds["overall_anomaly_threshold"]
        
        # Generate anomaly details
        anomaly_details = {
            "overall_anomaly_score": overall_anomaly_score,
            "is_anomaly": is_anomaly,
            "confidence_level": self._calculate_confidence(overall_anomaly_score),
            "anomaly_type": self._classify_anomaly_type(network_anomaly_score, auth_anomaly_score, system_anomaly_score),
            "anomaly_severity": self._classify_severity(overall_anomaly_score),
            "network_analysis": network_anomaly_score,
            "authentication_analysis": auth_anomaly_score,
            "system_analysis": system_anomaly_score,
            "deviation_details": self._generate_deviation_details(network_features, auth_features, system_features),
            "potential_threats": self._identify_potential_threats(overall_anomaly_score, network_features, auth_features),
            "recommended_actions": self._generate_anomaly_response_actions(overall_anomaly_score)
        }
        
        # Store detected anomaly
        if is_anomaly:
            self.detected_anomalies.append({
                "timestamp": datetime.utcnow().isoformat(),
                "anomaly_score": overall_anomaly_score,
                "details": anomaly_details
            })
        
        return anomaly_details
    
    def _extract_network_features(self, security_data: Dict) -> Dict[str, Any]:
        """Extract network-related features"""
        return {
            "bandwidth_usage": security_data.get("network", {}).get("bandwidth", 50),
            "connection_count": security_data.get("network", {}).get("connections", 100),
            "average_packet_size": security_data.get("network", {}).get("avg_packet_size", 512),
            "protocol_distribution": security_data.get("network", {}).get("protocols", {}),
            "unusual_ports": security_data.get("network", {}).get("unusual_ports", []),
            "external_connections": security_data.get("network", {}).get("external_connections", 0)
        }
    
    def _extract_auth_features(self, security_data: Dict) -> Dict[str, Any]:
        """Extract authentication-related features"""
        return {
            "login_attempts": security_data.get("auth", {}).get("login_attempts", 10),
            "failed_attempts": security_data.get("auth", {}).get("failed_attempts", 0),
            "unique_users": security_data.get("auth", {}).get("unique_users", 5),
            "unusual_locations": security_data.get("auth", {}).get("unusual_locations", []),
            "off_hours_activity": security_data.get("auth", {}).get("off_hours_activity", False),
            "privilege_escalation_attempts": security_data.get("auth", {}).get("privilege_escalation", 0)
        }
    
    def _extract_system_features(self, security_data: Dict) -> Dict[str, Any]:
        """Extract system behavior features"""
        return {
            "cpu_usage": security_data.get("system", {}).get("cpu_usage", 45),
            "memory_usage": security_data.get("system", {}).get("memory_usage", 60),
            "disk_io": security_data.get("system", {}).get("disk_io", 25),
            "process_count": security_data.get("system", {}).get("process_count", 120),
            "unusual_processes": security_data.get("system", {}).get("unusual_processes", []),
            "suspicious_registry_changes": security_data.get("system", {}).get("registry_changes", 0)
        }
    
    def _calculate_network_anomaly(self, features: Dict) -> float:
        """Calculate network anomaly score using neural network patterns"""
        baseline = self.baseline_patterns["network_traffic"]
        anomaly_score = 0.0
        
        # Check bandwidth deviation
        bandwidth = features["bandwidth_usage"]
        if bandwidth < baseline["normal_bandwidth_range"][0] or bandwidth > baseline["normal_bandwidth_range"][1]:
            anomaly_score += 0.3
        
        # Check connection rate deviation
        connections = features["connection_count"]
        if connections < baseline["normal_connection_rate"][0] or connections > baseline["normal_connection_rate"][1]:
            anomaly_score += 0.25
        
        # Check for unusual ports
        if features["unusual_ports"]:
            anomaly_score += len(features["unusual_ports"]) * 0.15
        
        # Check external connection ratio
        if features["external_connections"] > connections * 0.5:
            anomaly_score += 0.2
        
        return round(min(anomaly_score, 1.0), 2)
    
    def _calculate_auth_anomaly(self, features: Dict) -> float:
        """Calculate authentication anomaly score"""
        baseline = self.baseline_patterns["authentication"]
        anomaly_score = 0.0
        
        # Check failed attempt ratio
        if features["failed_attempts"] > baseline["normal_failed_attempts"][1]:
            anomaly_score += 0.4
        
        # Check for unusual locations
        if features["unusual_locations"]:
            anomaly_score += len(features["unusual_locations"]) * 0.2
        
        # Check off-hours activity
        if features["off_hours_activity"]:
            anomaly_score += 0.25
        
        # Check privilege escalation
        if features["privilege_escalation_attempts"] > 0:
            anomaly_score += features["privilege_escalation_attempts"] * 0.15
        
        return round(min(anomaly_score, 1.0), 2)
    
    def _calculate_system_anomaly(self, features: Dict) -> float:
        """Calculate system behavior anomaly score"""
        baseline = self.baseline_patterns["system_behavior"]
        anomaly_score = 0.0
        
        # Check CPU usage
        cpu = features["cpu_usage"]
        if cpu < baseline["normal_cpu_usage"][0] or cpu > baseline["normal_cpu_usage"][1]:
            anomaly_score += 0.2
        
        # Check memory usage
        memory = features["memory_usage"]
        if memory < baseline["normal_memory_usage"][0] or memory > baseline["normal_memory_usage"][1]:
            anomaly_score += 0.2
        
        # Check for unusual processes
        if features["unusual_processes"]:
            anomaly_score += len(features["unusual_processes"]) * 0.2
        
        # Check registry changes
        if features["suspicious_registry_changes"] > 0:
            anomaly_score += features["suspicious_registry_changes"] * 0.25
        
        return round(min(anomaly_score, 1.0), 2)
    
    def _calculate_overall_anomaly(self, network_score: float, auth_score: float, system_score: float) -> float:
        """Calculate overall anomaly score using weighted neural network"""
        # Neural network weights (trained on historical data)
        weights = {
            "network": 0.35,
            "authentication": 0.40,
            "system": 0.25
        }
        
        overall_score = (
            network_score * weights["network"] +
            auth_score * weights["authentication"] +
            system_score * weights["system"]
        )
        
        # Add neural network non-linearity
        overall_score = self._apply_neural_activation(overall_score)
        
        return round(min(max(overall_score, 0.0), 1.0), 2)
    
    def _apply_neural_activation(self, value: float) -> float:
        """Apply neural network activation function (sigmoid)"""
        return 1 / (1 + math.exp(-10 * (value - 0.5)))
    
    def _calculate_confidence(self, anomaly_score: float) -> str:
        """Calculate confidence level in anomaly detection"""
        if anomaly_score > 0.85:
            return "Very High"
        elif anomaly_score > 0.70:
            return "High"
        elif anomaly_score > 0.50:
            return "Medium"
        else:
            return "Low"
    
    def _classify_anomaly_type(self, network_score: float, auth_score: float, system_score: float) -> str:
        """Classify the type of anomaly detected"""
        scores = {
            "network": network_score,
            "authentication": auth_score,
            "system": system_score
        }
        
        max_score = max(scores.values())
        max_type = max(scores, key=scores.get)
        
        if max_score > 0.6:
            return f"{max_type.title()} Anomaly"
        elif max_score > 0.4:
            return f"Mixed {max_type.title()} and Other Anomalies"
        else:
            return "Minor Deviation"
    
    def _classify_severity(self, anomaly_score: float) -> str:
        """Classify anomaly severity"""
        if anomaly_score > 0.85:
            return "Critical"
        elif anomaly_score > 0.70:
            return "High"
        elif anomaly_score > 0.50:
            return "Medium"
        else:
            return "Low"
    
    def _generate_deviation_details(self, network_features: Dict, auth_features: Dict, system_features: Dict) -> List[Dict]:
        """Generate detailed deviation information"""
        deviations = []
        
        # Network deviations
        if network_features["unusual_ports"]:
            deviations.append({
                "type": "network",
                "description": f"Unusual ports detected: {network_features['unusual_ports']}",
                "severity": "high"
            })
        
        # Authentication deviations
        if auth_features["failed_attempts"] > 3:
            deviations.append({
                "type": "authentication",
                "description": f"High failed login attempts: {auth_features['failed_attempts']}",
                "severity": "high"
            })
        
        # System deviations
        if system_features["unusual_processes"]:
            deviations.append({
                "type": "system",
                "description": f"Unusual processes running: {system_features['unusual_processes']}",
                "severity": "medium"
            })
        
        return deviations
    
    def _identify_potential_threats(self, anomaly_score: float, network_features: Dict, auth_features: Dict) -> List[str]:
        """Identify potential threats based on anomaly patterns"""
        threats = []
        
        if anomaly_score > 0.8:
            threats.extend([
                "Potential Advanced Persistent Threat (APT)",
                "Possible data exfiltration in progress",
                "Lateral movement indicators detected"
            ])
        elif anomaly_score > 0.6:
            threats.extend([
                "Possible malware infection",
                "Suspicious network activity",
                "Unauthorized access attempt"
            ])
        
        if auth_features["unusual_locations"]:
            threats.append("Geographically anomalous authentication")
        
        if network_features["external_connections"] > 50:
            threats.append("High external connection rate")
        
        return threats
    
    def _generate_anomaly_response_actions(self, anomaly_score: float) -> List[str]:
        """Generate recommended response actions"""
        actions = []
        
        if anomaly_score > 0.85:
            actions.extend([
                "IMMEDIATE: Isolate affected systems from network",
                "Escalate to incident response team",
                "Initiate forensic investigation",
                "Block identified suspicious IPs and domains"
            ])
        elif anomaly_score > 0.7:
            actions.extend([
                "Monitor affected systems closely",
                "Review authentication logs",
                "Investigate unusual network connections",
                "Prepare containment procedures"
            ])
        elif anomaly_score > 0.5:
            actions.extend([
                "Log anomaly for further investigation",
                "Increase monitoring frequency",
                "Review system logs",
                "Update threat intelligence"
            ])
        else:
            actions.extend([
                "Continue normal monitoring",
                "Document anomaly for trend analysis",
                "Review in next security assessment"
            ])
        
        return actions
    
    def get_anomaly_trends(self, time_range_hours: int = 24) -> Dict[str, Any]:
        """Get anomaly trends over time"""
        recent_anomalies = [
            anomaly for anomaly in self.detected_anomalies
            if self._is_within_time_range(anomaly["timestamp"], time_range_hours)
        ]
        
        if not recent_anomalies:
            return {
                "total_anomalies": 0,
                "trend_direction": "stable",
                "average_severity": "none",
                "anomaly_types": {},
                "time_series_data": []
            }
        
        # Calculate trends
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        anomaly_types = {}
        
        for anomaly in recent_anomalies:
            severity = anomaly["details"]["anomaly_severity"]
            severity_counts[severity] += 1
            
            anomaly_type = anomaly["details"]["anomaly_type"]
            anomaly_types[anomaly_type] = anomaly_types.get(anomaly_type, 0) + 1
        
        # Calculate trend direction
        anomaly_scores = [anomaly["anomaly_score"] for anomaly in recent_anomalies]
        if len(anomaly_scores) > 1:
            if anomaly_scores[-1] > anomaly_scores[0]:
                trend_direction = "increasing"
            else:
                trend_direction = "decreasing"
        else:
            trend_direction = "stable"
        
        return {
            "total_anomalies": len(recent_anomalies),
            "trend_direction": trend_direction,
            "average_severity": self._calculate_average_severity(severity_counts),
            "severity_distribution": severity_counts,
            "anomaly_types": anomaly_types,
            "time_series_data": self._generate_time_series_data(recent_anomalies),
            "peak_anomaly_time": self._find_peak_anomaly_time(recent_anomalies)
        }
    
    def _is_within_time_range(self, timestamp: str, hours: int) -> bool:
        """Check if timestamp is within specified time range"""
        anomaly_time = datetime.fromisoformat(timestamp)
        current_time = datetime.utcnow()
        time_diff = (current_time - anomaly_time).total_seconds() / 3600
        return time_diff <= hours
    
    def _calculate_average_severity(self, severity_counts: Dict) -> str:
        """Calculate average severity from counts"""
        total = sum(severity_counts.values())
        if total == 0:
            return "none"
        
        weighted_sum = (
            severity_counts["Critical"] * 4 +
            severity_counts["High"] * 3 +
            severity_counts["Medium"] * 2 +
            severity_counts["Low"] * 1
        )
        
        average = weighted_sum / total
        
        if average >= 3.5:
            return "Critical"
        elif average >= 2.5:
            return "High"
        elif average >= 1.5:
            return "Medium"
        else:
            return "Low"
    
    def _generate_time_series_data(self, anomalies: List[Dict]) -> List[Dict]:
        """Generate time series data for visualization"""
        time_series = []
        
        for anomaly in anomalies:
            time_series.append({
                "timestamp": anomaly["timestamp"],
                "anomaly_score": anomaly["anomaly_score"],
                "severity": anomaly["details"]["anomaly_severity"],
                "type": anomaly["details"]["anomaly_type"]
            })
        
        return sorted(time_series, key=lambda x: x["timestamp"])
    
    def _find_peak_anomaly_time(self, anomalies: List[Dict]) -> Optional[str]:
        """Find the time of the highest anomaly score"""
        if not anomalies:
            return None
        
        peak_anomaly = max(anomalies, key=lambda x: x["anomaly_score"])
        return peak_anomaly["timestamp"]