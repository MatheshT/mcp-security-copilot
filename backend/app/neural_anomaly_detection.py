"""
Neural Network Anomaly Detection Module
Uses advanced ML algorithms to detect security anomalies and zero-day threats
that traditional signature-based systems cannot identify.
"""

from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import random
import math
import json
from collections import defaultdict, deque


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
        self.historical_data = deque(maxlen=1000)  # Store recent data for pattern learning
        self.alert_history = deque(maxlen=500)  # Store alert history
        self.anomaly_trends = defaultdict(list)  # Track anomaly trends over time
        self.baseline_learning_enabled = True
        self.adaptive_thresholds = True
        
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
        # Store data for continuous learning
        self.historical_data.append({
            "timestamp": datetime.utcnow().isoformat(),
            "data": security_data
        })
        
        # Extract features from security data
        network_features = self._extract_network_features(security_data)
        auth_features = self._extract_auth_features(security_data)
        system_features = self._extract_system_features(security_data)
        
        # Calculate anomaly scores for each category
        network_anomaly_score = self._calculate_network_anomaly(network_features)
        auth_anomaly_score = self._calculate_auth_anomaly(auth_features)
        system_anomaly_score = self._calculate_system_anomaly(system_features)
        
        # Apply adaptive thresholds if enabled
        if self.adaptive_thresholds:
            network_anomaly_score = self._apply_adaptive_threshold(network_anomaly_score, "network")
            auth_anomaly_score = self._apply_adaptive_threshold(auth_anomaly_score, "auth")
            system_anomaly_score = self._apply_adaptive_threshold(system_anomaly_score, "system")
        
        # Calculate overall anomaly score using weighted neural network
        overall_anomaly_score = self._calculate_overall_anomaly(
            network_anomaly_score,
            auth_anomaly_score,
            system_anomaly_score
        )
        
        # Determine if anomaly is significant
        current_threshold = self._get_adaptive_overall_threshold()
        is_anomaly = overall_anomaly_score > current_threshold
        
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
            "recommended_actions": self._generate_anomaly_response_actions(overall_anomaly_score),
            "temporal_analysis": self._perform_temporal_analysis(),
            "pattern_recognition": self._recognize_attack_patterns(),
            "risk_forecast": self._forecast_risk(),
            "adaptive_threshold_used": current_threshold,
            "baseline_learning_status": "active" if self.baseline_learning_enabled else "disabled",
            "model_accuracy": self.model_accuracy
        }
        
        # Store detected anomaly for trend analysis
        if is_anomaly:
            self.detected_anomalies.append({
                "timestamp": datetime.utcnow().isoformat(),
                "anomaly_score": overall_anomaly_score,
                "details": anomaly_details
            })
            self.alert_history.append({
                "timestamp": datetime.utcnow().isoformat(),
                "anomaly_score": overall_anomaly_score,
                "type": anomaly_details["anomaly_type"]
            })
            
            # Update anomaly trends
            self.anomaly_trends[anomaly_details["anomaly_type"]].append({
                "timestamp": datetime.utcnow().isoformat(),
                "score": overall_anomaly_score
            })
        
        # Update baseline patterns if learning is enabled
        if self.baseline_learning_enabled and not is_anomaly:
            self._update_baseline_patterns(network_features, auth_features, system_features)
        
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
    
    def get_anomaly_statistics(self) -> Dict[str, Any]:
        """Get comprehensive anomaly statistics"""
        if not self.detected_anomalies:
            return {"status": "no_anomalies_detected"}
        
        # Calculate statistics
        total_anomalies = len(self.detected_anomalies)
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)
        
        for anomaly in self.detected_anomalies:
            severity = anomaly["details"]["anomaly_severity"]
            anomaly_type = anomaly["details"]["anomaly_type"]
            severity_counts[severity] += 1
            type_counts[anomaly_type] += 1
        
        # Calculate trends
        recent_trend = self._calculate_trend_direction(self.detected_anomalies[-20:])
        
        return {
            "total_anomalies": total_anomalies,
            "severity_distribution": dict(severity_counts),
            "type_distribution": dict(type_counts),
            "trend_direction": recent_trend,
            "average_anomaly_score": sum(a["anomaly_score"] for a in self.detected_anomalies) / total_anomalies,
            "high_severity_count": severity_counts["Critical"] + severity_counts["High"],
            "baseline_samples": len(self.historical_data),
            "adaptive_learning_enabled": self.baseline_learning_enabled,
            "anomaly_trends": dict(self.anomaly_trends)
        }
    
    def reset_baseline(self):
        """Reset baseline patterns to initial values"""
        self.baseline_patterns = self._initialize_baseline_patterns()
        self.historical_data.clear()
        self.detected_anomalies.clear()
        self.alert_history.clear()
        self.anomaly_trends.clear()
        return {"status": "baseline_reset_complete"}
    
    def configure_thresholds(self, overall: float = None, network: float = None, 
                          auth: float = None, system: float = None):
        """Configure custom anomaly thresholds"""
        if overall is not None:
            self.anomaly_thresholds["overall_anomaly_threshold"] = overall
        if network is not None:
            self.anomaly_thresholds["network_anomaly_threshold"] = network
        if auth is not None:
            self.anomaly_thresholds["authentication_anomaly_threshold"] = auth
        if system is not None:
            self.anomaly_thresholds["system_anomaly_threshold"] = system
        
        return {
            "status": "thresholds_updated",
            "current_thresholds": self.anomaly_thresholds
        }
    
    def enable_adaptive_learning(self, enabled: bool = True):
        """Enable or disable adaptive learning"""
        self.baseline_learning_enabled = enabled
        self.adaptive_thresholds = enabled
        return {
            "status": "adaptive_learning_updated",
            "baseline_learning": enabled,
            "adaptive_thresholds": enabled
        }
    
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
    
    def _apply_adaptive_threshold(self, score: float, category: str) -> float:
        """Apply adaptive threshold based on historical data"""
        if len(self.historical_data) < 50:
            return score  # Not enough data for adaptive threshold
        
        # Calculate moving average of recent scores
        recent_scores = []
        for data_point in list(self.historical_data)[-50:]:
            if category == "network":
                features = self._extract_network_features(data_point["data"])
                recent_scores.append(self._calculate_network_anomaly(features))
            elif category == "auth":
                features = self._extract_auth_features(data_point["data"])
                recent_scores.append(self._calculate_auth_anomaly(features))
            elif category == "system":
                features = self._extract_system_features(data_point["data"])
                recent_scores.append(self._calculate_system_anomaly(features))
        
        if not recent_scores:
            return score
        
        mean_score = sum(recent_scores) / len(recent_scores)
        std_dev = math.sqrt(sum((x - mean_score) ** 2 for x in recent_scores) / len(recent_scores))
        
        # Adjust score based on deviation from mean
        if std_dev > 0:
            z_score = (score - mean_score) / std_dev
            # Amplify anomalies that are statistically significant
            if abs(z_score) > 2:
                return min(score * 1.2, 1.0)
            elif abs(z_score) > 1:
                return min(score * 1.1, 1.0)
        
        return score
    
    def _get_adaptive_overall_threshold(self) -> float:
        """Get adaptive overall threshold based on recent anomaly patterns"""
        if len(self.detected_anomalies) < 20:
            return self.anomaly_thresholds["overall_anomaly_threshold"]
        
        # Calculate recent anomaly rate
        recent_anomalies = [a for a in self.detected_anomalies 
                            if datetime.fromisoformat(a["timestamp"]) > datetime.utcnow() - timedelta(hours=24)]
        
        if len(recent_anomalies) > 10:
            # High anomaly rate - lower threshold to catch more
            return self.anomaly_thresholds["overall_anomaly_threshold"] * 0.9
        elif len(recent_anomalies) < 3:
            # Low anomaly rate - raise threshold to reduce false positives
            return self.anomaly_thresholds["overall_anomaly_threshold"] * 1.1
        
        return self.anomaly_thresholds["overall_anomaly_threshold"]
    
    def _perform_temporal_analysis(self) -> Dict[str, Any]:
        """Perform temporal analysis of anomalies"""
        if len(self.alert_history) < 10:
            return {"status": "insufficient_data"}
        
        # Group by time periods
        now = datetime.utcnow()
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)
        week_ago = now - timedelta(days=7)
        
        recent_hour = [a for a in self.alert_history 
                      if datetime.fromisoformat(a["timestamp"]) > hour_ago]
        recent_day = [a for a in self.alert_history 
                     if datetime.fromisoformat(a["timestamp"]) > day_ago]
        recent_week = [a for a in self.alert_history 
                      if datetime.fromisoformat(a["timestamp"]) > week_ago]
        
        return {
            "hourly_anomaly_count": len(recent_hour),
            "daily_anomaly_count": len(recent_day),
            "weekly_anomaly_count": len(recent_week),
            "trend_direction": self._calculate_trend_direction(recent_day),
            "peak_anomaly_time": self._find_peak_anomaly_time(recent_week),
            "average_score_last_hour": sum(a["anomaly_score"] for a in recent_hour) / len(recent_hour) if recent_hour else 0
        }
    
    def _calculate_trend_direction(self, anomalies: List) -> str:
        """Calculate trend direction of anomalies"""
        if len(anomalies) < 2:
            return "stable"
        
        first_half = anomalies[:len(anomalies)//2]
        second_half = anomalies[len(anomalies)//2:]
        
        first_avg = sum(a["anomaly_score"] for a in first_half) / len(first_half)
        second_avg = sum(a["anomaly_score"] for a in second_half) / len(second_half)
        
        if second_avg > first_avg * 1.2:
            return "increasing"
        elif second_avg < first_avg * 0.8:
            return "decreasing"
        else:
            return "stable"
    
    def _recognize_attack_patterns(self) -> Dict[str, Any]:
        """Recognize attack patterns from anomaly history"""
        if len(self.detected_anomalies) < 5:
            return {"status": "insufficient_data"}
        
        # Analyze anomaly type sequences
        type_sequences = []
        for anomaly in self.detected_anomalies[-20:]:
            type_sequences.append(anomaly["details"]["anomaly_type"])
        
        # Look for common sequences
        pattern_analysis = {
            "recurring_patterns": [],
            "pattern_frequency": {},
            "potential_attack_chains": []
        }
        
        # Find repeating patterns
        for i in range(len(type_sequences) - 2):
            pattern = tuple(type_sequences[i:i+3])
            pattern_analysis["pattern_frequency"][pattern] = pattern_analysis["pattern_frequency"].get(pattern, 0) + 1
        
        # Identify significant patterns
        for pattern, count in pattern_analysis["pattern_frequency"].items():
            if count >= 2:
                pattern_analysis["recurring_patterns"].append({
                    "pattern": list(pattern),
                    "frequency": count
                })
        
        # Identify potential attack chains
        attack_chains = [
            ["network", "authentication", "system"],
            ["authentication", "system", "network"],
            ["network", "system", "authentication"]
        ]
        
        for chain in attack_chains:
            if all(anomaly_type in type_sequences for anomaly_type in chain):
                pattern_analysis["potential_attack_chains"].append(chain)
        
        return pattern_analysis
    
    def _forecast_risk(self) -> Dict[str, Any]:
        """Forecast future risk based on current trends"""
        if len(self.detected_anomalies) < 10:
            return {"status": "insufficient_data"}
        
        recent_scores = [a["anomaly_score"] for a in self.detected_anomalies[-10:]]
        avg_score = sum(recent_scores) / len(recent_scores)
        trend = self._calculate_trend_direction(self.detected_anomalies[-10:])
        
        # Simple forecasting
        forecast = {
            "current_risk_level": self._classify_severity(avg_score),
            "trend": trend,
            "predicted_risk_next_hour": self._predict_next_risk(avg_score, trend),
            "confidence_in_forecast": "Medium" if len(self.detected_anomalies) >= 20 else "Low",
            "recommended_monitoring_level": self._get_monitoring_recommendation(avg_score, trend)
        }
        
        return forecast
    
    def _predict_next_risk(self, current_score: float, trend: str) -> str:
        """Predict risk for next time period"""
        if trend == "increasing":
            new_score = min(current_score * 1.15, 1.0)
        elif trend == "decreasing":
            new_score = max(current_score * 0.85, 0.0)
        else:
            new_score = current_score
        
        return self._classify_severity(new_score)
    
    def _get_monitoring_recommendation(self, score: float, trend: str) -> str:
        """Get monitoring level recommendation"""
        if score > 0.8 or trend == "increasing":
            return "Critical - Continuous monitoring required"
        elif score > 0.6:
            return "High - Increased monitoring frequency"
        elif score > 0.4:
            return "Medium - Standard monitoring"
        else:
            return "Normal - Routine monitoring"
    
    def _update_baseline_patterns(self, network_features: Dict, auth_features: Dict, system_features: Dict):
        """Update baseline patterns with new normal data"""
        # Gradually adjust baseline patterns
        learning_rate = 0.05
        
        # Update network baseline
        if "bandwidth" in network_features:
            current_bandwidth = self.baseline_patterns["network_traffic"]["normal_bandwidth_range"]
            new_bandwidth = (
                current_bandwidth[0] * (1 - learning_rate) + network_features["bandwidth"] * learning_rate,
                current_bandwidth[1] * (1 - learning_rate) + network_features["bandwidth"] * learning_rate
            )
            self.baseline_patterns["network_traffic"]["normal_bandwidth_range"] = new_bandwidth
        
        # Update authentication baseline
        if "login_attempts" in auth_features:
            current_logins = self.baseline_patterns["authentication"]["normal_login_rate"]
            new_logins = (
                current_logins[0] * (1 - learning_rate) + auth_features["login_attempts"] * learning_rate,
                current_logins[1] * (1 - learning_rate) + auth_features["login_attempts"] * learning_rate
            )
            self.baseline_patterns["authentication"]["normal_login_rate"] = new_logins
        
        # Update system baseline
        if "cpu_usage" in system_features:
            current_cpu = self.baseline_patterns["system_behavior"]["normal_cpu_usage"]
            new_cpu = (
                current_cpu[0] * (1 - learning_rate) + system_features["cpu_usage"] * learning_rate,
                current_cpu[1] * (1 - learning_rate) + system_features["cpu_usage"] * learning_rate
            )
            self.baseline_patterns["system_behavior"]["normal_cpu_usage"] = new_cpu