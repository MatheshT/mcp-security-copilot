"""
Enterprise ML Threat Detection & UEBA Router
FastAPI routes for machine-learning-driven security telemetry inference.
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from ..services.ml_engine import ml_engine

router = APIRouter(prefix="/ml", tags=["Machine Learning Threat Detection"])


class SecurityEventInput(BaseModel):
    rule_level: Optional[float] = Field(default=4.0, description="Wazuh rule level (1-16)")
    frequency: Optional[float] = Field(default=1.0, description="Frequency in last 5 minutes")
    port_entropy: Optional[float] = Field(default=0.8, description="Port distribution entropy")
    payload_length: Optional[float] = Field(default=120.0, description="Character length of raw log")
    full_log: Optional[str] = Field(default="", description="Raw command line or log text")
    hour: Optional[int] = Field(default=None, description="Hour of the day (0-23)")
    user: Optional[str] = Field(default="admin", description="Account or identity name")
    failed_ratio: Optional[float] = Field(default=0.05, description="Failed logon attempts ratio")
    outbound_conn_count: Optional[float] = Field(default=1.0, description="Outbound socket connection count")
    agent_name: Optional[str] = Field(default="wazuh-agent-01", description="Host or agent name")


class RetrainInput(BaseModel):
    sample_count: Optional[int] = Field(default=1500, description="Sample count for baseline retrain")


@router.post("/detect-anomaly", summary="Run IsolationForest Anomaly Inference")
async def detect_anomaly(event: SecurityEventInput):
    """
    Executes unsupervised Isolation Forest anomaly detection on security event vectors.
    Returns anomaly status, risk index (0-100), and driving risk factors.
    """
    try:
        data = event.model_dump()
        result = ml_engine.predict_anomaly(data)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/predict-severity", summary="Run Random Forest Triage & False-Positive Estimation")
async def predict_severity(event: SecurityEventInput):
    """
    Predicts alert severity (LOW, MEDIUM, HIGH, CRITICAL) and evaluates false-positive probability.
    """
    try:
        data = event.model_dump()
        result = ml_engine.predict_severity(data)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze-ueba", summary="Analyze User & Entity Behavioral Baseline Drift")
async def analyze_ueba(event: SecurityEventInput):
    """
    Performs User and Entity Behavior Analytics (UEBA) against established baselines.
    """
    try:
        data = event.model_dump()
        result = ml_engine.analyze_ueba(data)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/model-stats", summary="Get ML Architecture & Health Telemetry")
async def get_model_stats():
    """
    Returns architecture specifications, feature importances, and status of the ML models.
    """
    try:
        metrics = ml_engine.get_metrics()
        return {"status": "success", "metrics": metrics}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/recent-anomalies", summary="Get Recent Detected Machine Learning Anomalies")
async def get_recent_anomalies():
    """
    Fetches the rolling memory buffer of significant anomalies flagged by the ML engine.
    """
    return {
        "status": "success",
        "count": len(ml_engine.recent_anomalies),
        "anomalies": ml_engine.recent_anomalies
    }


@router.post("/retrain", summary="Trigger Background Model Retraining")
async def retrain_models(param: RetrainInput):
    """
    Retrains the IsolationForest and RandomForest models on updated enterprise baselines.
    """
    try:
        ml_engine._bootstrap_models()
        return {
            "status": "success",
            "message": "ML models successfully retrained on updated baseline telemetry.",
            "metrics": ml_engine.get_metrics()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
