from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel
from typing import Optional
import json

from app.investigation_service import InvestigationService
from app.schemas import ChatRequest
from app.predictive_analytics import PredictiveSecurityEngine
from app.collaborative_investigation import CollaborativeInvestigationPlatform
from app.blockchain_evidence import BlockchainEvidenceIntegrity
from app.neural_anomaly_detection import NeuralAnomalyDetector
from app.threat_actor_persona import ThreatActorPersonaEngine
from app.automated_response import AutomatedResponseOrchestrator

router = APIRouter(
    prefix="/api",
    tags=["investigation"]
)

service = InvestigationService()
predictive_engine = PredictiveSecurityEngine()
collaborative_platform = CollaborativeInvestigationPlatform()
blockchain_integrity = BlockchainEvidenceIntegrity()
neural_detector = NeuralAnomalyDetector()
persona_engine = ThreatActorPersonaEngine()
response_orchestrator = AutomatedResponseOrchestrator()


class InvestigationRequest(BaseModel):
    query: str


class CollaborativeSessionRequest(BaseModel):
    user_id: str
    investigation_data: dict


class InsightShareRequest(BaseModel):
    session_id: str
    user_id: str
    insight: dict


class DecisionRecordRequest(BaseModel):
    session_id: str
    user_id: str
    decision: dict


class EvidenceBlockRequest(BaseModel):
    evidence_data: dict
    investigator_id: str
    signature: str


class AnomalyDetectionRequest(BaseModel):
    security_data: dict


class PersonaAnalysisRequest(BaseModel):
    attack_data: dict


class AutomatedResponseRequest(BaseModel):
    incident_data: dict
    playbook_id: str
    auto_approve: bool = False


@router.post("/investigate")
async def investigate(req: InvestigationRequest):
    result = service.analyze_query(req.query)
    return result


@router.post("/chat")
async def chat(req: ChatRequest):
    user_query = req.query or req.message or ""
    result = service.analyze_query(user_query)
    return result


@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Upload and analyze files/images for security investigation.
    Supports: logs, images, screenshots, config files
    """
    content = await file.read()
    result = service.analyze_file_upload(file.filename, content)
    return result


# UNIQUE FEATURE: Predictive Analytics
@router.post("/predictive-analytics")
async def predictive_analytics(request: dict):
    """
    Generate predictive threat analytics using ML algorithms.
    Forecast future threats and calculate risk scores.
    """
    try:
        predictions = predictive_engine.predict_threat_probability(request)
        return {
            "status": "success",
            "predictions": predictions
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/security-posture")
async def security_posture():
    """
    Generate overall security posture score based on historical data.
    Provides comprehensive security health assessment.
    """
    try:
        # Get historical investigations (in real implementation, from database)
        investigations = []  # Placeholder
        
        posture = predictive_engine.generate_security_posture_score(investigations)
        return {
            "status": "success",
            "security_posture": posture
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# UNIQUE FEATURE: Collaborative Investigation
@router.post("/collaborative/session")
async def create_collaborative_session(req: CollaborativeSessionRequest):
    """
    Create a collaborative investigation session for team-based analysis.
    Enables real-time collaboration and collective intelligence.
    """
    try:
        session = collaborative_platform.create_investigation_session(
            req.user_id, 
            req.investigation_data
        )
        return {
            "status": "success",
            "session": session
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/collaborative/{session_id}/join")
async def join_collaborative_session(session_id: str, req: dict):
    """
    Join an existing collaborative investigation session.
    """
    try:
        result = collaborative_platform.add_participant(
            session_id, 
            req.get("user_id", "anonymous"),
            req.get("role", "analyst")
        )
        return {
            "status": "success",
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/collaborative/{session_id}/insight")
async def share_insight(session_id: str, req: InsightShareRequest):
    """
    Share a security insight with the investigation team.
    Insights are analyzed for relevance and added to collective intelligence.
    """
    try:
        result = collaborative_platform.share_insight(
            session_id, 
            req.user_id, 
            req.insight
        )
        return {
            "status": "success",
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/collaborative/{session_id}/decision")
async def record_decision(session_id: str, req: DecisionRecordRequest):
    """
    Record a security decision in the investigation decision log.
    Creates audit trail with reasoning and expected outcomes.
    """
    try:
        result = collaborative_platform.record_decision(
            session_id, 
            req.user_id, 
            req.decision
        )
        return {
            "status": "success",
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/collaborative/{session_id}/intelligence")
async def get_collective_intelligence(session_id: str):
    """
    Generate collective intelligence from team insights and decisions.
    Synthesizes team knowledge into actionable intelligence.
    """
    try:
        intelligence = collaborative_platform.generate_collective_intelligence(session_id)
        return {
            "status": "success",
            "collective_intelligence": intelligence
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# UNIQUE FEATURE: Blockchain Evidence Integrity
@router.post("/evidence/block")
async def create_evidence_block(req: EvidenceBlockRequest):
    """
    Create a blockchain evidence block for tamper-proof evidence handling.
    Ensures evidence integrity and authenticity for legal proceedings.
    """
    try:
        block = blockchain_integrity.create_evidence_block(
            req.evidence_data,
            req.investigator_id,
            req.signature
        )
        return {
            "status": "success",
            "block": block
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/evidence/{block_id}/verify")
async def verify_evidence(block_id: str):
    """
    Verify the integrity of evidence using blockchain technology.
    Ensures evidence has not been tampered with.
    """
    try:
        verification = blockchain_integrity.verify_evidence_integrity(block_id)
        return {
            "status": "success",
            "verification": verification
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/evidence/{block_id}/certificate")
async def generate_evidence_certificate(block_id: str):
    """
    Generate a cryptographically signed certificate for evidence.
    Suitable for legal proceedings and audits.
    """
    try:
        certificate = blockchain_integrity.generate_evidence_certificate(block_id)
        return {
            "status": "success",
            "certificate": certificate
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# UNIQUE FEATURE: Neural Anomaly Detection
@router.post("/anomaly-detection")
async def anomaly_detection(request: AnomalyDetectionRequest):
    """
    Detect security anomalies using neural network algorithms.
    Returns detailed anomaly analysis with confidence scores.
    """
    try:
        anomalies = neural_detector.detect_anomalies(request.security_data)
        return {
            "status": "success",
            "anomaly_details": anomalies
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# UNIQUE FEATURE: Threat Actor Persona Analysis
@router.post("/threat-actor-persona")
async def threat_actor_persona(request: PersonaAnalysisRequest):
    """
    Analyze threat actor persona based on attack data.
    Uses AI to create psychological and behavioral profiles.
    """
    try:
        persona = persona_engine.analyze_actor_persona(request.attack_data)
        return {
            "status": "success",
            "persona_analysis": persona
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# UNIQUE FEATURE: Automated Incident Response
@router.post("/automated-response")
async def automated_response(request: AutomatedResponseRequest):
    """
    Initiate automated incident response using AI-driven decision making.
    Automatically executes approved actions while requiring approval for critical ones.
    """
    try:
        response = response_orchestrator.initiate_automated_response(
            request.incident_data,
            request.playbook_id,
            request.auto_approve
        )
        return {
            "status": "success",
            "response": response
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/evidence/{block_id}/custody")
async def get_chain_of_custody(block_id: str):
    """
    Generate complete chain of custody for evidence.
    Shows every person who handled the evidence and when.
    """
    try:
        custody = blockchain_integrity.get_evidence_chain_of_custody(block_id)
        return {
            "status": "success",
            "chain_of_custody": custody
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# UNIQUE FEATURE: Neural Network Anomaly Detection
@router.post("/anomaly/detect")
async def detect_anomalies(req: AnomalyDetectionRequest):
    """
    Detect security anomalies using neural network algorithms.
    Identifies zero-day threats and patterns traditional systems miss.
    """
    try:
        anomalies = neural_detector.detect_anomalies(req.security_data)
        return {
            "status": "success",
            "anomaly_detection": anomalies
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/anomaly/trends")
async def get_anomaly_trends(time_range_hours: int = 24):
    """
    Get anomaly trends over time for pattern analysis.
    Provides insights into threat evolution.
    """
    try:
        trends = neural_detector.get_anomaly_trends(time_range_hours)
        return {
            "status": "success",
            "trends": trends
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# UNIQUE FEATURE: Threat Actor Persona Analysis
@router.post("/threat-actor/persona")
async def analyze_threat_actor_persona(req: PersonaAnalysisRequest):
    """
    Analyze threat actor persona using AI psychological profiling.
    Creates behavioral profiles and predicts future actions.
    """
    try:
        persona = persona_engine.analyze_actor_persona(req.attack_data)
        return {
            "status": "success",
            "persona_analysis": persona
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# UNIQUE FEATURE: Automated Incident Response
@router.post("/response/initiate")
async def initiate_automated_response(req: AutomatedResponseRequest):
    """
    Initiate automated incident response with AI-driven decision making.
    Executes containment actions while maintaining human oversight.
    """
    try:
        response = response_orchestrator.initiate_automated_response(
            req.incident_data,
            req.playbook_id,
            req.auto_approve
        )
        return {
            "status": "success",
            "automated_response": response
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/response/{response_id}/approve/{action_id}")
async def approve_action(response_id: str, action_id: str, req: dict):
    """
    Approve a pending automated response action.
    Allows human oversight of critical actions.
    """
    try:
        result = response_orchestrator.approve_pending_action(
            response_id,
            action_id,
            req.get("approver_id", "system")
        )
        return {
            "status": "success",
            "approval_result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/response/{response_id}/status")
async def get_response_status(response_id: str):
    """
    Get current status of automated incident response.
    Provides real-time monitoring of response progress.
    """
    try:
        status = response_orchestrator.get_response_status(response_id)
        return {
            "status": "success",
            "response_status": status
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/response/{response_id}/report")
async def generate_response_report(response_id: str):
    """
    Generate comprehensive incident response report.
    Includes effectiveness metrics and lessons learned.
    """
    try:
        report = response_orchestrator.generate_response_report(response_id)
        return {
            "status": "success",
            "response_report": report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))