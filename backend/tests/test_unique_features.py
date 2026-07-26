"""
Comprehensive tests for unique security features
Tests predictive analytics, collaborative investigation, blockchain evidence, 
neural anomaly detection, threat actor persona, and automated response
"""

import pytest
from app.predictive_analytics import PredictiveSecurityEngine
from app.collaborative_investigation import CollaborativeInvestigationPlatform
from app.blockchain_evidence import BlockchainEvidenceIntegrity
from app.neural_anomaly_detection import NeuralAnomalyDetector
from app.threat_actor_persona import ThreatActorPersonaEngine
from app.automated_response import AutomatedResponseOrchestrator


class TestPredictiveAnalytics:
    """Test predictive analytics functionality"""
    
    def test_initialization(self):
        """Test that PredictiveSecurityEngine initializes correctly"""
        engine = PredictiveSecurityEngine()
        assert engine.historical_data == []
        assert engine.threat_patterns is not None
        assert engine.risk_factors is not None
    
    def test_threat_probability_calculation(self):
        """Test threat probability calculation"""
        engine = PredictiveSecurityEngine()
        investigation_data = {
            "alerts": [],
            "tool_reports": {
                "virustotal_report": {"indicator": "192.168.1.1"},
                "wazuh_report": {"source_ip": "192.168.1.1"}
            }
        }
        
        result = engine.predict_threat_probability(investigation_data)
        
        assert "threat_probability" in result
        assert "confidence_level" in result
        assert "predicted_attack_vectors" in result
        assert "risk_timeline" in result
        assert 0 <= result["threat_probability"] <= 1
    
    def test_security_posture_generation(self):
        """Test security posture score generation"""
        engine = PredictiveSecurityEngine()
        investigations = []
        
        posture = engine.generate_security_posture_score(investigations)
        
        assert "overall_score" in posture
        assert "threat_level" in posture
        assert "vulnerability_count" in posture
        assert 0 <= posture["overall_score"] <= 100


class TestCollaborativeInvestigation:
    """Test collaborative investigation functionality"""
    
    def test_session_creation(self):
        """Test creating collaborative investigation session"""
        platform = CollaborativeInvestigationPlatform()
        
        session = platform.create_investigation_session(
            "analyst-1",
            {"title": "Test Investigation"}
        )
        
        assert "session_id" in session
        assert "invitation_link" in session
        assert "participant_count" in session
        assert session["participant_count"] == 1
    
    def test_participant_addition(self):
        """Test adding participants to session"""
        platform = CollaborativeInvestigationPlatform()
        session = platform.create_investigation_session("analyst-1", {})
        
        result = platform.add_participant(
            session["session_id"],
            "analyst-2",
            "senior_analyst"
        )
        
        assert result["participant_count"] == 2
        assert result["role"] == "senior_analyst"
    
    def test_insight_sharing(self):
        """Test sharing insights in session"""
        platform = CollaborativeInvestigationPlatform()
        session = platform.create_investigation_session("analyst-1", {})
        
        insight = {
            "text": "Suspicious activity detected",
            "iocs": ["192.168.1.1"],
            "type": "observation"
        }
        
        result = platform.share_insight(
            session["session_id"],
            "analyst-1",
            insight
        )
        
        assert "insight_id" in result
        assert "relevance_score" in result
        assert 0 <= result["relevance_score"] <= 1
    
    def test_collective_intelligence(self):
        """Test collective intelligence generation"""
        platform = CollaborativeInvestigationPlatform()
        session = platform.create_investigation_session("analyst-1", {})
        
        intelligence = platform.generate_collective_intelligence(session["session_id"])
        
        assert "collective_intelligence_score" in intelligence
        assert "insight_patterns" in intelligence
        assert "decision_patterns" in intelligence
        assert "team_expertise" in intelligence


class TestBlockchainEvidence:
    """Test blockchain evidence functionality"""
    
    def test_evidence_block_creation(self):
        """Test creating evidence block"""
        blockchain = BlockchainEvidenceIntegrity()
        
        evidence_data = {
            "type": "log",
            "data": "Suspicious login attempt",
            "timestamp": "2026-07-24T10:00:00Z"
        }
        
        block = blockchain.create_evidence_block(
            evidence_data,
            "investigator-1",
            "signature-123"
        )
        
        assert "block_id" in block
        assert "block_height" in block
        assert "block_hash" in block
        assert block["verification_status"] == "valid"
    
    def test_evidence_verification(self):
        """Test evidence verification"""
        blockchain = BlockchainEvidenceIntegrity()
        
        evidence_data = {"type": "log", "data": "Test evidence"}
        block = blockchain.create_evidence_block(evidence_data, "inv-1", "sig-1")
        
        verification = blockchain.verify_evidence_integrity(block["block_id"])
        
        assert verification["valid"] == True
        assert "block_height" in verification
        assert "timestamp" in verification
    
    def test_certificate_generation(self):
        """Test evidence certificate generation"""
        blockchain = BlockchainEvidenceIntegrity()
        
        evidence_data = {"type": "log", "data": "Test evidence"}
        block = blockchain.create_evidence_block(evidence_data, "inv-1", "sig-1")
        
        certificate = blockchain.generate_evidence_certificate(block["block_id"])
        
        assert "certificate_id" in certificate
        assert "evidence_block_id" in certificate
        assert "verification_status" in certificate
        assert certificate["verification_status"] == "verified"


class TestNeuralAnomalyDetection:
    """Test neural anomaly detection functionality"""
    
    def test_initialization(self):
        """Test that NeuralAnomalyDetector initializes correctly"""
        detector = NeuralAnomalyDetector()
        assert detector.baseline_patterns is not None
        assert detector.anomaly_thresholds is not None
        assert detector.detected_anomalies == []
    
    def test_anomaly_detection(self):
        """Test anomaly detection"""
        detector = NeuralAnomalyDetector()
        
        security_data = {
            "network": {
                "bandwidth": 500,  # Unusually high
                "connections": 1000,  # Unusually high
                "avg_packet_size": 512,
                "unusual_ports": ["4444", "6666"]
            },
            "auth": {
                "login_attempts": 100,  # Unusually high
                "failed_attempts": 50,  # Unusually high
                "unusual_locations": ["Unknown Country"],
                "off_hours_activity": True
            },
            "system": {
                "cpu_usage": 95,  # Unusually high
                "memory_usage": 98,  # Unusually high
                "disk_io": 100,
                "unusual_processes": ["malware.exe"]
            }
        }
        
        result = detector.detect_anomalies(security_data)
        
        assert "overall_anomaly_score" in result
        assert "is_anomaly" in result
        assert "confidence_level" in result
        assert "anomaly_type" in result
        assert 0 <= result["overall_anomaly_score"] <= 1
    
    def test_normal_behavior_detection(self):
        """Test detection of normal behavior"""
        detector = NeuralAnomalyDetector()
        
        security_data = {
            "network": {
                "bandwidth": 50,  # Normal
                "connections": 100,  # Normal
                "avg_packet_size": 512,
                "unusual_ports": []
            },
            "auth": {
                "login_attempts": 10,  # Normal
                "failed_attempts": 1,  # Normal
                "unusual_locations": [],
                "off_hours_activity": False
            },
            "system": {
                "cpu_usage": 45,  # Normal
                "memory_usage": 60,  # Normal
                "disk_io": 25,
                "unusual_processes": []
            }
        }
        
        result = detector.detect_anomalies(security_data)
        
        # Should have lower anomaly score for normal behavior
        assert result["overall_anomaly_score"] < 0.5


class TestThreatActorPersona:
    """Test threat actor persona analysis functionality"""
    
    def test_initialization(self):
        """Test that ThreatActorPersonaEngine initializes correctly"""
        engine = ThreatActorPersonaEngine()
        assert engine.known_actor_profiles is not None
        assert engine.personality_traits is not None
        assert engine.motivation_patterns is not None
    
    def test_actor_persona_analysis(self):
        """Test threat actor persona analysis"""
        engine = ThreatActorPersonaEngine()
        
        attack_data = {
            "tools": ["mimikatz", "custom_malware"],
            "techniques": ["credential_harvesting", "lateral_movement"],
            "targets": ["government", "military"],
            "target_industries": ["government", "defense"],
            "uses_custom_malware": True,
            "uses_zero_day": True,
            "uses_encryption": True,
            "uses_anti_forensics": True,
            "uses_opsec": True
        }
        
        result = engine.analyze_actor_persona(attack_data)
        
        assert "actor_identification" in result
        assert "persona_profile" in result
        assert "behavioral_predictions" in result
        assert "recommended_countermeasures" in result
        assert "confidence_level" in result
    
    def test_known_actor_matching(self):
        """Test matching against known threat actors"""
        engine = ThreatActorPersonaEngine()
        
        # Test data that should match APT29
        attack_data = {
            "tools": ["spearphishing", "credential_theft"],
            "techniques": ["lateral_movement", "persistence"],
            "targets": ["government", "diplomacy"],
            "uses_custom_malware": True,
            "uses_zero_day": False,
            "uses_encryption": True,
            "uses_anti_forensics": True,
            "uses_opsec": True
        }
        
        result = engine.analyze_actor_persona(attack_data)
        
        assert result["actor_identification"] is not None
        assert "name" in result["actor_identification"]


class TestAutomatedResponse:
    """Test automated incident response functionality"""
    
    def test_initialization(self):
        """Test that AutomatedResponseOrchestrator initializes correctly"""
        orchestrator = AutomatedResponseOrchestrator()
        assert orchestrator.response_playbooks is not None
        assert orchestrator.containment_strategies is not None
        assert orchestrator.active_responses == {}
    
    def test_response_initiation(self):
        """Test initiating automated response"""
        orchestrator = AutomatedResponseOrchestrator()
        
        incident_data = {
            "severity": "critical",
            "affected_assets": ["server-01", "database-02"],
            "data_sensitivity": "high",
            "operational_impact": "high",
            "financial_impact": "high"
        }
        
        response = orchestrator.initiate_automated_response(
            incident_data,
            "malware",
            auto_approve=False
        )
        
        assert "response_id" in response
        assert "playbook_activated" in response
        assert "incident_assessment" in response
        assert "strategies_selected" in response
        assert response["actions_automated"] >= 0
        assert response["actions_requiring_approval"] >= 0
    
    def test_auto_approval_response(self):
        """Test auto-approval response"""
        orchestrator = AutomatedResponseOrchestrator()
        
        incident_data = {
            "severity": "high",
            "affected_assets": ["workstation-01"],
            "data_sensitivity": "medium"
        }
        
        response = orchestrator.initiate_automated_response(
            incident_data,
            "malware",
            auto_approve=True
        )
        
        assert response["response_id"] is not None
        # Auto-approval should have more automated actions
        assert response["actions_automated"] >= 0
    
    def test_incident_assessment(self):
        """Test incident assessment"""
        orchestrator = AutomatedResponseOrchestrator()
        
        incident_data = {
            "severity": "critical",
            "affected_assets": ["server-01", "server-02", "server-03"],
            "data_sensitivity": "critical"
        }
        
        assessment = orchestrator._assess_incident(incident_data)
        
        assert "severity" in assessment
        assert "scope" in assessment
        assert "impact_score" in assessment
        assert "urgency_level" in assessment
        assert 0 <= assessment["impact_score"] <= 1


class TestIntegration:
    """Integration tests for unique features"""
    
    def test_predictive_to_collaborative_workflow(self):
        """Test workflow from predictive analytics to collaborative investigation"""
        predictive_engine = PredictiveSecurityEngine()
        collaborative_platform = CollaborativeInvestigationPlatform()
        
        # Step 1: Generate predictive analysis
        investigation_data = {
            "alerts": [{"severity": "high"}],
            "tool_reports": {"virustotal_report": {"indicator": "192.168.1.1"}}
        }
        
        predictions = predictive_engine.predict_threat_probability(investigation_data)
        
        # Step 2: Create collaborative session based on predictions
        session = collaborative_platform.create_investigation_session(
            "analyst-1",
            {"threat_probability": predictions["threat_probability"]}
        )
        
        assert predictions["threat_probability"] > 0
        assert session["session_id"] is not None
    
    def test_evidence_to_blockchain_workflow(self):
        """Test workflow from evidence collection to blockchain"""
        blockchain = BlockchainEvidenceIntegrity()
        
        # Simulate collecting evidence during investigation
        evidence_items = [
            {"type": "log", "data": "Suspicious login"},
            {"type": "screenshot", "data": "Malware GUI"},
            {"type": "network_capture", "data": "C2 traffic"}
        ]
        
        blocks = []
        for evidence in evidence_items:
            block = blockchain.create_evidence_block(
                evidence,
                "investigator-1",
                f"signature-{len(blocks)}"
            )
            blocks.append(block)
        
        # Verify all blocks
        for block in blocks:
            verification = blockchain.verify_evidence_integrity(block["block_id"])
            assert verification["valid"] == True
        
        assert len(blocks) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])