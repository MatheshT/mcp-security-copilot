"""
Tests for new Cyber Range Simulator, SOAR Orchestration, and MITRE ATT&CK Matrix routes.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_get_simulator_scenarios():
    """Test retrieving available simulation scenarios"""
    response = client.get("/api/v2/simulator/scenarios")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["total_scenarios"] >= 5
    scenario_ids = [s["id"] for s in data["scenarios"]]
    assert "ransomware_lockbit" in scenario_ids
    assert "ad_kerberoast" in scenario_ids

def test_launch_simulation():
    """Test executing a live simulation scenario"""
    payload = {"scenario_id": "ransomware_lockbit", "auto_remediate": True}
    response = client.post("/api/v2/simulator/launch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "simulation_id" in data
    assert data["alerts_generated"] >= 4
    assert "threat_actor_attribution" in data
    assert "soar_remediation" in data
    assert "ai_soc_verdict" in data

def test_get_soar_actions_and_execute():
    """Test fetching SOAR actions and executing containment"""
    response = client.get("/api/v2/soar/actions")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["total_actions"] > 0

    # Test executing an action
    exec_payload = {"action_id": "SOAR-ACT-001", "approver": "Senior SOC Lead"}
    exec_res = client.post("/api/v2/soar/execute", json=exec_payload)
    assert exec_res.status_code == 200
    exec_data = exec_res.json()
    assert exec_data["status"] == "success"
    assert exec_data["action"]["status"] == "executed"

def test_get_mitre_matrix_and_coverage():
    """Test retrieving MITRE ATT&CK matrix and coverage metrics"""
    matrix_res = client.get("/api/v2/mitre/matrix")
    assert matrix_res.status_code == 200
    matrix_data = matrix_res.json()
    assert matrix_data["status"] == "success"
    assert matrix_data["total_tactics"] == 12
    assert matrix_data["total_active_detections"] > 0

    cov_res = client.get("/api/v2/mitre/coverage")
    assert cov_res.status_code == 200
    cov_data = cov_res.json()
    assert cov_data["status"] == "success"
    assert cov_data["coverage_percentage"] > 80
