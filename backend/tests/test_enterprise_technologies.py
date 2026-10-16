import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_swarm_agents_endpoint():
    response = client.get("/api/swarm/agents")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "agents" in data
    assert len(data["agents"]) == 5
    agent_names = [a["name"] for a in data["agents"]]
    assert any("Sentinel Alpha" in n for n in agent_names)
    assert any("Hunter Beta" in n for n in agent_names)
    assert any("Specter Gamma" in n for n in agent_names)

def test_swarm_orchestrate_consensus():
    payload = {
        "query": "Investigate suspicious Kerberoasting and beaconing",
        "target_ip": "185.220.101.45",
        "target_host": "WS-FIN-04"
    }
    response = client.post("/api/swarm/orchestrate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "orchestration_id" in data
    assert "swarm_verdict" in data
    assert len(data["agent_findings"]) == 5
    assert len(data["consensus_actions"]) >= 3

def test_stix_21_bundle_export():
    response = client.get("/api/stix/export?ip=185.220.101.45&technique=T1059.001")
    assert response.status_code == 200
    bundle = response.json()
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert "objects" in bundle
    types = [obj["type"] for obj in bundle["objects"]]
    assert "identity" in types
    assert "indicator" in types
    assert "threat-actor" in types
    assert "course-of-action" in types

def test_taxii_collections_and_publish():
    # Collections
    c_res = client.get("/api/stix/taxii/collections")
    assert c_res.status_code == 200
    assert len(c_res.json()["collections"]) >= 1

    # Publish
    p_res = client.post("/api/stix/taxii/publish", json={"indicator_ip": "185.220.101.45"})
    assert p_res.status_code == 200
    assert p_res.json()["status"] == "success"

def test_telemetry_stream_status():
    res = client.get("/api/telemetry/stream-status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "active"
    assert data["throughput_eps"] > 0
    assert "ws" in data["supported_protocols"]

def test_websocket_handshake():
    with client.websocket_connect("/ws/telemetry") as websocket:
        data = websocket.receive_json()
        assert data["type"] == "handshake"
        assert data["status"] == "connected"
        assert "SentinelAI" in data["server"]
