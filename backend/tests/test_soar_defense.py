import pytest
from app.mcp.soar_server import SOARServer

def test_soar_server_initialization():
    server = SOARServer()
    assert server.name == "SOAR"
    assert "block_ip" in server.supported_features
    assert "isolate_host" in server.supported_features

def test_soar_block_ip():
    server = SOARServer()
    test_ip = "203.0.113.55"
    response = server.block_ip(test_ip)
    assert response.status == "success"
    assert response.data["status"] == "BLOCKED"
    assert response.data["ip"] == test_ip
    assert test_ip in server.blocked_ips

def test_soar_isolate_host():
    server = SOARServer()
    test_host = "ENDPOINT-DEV-09"
    response = server.isolate_host(test_host)
    assert response.status == "success"
    assert response.data["status"] == "ISOLATED"
    assert test_host in server.isolated_hosts

def test_soar_run_playbook():
    server = SOARServer()
    response = server.run_playbook("ransomware")
    assert response.status == "success"
    assert response.data["status"] == "COMPLETED"
    assert "Ransomware" in response.data["playbook"]

def test_soar_get_playbooks():
    server = SOARServer()
    response = server.get_playbooks()
    assert response.status == "success"
    assert len(response.data["available_playbooks"]) >= 4
