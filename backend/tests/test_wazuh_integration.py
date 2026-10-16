import importlib


def test_wazuh_definition_is_not_routed_as_live_telemetry():
    orchestrator_module = importlib.import_module("app.orchestrator_enhanced")

    class LLMStub:
        def generate_response(self, query, report):
            return "Wazuh is an open-source security monitoring platform."

    orchestrator = orchestrator_module.EnhancedSecurityCopilotOrchestrator.__new__(
        orchestrator_module.EnhancedSecurityCopilotOrchestrator
    )
    orchestrator.llm_client = LLMStub()

    result = orchestrator._generate_llm_only_response(
        "what is wazuh",
        {"intent": "tool_explanation", "query_type": "tool_explanation"},
        {},
    )

    assert result["ai_answer"] == "Wazuh is an open-source security monitoring platform."
    assert result["tool_responses"] == []


def test_wazuh_answer_uses_statistics_when_agent_list_is_missing():
    orchestrator_module = importlib.import_module("app.orchestrator_enhanced")
    orchestrator = orchestrator_module.EnhancedSecurityCopilotOrchestrator.__new__(
        orchestrator_module.EnhancedSecurityCopilotOrchestrator
    )

    answer = orchestrator._generate_wazuh_ai_answer(
        {
            "statistics": {
                "total_agents": 2,
                "active_agents": 2,
                "total_alerts": 0,
            }
        },
        "how many agents are connected",
    )

    assert "2" in answer
    assert "No Wazuh agents are currently configured or connected" not in answer


class DummyResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("request failed")

    def json(self):
        # If payload is a string (raw token), raise ValueError to trigger text parsing
        if isinstance(self._payload, str):
            raise ValueError("Not JSON")
        return self._payload
    
    @property
    def text(self):
        if isinstance(self._payload, str):
            return self._payload
        return str(self._payload)


def test_authenticate_uses_post_method_and_raw_token(monkeypatch):
    wazuh_server_module = importlib.import_module("app.mcp.wazuh_server")
    monkeypatch.setenv("WAZUH_URL", "https://192.168.56.101:55000")
    monkeypatch.setenv("WAZUH_USERNAME", "wazuh")
    monkeypatch.setenv("WAZUH_PASSWORD", "wazuh")

    calls = []

    def fake_post(url, headers=None, params=None, timeout=20, verify=False):
        calls.append(("POST", url, headers, params, verify))
        return DummyResponse("abc123")  # Raw token response

    monkeypatch.setattr(wazuh_server_module.requests, "post", fake_post)

    server = wazuh_server_module.WazuhServer()
    token = server._authenticate()

    assert token == "abc123"
    assert server.token == "abc123"
    assert calls[0][0] == "POST"
    assert calls[0][1].endswith("/security/user/authenticate?raw=true")


def test_get_agents_with_affected_items_format(monkeypatch):
    wazuh_server_module = importlib.import_module("app.mcp.wazuh_server")
    monkeypatch.setenv("WAZUH_URL", "https://192.168.56.101:55000")
    monkeypatch.setenv("WAZUH_USERNAME", "wazuh")
    monkeypatch.setenv("WAZUH_PASSWORD", "wazuh")

    def fake_post(url, headers=None, params=None, timeout=20, verify=False):
        if "authenticate" in url:
            return DummyResponse("fake_jwt_token")
        raise AssertionError(f"Unexpected POST URL: {url}")

    def fake_get(url, headers=None, params=None, timeout=20, verify=False):
        if url.endswith("/agents"):
            # Return real Wazuh API response format
            return DummyResponse({
                "data": {
                    "affected_items": [
                        {"id": "000", "name": "wazuh-server", "status": "active"},
                        {"id": "002", "name": "Windows11", "status": "active", "ip": "192.168.56.1", "group": "default", "version": "Wazuh v4.14.7"}
                    ],
                    "total_affected_items": 2,
                    "total_failed_items": 0,
                    "failed_items": []
                },
                "message": "Agents retrieved successfully",
                "error": 0
            })
        raise AssertionError(f"Unexpected GET URL: {url}")

    monkeypatch.setattr(wazuh_server_module.requests, "post", fake_post)
    monkeypatch.setattr(wazuh_server_module.requests, "get", fake_get)

    server = wazuh_server_module.WazuhServer()
    agents_result = server.get_agents()

    assert agents_result.status == "success"
    agents = agents_result.data["agents"]
    assert len(agents) == 2
    assert agents[0]["id"] == "000"
    assert agents[0]["name"] == "wazuh-server"
    assert agents[0]["status"] == "active"
    
    # Verify agent 002 / Windows11 exists and is active
    agent_002 = next((a for a in agents if a["id"] == "002"), None)
    assert agent_002 is not None
    assert agent_002["name"] == "Windows11"
    assert agent_002["status"] == "active"


def test_real_alerts_no_synthetic(monkeypatch):
    wazuh_server_module = importlib.import_module("app.mcp.wazuh_server")
    monkeypatch.setenv("WAZUH_URL", "https://192.168.56.101:55000")
    monkeypatch.setenv("WAZUH_USERNAME", "wazuh")
    monkeypatch.setenv("WAZUH_PASSWORD", "wazuh")

    def fake_post(url, headers=None, params=None, timeout=20, verify=False):
        if "authenticate" in url:
            return DummyResponse("fake_jwt_token")
        raise AssertionError(f"Unexpected POST URL: {url}")

    def fake_get(url, headers=None, params=None, timeout=20, verify=False):
        # Simulate no real alerts available
        if url.endswith("/security/events"):
            # Return empty response
            return DummyResponse({
                "data": {
                    "affected_items": [],
                    "total_affected_items": 0,
                    "total_failed_items": 0,
                    "failed_items": []
                },
                "message": "No events found",
                "error": 0
            })
        raise AssertionError(f"Unexpected GET URL: {url}")

    monkeypatch.setattr(wazuh_server_module.requests, "post", fake_post)
    monkeypatch.setattr(wazuh_server_module.requests, "get", fake_get)

    server = wazuh_server_module.WazuhServer()
    alerts_result = server.get_alerts()

    assert alerts_result.status == "success"
    alerts = alerts_result.data["alerts"]
    # Should return empty list, not synthetic alerts
    assert len(alerts) == 0
    assert "No security alerts detected" in alerts_result.details


def test_get_alerts_no_wazuh_server_returns_empty_success(monkeypatch):
    wazuh_server_module = importlib.import_module("app.mcp.wazuh_server")
    monkeypatch.delenv("WAZUH_URL", raising=False)
    monkeypatch.delenv("WAZUH_API_URL", raising=False)
    monkeypatch.delenv("WAZUH_USERNAME", raising=False)
    monkeypatch.delenv("WAZUH_PASSWORD", raising=False)

    server = wazuh_server_module.WazuhServer()
    alerts_result = server.get_alerts()

    assert alerts_result.status == "success"
    assert alerts_result.data["alerts"] == []
    assert "Wazuh not configured" in alerts_result.details


def test_real_alerts_with_security_events(monkeypatch):
    wazuh_server_module = importlib.import_module("app.mcp.wazuh_server")
    monkeypatch.setenv("WAZUH_URL", "https://192.168.56.101:55000")
    monkeypatch.setenv("WAZUH_USERNAME", "wazuh")
    monkeypatch.setenv("WAZUH_PASSWORD", "wazuh")

    def fake_post(url, headers=None, params=None, timeout=20, verify=False):
        if "authenticate" in url:
            return DummyResponse("fake_jwt_token")
        raise AssertionError(f"Unexpected POST URL: {url}")

    def fake_get(url, headers=None, params=None, timeout=20, verify=False):
        if url.endswith("/security/events"):
            # Return real Wazuh security events
            return DummyResponse({
                "data": {
                    "affected_items": [
                        {
                            "id": "123456789",
                            "rule": {
                                "id": "1001",
                                "level": 10,
                                "description": "SSH login attempt",
                                "name": "SSH Brute Force"
                            },
                            "agent": {
                                "id": "002",
                                "name": "Windows11"
                            },
                            "timestamp": "2026-08-08T10:15:30Z",
                            "src_ip": "192.168.1.100",
                            "dst_ip": "192.168.56.1",
                            "full_log": "SSH login from 192.168.1.100 to 192.168.56.1",
                            "mitre": {
                                "tactic": "Credential Access",
                                "technique": "T1110"
                            }
                        }
                    ],
                    "total_affected_items": 1,
                    "total_failed_items": 0,
                    "failed_items": []
                },
                "message": "Events retrieved successfully",
                "error": 0
            })
        raise AssertionError(f"Unexpected GET URL: {url}")

    monkeypatch.setattr(wazuh_server_module.requests, "post", fake_post)
    monkeypatch.setattr(wazuh_server_module.requests, "get", fake_get)

    server = wazuh_server_module.WazuhServer()
    alerts_result = server.get_alerts()

    assert alerts_result.status == "success"
    alerts = alerts_result.data["alerts"]
    assert len(alerts) == 1
    assert alerts[0]["id"] == "123456789"
    assert alerts[0]["rule"]["level"] == 10
    assert alerts[0]["rule"]["description"] == "SSH login attempt"
    assert alerts[0]["agent"]["name"] == "Windows11"
    assert alerts[0]["source_ip"] == "192.168.1.100"
    assert alerts[0]["destination_ip"] == "192.168.56.1"
    assert "real Wazuh security alerts" in alerts_result.details