from types import SimpleNamespace

from app.llm_client import LLMClient
from app.orchestrator_enhanced import EnhancedSecurityCopilotOrchestrator


def test_collect_logs_routes_to_windows_log_collection():
    result = LLMClient().get_intent_and_tools("coolect logs")

    assert result["required_tools"] == ["WindowsLogs"]
    assert result["tool_commands"]["WindowsLogs"] == [
        "get_security_events",
        "get_system_events",
        "get_application_events",
    ]


def test_start_investigation_routes_to_wazuh_and_endpoint_logs():
    result = LLMClient().get_intent_and_tools("start investgation")

    assert result["required_tools"] == ["Wazuh", "WindowsLogs"]
    assert result["tool_commands"]["Wazuh"] == [
        "get_alerts",
        "get_agents",
        "get_statistics",
    ]


def test_windows_log_collection_unwraps_event_payloads():
    events_by_query = {
        "get_security_events": [{"event_id": "security-1"}],
        "get_system_events": [{"event_id": "system-1"}],
        "get_application_events": [{"event_id": "application-1"}],
    }

    class MCPStub:
        def call_tool(self, _tool_name, query):
            return SimpleNamespace(
                data={"events": events_by_query[query], "total_count": 1},
                status="success",
                details="Retrieved 1 event.",
            )

    orchestrator = EnhancedSecurityCopilotOrchestrator.__new__(EnhancedSecurityCopilotOrchestrator)
    orchestrator.mcp_client = MCPStub()
    extracted_data = {"windows_logs_data": {}, "tool_usage_log": []}

    orchestrator._execute_windows_logs({}, extracted_data, {})

    assert extracted_data["windows_logs_data"]["security_events"] == events_by_query["get_security_events"]
    assert extracted_data["windows_logs_data"]["system_events"] == events_by_query["get_system_events"]
    assert extracted_data["windows_logs_data"]["application_events"] == events_by_query["get_application_events"]
    log_report = orchestrator._format_windows_logs_results(extracted_data)
    assert "Security Events**: 1" in log_report
    assert "Application Events**: 1" in log_report


def test_log_collection_summary_does_not_claim_wazuh_was_queried():
    orchestrator = EnhancedSecurityCopilotOrchestrator.__new__(EnhancedSecurityCopilotOrchestrator)

    summary = orchestrator._generate_investigation_summary({
        "tool_usage_log": [{"tool": "WindowsLogs", "status": "completed"}],
        "windows_logs_data": {
            "security_events": [],
            "system_events": [{"event_id": "system-1"}],
            "application_events": [],
        },
    })

    assert "Collected 1 Windows events" in summary
    assert "Wazuh analyzed" not in summary