import asyncio

from app.llm_client import LLMClient
from app.log_collector.windows_log_collector import WindowsLogCollector
from app.soc_analyst.autonomous_analyst import AutonomousSOCAnalyst


def test_llm_client_accepts_config():
    client = LLMClient({"llm_provider": "free"})
    assert client.provider == "free"


def test_windows_log_collector_initializes():
    collector = WindowsLogCollector()
    assert "windows_event" in collector.log_sources
    assert "powershell" in collector.log_sources


def test_correlation_result_passes_threat_intel_to_risk_assessment():
    analyst = AutonomousSOCAnalyst.__new__(AutonomousSOCAnalyst)
    analyst.investigation_state = {"findings": {}, "risk_score": 0}
    threat_intel_result = {
        "threat_intel_analysis": {
            "correlation_analysis": {},
            "risk_assessment": {"overall_risk_score": 12, "risk_level": "low"},
        }
    }

    async def run_phases():
        correlation_result = await analyst._perform_correlation(threat_intel_result)
        risk_result = await analyst._assess_risk(correlation_result)
        return correlation_result, risk_result

    correlation_result, risk_result = asyncio.run(run_phases())

    assert correlation_result["threat_intel_analysis"] is threat_intel_result["threat_intel_analysis"]
    assert risk_result["risk_assessment"]["overall_risk_score"] == 12


def test_analyst_cleanup_does_not_call_missing_llm_close():
    analyst = AutonomousSOCAnalyst.__new__(AutonomousSOCAnalyst)

    class ThreatIntelStub:
        closed = False

        async def close(self):
            self.closed = True

    analyst.threat_intel_orchestrator = ThreatIntelStub()
    analyst.llm_client = LLMClient()

    asyncio.run(analyst.close())

    assert analyst.threat_intel_orchestrator.closed
