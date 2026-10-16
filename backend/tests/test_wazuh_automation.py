from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.log_collector.models import Alert
from app.wazuh_automation import WazuhAutomationWorker


class FakeWazuhServer:
    def __init__(self, alerts):
        self.alerts = alerts

    def get_alerts(self):
        return SimpleNamespace(status="success", data={"alerts": self.alerts}, details=None)


class FakeInvestigationService:
    def analyze_query(self, query):
        assert "failed login/authentication" in query
        return {
            "ai_answer": "Repeated failed authentication needs analyst review.",
            "report_json": {
                "severity": "High",
                "investigation_summary": "Wazuh detected repeated failed logins.",
                "tools_used": ["Wazuh"],
                "recommendations": ["Verify the source and affected account."],
            },
        }


def make_session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)


def test_matches_failed_authentication_alerts_across_all_groups():
    alert = {
        "id": "evt-1",
        "rule": {"description": "Multiple failed login attempts detected"},
        "agent": {"id": "007", "name": "workstation-7"},
    }

    assert WazuhAutomationWorker.is_failed_authentication(alert)


def test_matches_failed_password_log_entries():
    alert = {"id": "evt-2", "full_log": "Failed password for root from 203.0.113.9"}

    assert WazuhAutomationWorker.is_failed_authentication(alert)


def test_ignores_non_authentication_failures_and_sample_alerts():
    assert not WazuhAutomationWorker.is_failed_authentication({
        "id": "evt-3",
        "rule": {"description": "Failed software update"},
    })
    assert not WazuhAutomationWorker.is_failed_authentication({
        "id": "sample-1",
        "rule": {"description": "Failed login attempt"},
    })


def test_dry_run_actions_are_proposals_only():
    actions = WazuhAutomationWorker.build_dry_run_actions({
        "agent": {"id": "007", "name": "workstation-7"},
        "source_ip": "203.0.113.9",
    })

    assert {action["action"] for action in actions} == {
        "isolate_host",
        "block_source_ip",
        "disable_compromised_account",
    }
    assert all(action["execution"] == "not_executed" for action in actions)
    assert all(action["status"] in {"dry_run", "report_only"} for action in actions)


def test_run_once_persists_report_and_deduplicates_alerts():
    engine, session_factory = make_session_factory()
    alert = {
        "id": "evt-123",
        "rule": {"id": "5710", "level": 10, "description": "Failed password authentication"},
        "agent": {"id": "007", "name": "workstation-7"},
        "source_ip": "203.0.113.9",
        "full_log": "Failed password for operator",
    }
    worker = WazuhAutomationWorker(
        wazuh_server=FakeWazuhServer([alert]),
        investigation_service=FakeInvestigationService(),
        session_factory=session_factory,
    )

    first_run = worker.run_once()
    second_run = worker.run_once()

    with session_factory() as db:
        stored = db.query(Alert).filter(Alert.alert_id == "wazuh:evt-123").one()
        assert stored.status == "dry_run"
        assert stored.alert_metadata["processing_status"] == "completed"
        assert stored.alert_metadata["investigation"]["ai_answer"].startswith("Repeated failed")
        assert all(action["execution"] == "not_executed" for action in stored.alert_metadata["actions"])

    assert first_run["processed"] == 1
    assert second_run["processed"] == 0
    assert second_run["skipped_duplicates"] == 1
    engine.dispose()