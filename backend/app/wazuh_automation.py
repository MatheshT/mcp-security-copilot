"""Read-only automation for investigating failed Wazuh authentication alerts."""

import asyncio
import hashlib
import json
import logging
import os
import re
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from .database import SessionLocal
from .investigation_service import InvestigationService
from .log_collector.models import Alert, RiskLevel
from .mcp.wazuh_server import WazuhServer

logger = logging.getLogger(__name__)


class WazuhAutomationWorker:
    """Poll live Wazuh alerts and store dry-run AI investigations."""

    FAILED_AUTH_PATTERN = re.compile(
        r"(?:failed|failure|unsuccessful).{0,40}(?:login|logon|auth|password|credential)"
        r"|(?:login|logon|auth|password|credential).{0,40}(?:failed|failure|unsuccessful)",
        re.IGNORECASE,
    )

    def __init__(
        self,
        wazuh_server: Optional[Any] = None,
        investigation_service: Optional[Any] = None,
        session_factory: Any = SessionLocal,
        interval_seconds: int = 300,
        max_alerts_per_run: int = 10,
    ) -> None:
        self.wazuh_server = wazuh_server or WazuhServer()
        self.investigation_service = investigation_service or InvestigationService()
        self.session_factory = session_factory
        self.interval_seconds = max(30, interval_seconds)
        self.max_alerts_per_run = max(1, max_alerts_per_run)
        self.running = False
        self.last_run: Optional[str] = None
        self.last_result: Dict[str, Any] = {"status": "not_started"}
        self._run_lock = threading.Lock()

    @classmethod
    def is_failed_authentication(cls, alert: Dict[str, Any]) -> bool:
        """Match failed authentication events, excluding demo/sample records."""
        alert_id = str(alert.get("id") or alert.get("alert_id") or "")
        if alert_id.lower().startswith("sample-"):
            return False

        rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
        searchable_text = " ".join(
            str(value)
            for value in (
                rule.get("description"),
                rule.get("name"),
                alert.get("description"),
                alert.get("full_log"),
                alert.get("log"),
                alert.get("location"),
            )
            if value
        )
        return bool(cls.FAILED_AUTH_PATTERN.search(searchable_text))

    @staticmethod
    def _alert_key(alert: Dict[str, Any]) -> str:
        alert_id = alert.get("id") or alert.get("alert_id")
        if not alert_id:
            serialized = json.dumps(alert, sort_keys=True, default=str)
            alert_id = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return f"wazuh:{alert_id}"[:100]

    @staticmethod
    def _source_ip(alert: Dict[str, Any]) -> Optional[str]:
        raw = alert.get("raw") if isinstance(alert.get("raw"), dict) else {}
        value = alert.get("source_ip") or alert.get("src_ip") or raw.get("src_ip")
        return str(value) if value and str(value).upper() != "N/A" else None

    @staticmethod
    def _agent(alert: Dict[str, Any]) -> Dict[str, Any]:
        agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
        return {
            "id": agent.get("id") or alert.get("agent_id"),
            "name": agent.get("name") or alert.get("agent_name") or "unknown",
        }

    @staticmethod
    def _severity(alert: Dict[str, Any]) -> RiskLevel:
        rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
        try:
            level = int(rule.get("level", alert.get("level", 0)))
        except (TypeError, ValueError):
            level = 0
        if level >= 12:
            return RiskLevel.CRITICAL
        if level >= 8:
            return RiskLevel.HIGH
        if level >= 5:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @classmethod
    def build_dry_run_actions(cls, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Describe response actions without invoking any endpoint or firewall API."""
        agent = cls._agent(alert)
        source_ip = cls._source_ip(alert)
        actions = []

        if agent["id"]:
            actions.append({
                "action": "isolate_host",
                "target": agent,
                "status": "dry_run",
                "execution": "not_executed",
                "requires": "A configured Wazuh active-response command on the endpoint",
            })

        if source_ip:
            actions.append({
                "action": "block_source_ip",
                "target": source_ip,
                "status": "dry_run",
                "execution": "not_executed",
                "requires": "Windows Firewall active response configured through Wazuh on the endpoint",
            })

        actions.append({
            "action": "disable_compromised_account",
            "target": None,
            "status": "report_only",
            "execution": "not_executed",
            "requires": "An identity-provider integration and analyst verification",
        })
        return actions

    def run_once(self) -> Dict[str, Any]:
        """Poll live Wazuh alerts, investigate new failed-auth events, and persist results."""
        if not self._run_lock.acquire(blocking=False):
            return {"status": "already_running", "processed": 0}

        started_at = datetime.utcnow().isoformat() + "Z"
        try:
            response = self.wazuh_server.get_alerts()
            if getattr(response, "status", None) != "success":
                result = {
                    "status": "wazuh_unavailable",
                    "processed": 0,
                    "details": getattr(response, "details", None),
                    "checked_at": started_at,
                }
                self.last_run = started_at
                self.last_result = result
                return result

            payload = getattr(response, "data", {}) or {}
            alerts = payload.get("alerts", []) if isinstance(payload, dict) else []
            matches = [
                alert for alert in alerts
                if isinstance(alert, dict) and self.is_failed_authentication(alert)
            ]

            processed = []
            skipped = 0
            for alert in matches:
                outcome = self._process_alert(alert)
                if outcome.get("status") == "already_processed":
                    skipped += 1
                    continue
                processed.append(outcome)
                if len(processed) >= self.max_alerts_per_run:
                    break

            result = {
                "status": "success",
                "mode": "dry_run",
                "checked_at": started_at,
                "matched": len(matches),
                "processed": len(processed),
                "skipped_duplicates": skipped,
                "deferred": max(0, len(matches) - len(processed) - skipped),
                "results": processed,
            }
            self.last_run = started_at
            self.last_result = result
            return result
        except Exception as exc:
            logger.exception("Wazuh dry-run automation failed")
            result = {
                "status": "error",
                "processed": 0,
                "details": str(exc),
                "checked_at": started_at,
            }
            self.last_run = started_at
            self.last_result = result
            return result
        finally:
            self._run_lock.release()

    def _process_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        alert_key = self._alert_key(alert)
        rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
        agent = self._agent(alert)
        source_ip = self._source_ip(alert)
        metadata = {
            "automation_mode": "dry_run",
            "processing_status": "processing",
            "source": "live_wazuh_api",
            "actions": self.build_dry_run_actions(alert),
            "wazuh_alert": {
                "id": alert_key,
                "rule": rule,
                "agent": agent,
                "timestamp": alert.get("timestamp"),
                "source_ip": source_ip,
                "full_log": str(alert.get("full_log") or alert.get("log") or "")[:4000],
            },
        }

        with self.session_factory() as db:
            stored_alert = db.query(Alert).filter(Alert.alert_id == alert_key).first()
            if stored_alert and (stored_alert.alert_metadata or {}).get("processing_status") == "completed":
                return {"status": "already_processed", "alert_id": alert_key}

            if stored_alert is None:
                description = str(alert.get("full_log") or alert.get("log") or "")[:4000]
                stored_alert = Alert(
                    alert_id=alert_key,
                    title=str(rule.get("description") or rule.get("name") or "Failed authentication")[:255],
                    description=description,
                    severity=self._severity(alert),
                    alert_type="wazuh_failed_authentication",
                    source="Wazuh",
                    status="dry_run",
                    detection_rule=str(rule.get("id") or "unknown"),
                    iocs_involved=[source_ip] if source_ip else [],
                    affected_hosts=[agent["name"]] if agent["name"] != "unknown" else [],
                    alert_metadata=metadata,
                )
                db.add(stored_alert)
            else:
                stored_alert.alert_metadata = metadata
            db.commit()
            stored_id = stored_alert.id

        try:
            alert_id = str(alert.get("id") or alert.get("alert_id") or alert_key)
            report = self.investigation_service.analyze_query(
                f"Investigate failed login/authentication Wazuh alert {alert_id}"
            )
            if hasattr(report, "model_dump"):
                report_data = report.model_dump()
            elif hasattr(report, "dict"):
                report_data = report.dict()
            else:
                report_data = report if isinstance(report, dict) else {}

            report_json = report_data.get("report_json") or {}
            ai_answer = report_data.get("ai_answer") or "AI investigation did not return a narrative."
            result_data = {
                "processing_status": "completed",
                "automation_mode": "dry_run",
                "source": "live_wazuh_api",
                "completed_at": datetime.utcnow().isoformat() + "Z",
                "actions": metadata["actions"],
                "investigation": {
                    "ai_answer": str(ai_answer)[:12000],
                    "severity": report_json.get("severity"),
                    "summary": report_json.get("investigation_summary"),
                    "tools_used": report_json.get("tools_used", []),
                    "recommendations": report_json.get("recommendations", []),
                },
                "wazuh_alert": metadata["wazuh_alert"],
            }
            with self.session_factory() as db:
                stored_alert = db.query(Alert).filter(Alert.id == stored_id).first()
                if stored_alert:
                    stored_alert.status = "dry_run"
                    stored_alert.notes = str(ai_answer)[:12000]
                    stored_alert.alert_metadata = result_data
                    db.commit()

            return {"status": "completed", "alert_id": alert_key, **result_data}
        except Exception as exc:
            logger.exception("Failed to investigate Wazuh alert %s", alert_key)
            with self.session_factory() as db:
                stored_alert = db.query(Alert).filter(Alert.id == stored_id).first()
                if stored_alert:
                    metadata["processing_status"] = "failed"
                    metadata["error"] = str(exc)
                    stored_alert.alert_metadata = metadata
                    db.commit()
            return {"status": "failed", "alert_id": alert_key, "details": str(exc)}

    async def run_forever(self) -> None:
        """Poll Wazuh on a configurable interval until the application shuts down."""
        self.running = True
        logger.info("Starting Wazuh failed-authentication automation in dry-run mode")
        while self.running:
            await asyncio.to_thread(self.run_once)
            if self.running:
                await asyncio.sleep(self.interval_seconds)

    def stop(self) -> None:
        self.running = False


def create_wazuh_automation_worker() -> WazuhAutomationWorker:
    interval = int(os.getenv("WAZUH_AUTOMATION_INTERVAL_SECONDS", "300"))
    max_alerts = int(os.getenv("WAZUH_AUTOMATION_MAX_PER_RUN", "10"))
    return WazuhAutomationWorker(
        interval_seconds=interval,
        max_alerts_per_run=max_alerts,
    )


_worker: Optional[WazuhAutomationWorker] = None


def get_wazuh_automation_worker() -> WazuhAutomationWorker:
    global _worker
    if _worker is None:
        _worker = create_wazuh_automation_worker()
    return _worker