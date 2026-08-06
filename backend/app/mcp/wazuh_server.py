import os
from typing import Any, Dict, Optional

import requests
from requests.auth import HTTPBasicAuth

from .tool_server import BaseMCPServer, ToolRequest, ToolResponse


class WazuhServer(BaseMCPServer):
    name = "Wazuh"
    description = "Wazuh Security Monitoring Server"
    supported_features = [
        "get_alerts",
        "get_endpoint_info",
        "get_active_events",
    ]

    def __init__(self):
        super().__init__()

        self.base_url = os.getenv("WAZUH_API_URL") or os.getenv("WAZUH_URL")
        self.api_key = os.getenv("WAZUH_API_KEY") or os.getenv("WAZUH_TOKEN")
        self.username = os.getenv("WAZUH_USERNAME")
        self.password = os.getenv("WAZUH_PASSWORD")
        self.token: Optional[str] = None

    def _headers(self):
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        elif self.username and self.password:
            token = self._authenticate()
            if token:
                headers["Authorization"] = f"Bearer {token}"
        return headers

    def _auth(self):
        if self.api_key:
            return None
        if self.username and self.password and not self.token:
            return HTTPBasicAuth(self.username, self.password)
        return None

    def _authenticate(self) -> Optional[str]:
        if self.api_key:
            return self.api_key
        if self.token:
            return self.token

        if not self.username or not self.password:
            return None

        auth_url = f"{self.base_url.rstrip('/')}/security/user/authenticate"
        response = requests.post(
            auth_url,
            json={"username": self.username, "password": self.password},
            headers={"Content-Type": "application/json"},
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
        token = payload.get("data", {}).get("token") or payload.get("token")
        if token:
            self.token = token
            return token
        raise ValueError("Wazuh authentication token not found")

    def _request(self, path: str, params: Optional[Dict[str, Any]] = None):
        if not self.base_url:
            raise ValueError("WAZUH_API_URL or WAZUH_URL is not configured")

        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"

        response = requests.get(
            url,
            headers=self._headers(),
            auth=self._auth(),
            params=params,
            timeout=20,
        )

        response.raise_for_status()

        return response.json()

    ##################################################################
    # Alerts
    ##################################################################

    def get_alerts(self):
        try:
            payload = self._request("/alerts")
            alerts = payload.get("alerts", payload)

            print("=" * 50)
            print("Loaded Alerts")
            print(alerts)
            print("=" * 50)

            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "alerts": alerts
                },
                details="Alert list retrieved successfully.",
            )
        except Exception as e:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={"alerts": []},
                details=f"Failed to retrieve alerts from Wazuh: {str(e)}",
            )

    ##################################################################
    # Endpoint
    ##################################################################

    def get_endpoint_info(self, endpoint_id):
        try:
            payload = self._request(f"/agents/{endpoint_id}")
            endpoint = payload.get("agent", payload)

            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "endpoint": endpoint
                },
                details="Endpoint information retrieved.",
            )
        except Exception as e:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={"endpoint": None},
                details=f"Failed to retrieve endpoint info from Wazuh: {str(e)}",
            )

    ##################################################################
    # Events
    ##################################################################

    def get_active_events(self):
        try:
            payload = self._request("/events", {"status": "active"})
            events = payload.get("events", payload)

            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "events": events
                },
                details="Active events retrieved.",
            )
        except Exception as e:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={"events": []},
                details=f"Failed to retrieve active events from Wazuh: {str(e)}",
            )

    ##################################################################
    # MCP
    ##################################################################

    def get_alert_details(self, alert_id: str):
        if not alert_id:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={"alerts": []},
                details="Alert ID is required for get_alert_details.",
            )

        try:
            payload = self._request("/alerts")
            alerts = payload.get("alerts", payload)
            if isinstance(alerts, dict):
                alerts = alerts.get("alerts", [])

            selected = next(
                (
                    alert for alert in alerts
                    if str(alert.get("id") or alert.get("alert_id") or alert.get("rule") or alert.get("alertHash", "")).lower() == str(alert_id).lower()
                ),
                None,
            )

            if selected:
                return ToolResponse(
                    tool_name=self.name,
                    status="success",
                    data={"alerts": [selected]},
                    details="Alert details retrieved successfully.",
                )

        except Exception:
            alerts = self._load_local_alerts()
            selected = next(
                (
                    alert for alert in alerts
                    if str(alert.get("id") or alert.get("alert_id") or alert.get("rule") or alert.get("alertHash", "")).lower() == str(alert_id).lower()
                ),
                None,
            )
            if selected:
                return ToolResponse(
                    tool_name=self.name,
                    status="success",
                    data={"alerts": [selected]},
                    details="Alert details retrieved from local fallback.",
                )

        return ToolResponse(
            tool_name=self.name,
            status="success",
            data={"alerts": []},
            details="No matching alert found.",
        )

    def get_statistics(self):
        try:
            payload = self._request("/alerts")
            alerts = payload.get("alerts", payload)
            if isinstance(alerts, dict):
                alerts = alerts.get("alerts", [])

            counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for alert in alerts:
                severity = str(alert.get("severity", "Unknown")).title()
                if severity in counts:
                    counts[severity] += 1
                else:
                    counts[severity] = counts.get(severity, 0) + 1

            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "total_alerts": len(alerts),
                    "severity_distribution": counts,
                },
                details="Wazuh statistics retrieved successfully.",
            )
        except Exception:
            alerts = self._load_local_alerts()
            counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for alert in alerts:
                severity = str(alert.get("severity", "Unknown")).title()
                if severity in counts:
                    counts[severity] += 1
                else:
                    counts[severity] = counts.get(severity, 0) + 1

            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "total_alerts": len(alerts),
                    "severity_distribution": counts,
                },
                details="Wazuh statistics retrieved from local fallback.",
            )

    def handle_request(self, request: ToolRequest):

        query = request.query.lower()

        if query.startswith("get_alerts"):
            return self.get_alerts()

        elif query.startswith("get_alert_details"):
            alert_id = request.metadata.get("alert_id") or request.query.split()[-1]
            return self.get_alert_details(str(alert_id))

        elif query.startswith("get_statistics"):
            return self.get_statistics()

        elif query.startswith("get_endpoint_info"):
            endpoint = request.query.split()[-1]
            return self.get_endpoint_info(endpoint)

        elif query.startswith("get_active_events"):
            return self.get_active_events()

        return ToolResponse(

            tool_name=self.name,

            status="error",

            data={},

            details="Unknown Wazuh operation",

        )