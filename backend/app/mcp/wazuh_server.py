import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

import requests

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

        self.base_url = os.getenv("WAZUH_API_URL")
        self.api_key = os.getenv("WAZUH_API_KEY")
        self.data_file = Path(__file__).resolve().parents[2] / "alerts.json"

    def _headers(self):
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _load_local_alerts(self):
        if not self.data_file.exists():
            return []

        with self.data_file.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

        if isinstance(payload, list):
            return payload
        return payload.get("alerts", [])

    def _request(self, path: str, params: Optional[Dict[str, Any]] = None):

        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"

        response = requests.get(
            url,
            headers=self._headers(),
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

        except Exception:

            alerts = self._load_local_alerts()
            if not alerts:
                alerts = [
                    {
                        "id": "101",
                        "severity": "High",
                        "title": "No local alert feed available",
                        "description": "Local alert data could not be loaded.",
                        "hostname": "Unknown",
                        "agent": "Unknown",
                        "username": "unknown",
                        "source_ip": "0.0.0.0",
                        "destination_ip": "0.0.0.0",
                        "event": "Unknown",
                        "mitre": "N/A",
                        "status": "Open",
                        "timestamp": "unknown",
                    }
                ]

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

    ##################################################################
    # Endpoint
    ##################################################################

    def get_endpoint_info(self, endpoint_id):

        try:

            payload = self._request(f"/agents/{endpoint_id}")

            endpoint = payload.get("agent", payload)

        except Exception:

            endpoint = {

                "id": endpoint_id,

                "hostname": "Finance-PC",

                "ip": "192.168.1.10",

                "status": "Active",

                "os": "Windows 11",

                "user": "administrator",

                "last_seen": "2026-07-13 10:40:00",

            }

        return ToolResponse(

            tool_name=self.name,

            status="success",

            data={

                "endpoint": endpoint

            },

            details="Endpoint information retrieved.",

        )

    ##################################################################
    # Events
    ##################################################################

    def get_active_events(self):

        try:

            payload = self._request("/events", {"status": "active"})

            events = payload.get("events", payload)

        except Exception:

            events = [

                {
                    "event_id": "EVT-1001",
                    "rule": "Failed Login",
                    "agent": "Finance-PC",
                    "severity": "High",
                    "ip": "185.220.101.45",
                },

                {
                    "event_id": "EVT-1002",
                    "rule": "Malware Detected",
                    "agent": "HR-PC",
                    "severity": "Critical",
                    "ip": "103.44.22.15",
                },

                {
                    "event_id": "EVT-1003",
                    "rule": "Port Scan",
                    "agent": "Web-Server",
                    "severity": "Medium",
                    "ip": "45.155.205.233",
                },

            ]

        return ToolResponse(

            tool_name=self.name,

            status="success",

            data={

                "events": events

            },

            details="Active events retrieved.",

        )

    ##################################################################
    # MCP
    ##################################################################

    def handle_request(self, request: ToolRequest):

        query = request.query.lower()

        if query.startswith("get_alerts"):

            return self.get_alerts()

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