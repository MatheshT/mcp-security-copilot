import json
import os
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime, timedelta
import random

from .tool_server import BaseMCPServer, ToolRequest, ToolResponse
from ..collectors.windows_event_collector import get_event_collector


class WindowsLogsServer(BaseMCPServer):
    name = "WindowsLogs"
    description = "Windows Event Logs Monitoring Server"
    supported_features = [
        "get_security_events",
        "get_system_events",
        "get_application_events",
        "get_event_by_id",
    ]

    def __init__(self):
        super().__init__()
        
        self.log_file = Path(__file__).resolve().parents[2] / "windows_events.json"
        self.hostname = os.getenv("WINDOWS_HOSTNAME", "localhost")
        self.username = os.getenv("WINDOWS_USERNAME", "admin")

    def _load_local_events(self):
        """Load local Windows event data or generate mock data"""
        if not self.log_file.exists():
            return self._generate_mock_events()

        try:
            with self.log_file.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            
            if isinstance(payload, list):
                return payload
            return payload.get("events", [])
        except Exception:
            return self._generate_mock_events()

    def _generate_mock_events(self):
        """Generate realistic Windows event log entries"""
        events = []
        event_types = [
            {
                "event_id": 4625,
                "source": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "severity": "High",
                "title": "Failed Login Attempt",
                "description": "An account failed to log on",
                "mitre": "T1110.001"
            },
            {
                "event_id": 4624,
                "source": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "severity": "Low",
                "title": "Successful Login",
                "description": "An account was successfully logged on",
                "mitre": "N/A"
            },
            {
                "event_id": 4688,
                "source": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "severity": "Medium",
                "title": "Process Creation",
                "description": "A new process has been created",
                "mitre": "T1059"
            },
            {
                "event_id": 4720,
                "source": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "severity": "High",
                "title": "User Account Created",
                "description": "A user account was created",
                "mitre": "T1136"
            },
            {
                "event_id": 4732,
                "source": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "severity": "High",
                "title": "Added to Privileged Group",
                "description": "A member was added to a security-enabled global group",
                "mitre": "T1068"
            },
            {
                "event_id": 4740,
                "source": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "severity": "Critical",
                "title": "Account Locked Out",
                "description": "A user account was locked out",
                "mitre": "T1111"
            },
            {
                "event_id": 7045,
                "source": "Service Control Manager",
                "channel": "System",
                "severity": "High",
                "title": "Service Installed",
                "description": "A service was installed in the system",
                "mitre": "T1543"
            },
            {
                "event_id": 104,
                "source": "Microsoft-Windows-TaskScheduler",
                "channel": "System",
                "severity": "Medium",
                "title": "Task Scheduled",
                "description": "A task was registered in the Task Scheduler",
                "mitre": "T1053"
            }
        ]

        usernames = ["admin", "user1", "service_account", "attacker", "system"]
        ip_addresses = ["192.168.1.100", "192.168.1.101", "10.0.0.50", "172.16.0.25", "185.220.101.45"]
        
        for i in range(20):
            event_type = random.choice(event_types)
            timestamp = datetime.now() - timedelta(hours=random.randint(0, 48))
            
            event = {
                "event_id": f"EVT-{random.randint(10000, 99999)}",
                "windows_event_id": event_type["event_id"],
                "source": event_type["source"],
                "channel": event_type["channel"],
                "severity": event_type["severity"],
                "title": event_type["title"],
                "description": event_type["description"],
                "mitre": event_type["mitre"],
                "hostname": self.hostname,
                "username": random.choice(usernames),
                "source_ip": random.choice(ip_addresses) if event_type["severity"] in ["High", "Critical"] else "N/A",
                "timestamp": timestamp.isoformat(),
                "status": "Open" if event_type["severity"] in ["High", "Critical"] else "Resolved"
            }
            events.append(event)
        
        return sorted(events, key=lambda x: x["timestamp"], reverse=True)

    def get_security_events(self):
        """Get security events from Windows Event Logs - ONLY real data"""
        try:
            print("Attempting to collect real Windows Event Logs...")
            collector = get_event_collector()
            security_events = collector.get_security_events(hours=24, limit=50)
            
            print("=" * 50)
            print("Successfully loaded REAL Windows Security Events")
            print(f"Total events: {len(security_events)}")
            print(f"Data source: Real Windows Event Log")
            print("=" * 50)
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "events": security_events[:50],
                    "total_count": len(security_events),
                    "data_source": "real_windows_logs"
                },
                details=f"Retrieved {len(security_events)} security events from real Windows Event Logs.",
            )
        except Exception as e:
            print(f"Error getting real Windows events: {e}")
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={},
                details=f"Failed to retrieve security events from Windows Event Log: {str(e)}"
            )

    def get_system_events(self):
        """Get system events from Windows Event Logs - ONLY real data"""
        try:
            collector = get_event_collector()
            system_events = collector.get_system_events(hours=24, limit=50)
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "events": system_events[:50],
                    "total_count": len(system_events),
                    "data_source": "real_windows_logs"
                },
                details=f"Retrieved {len(system_events)} system events from real Windows Event Logs.",
            )
        except Exception as e:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={},
                details=f"Failed to retrieve system events from Windows Event Log: {str(e)}"
            )

    def get_application_events(self):
        """Get application events from Windows Event Logs - ONLY real data"""
        try:
            collector = get_event_collector()
            app_events = collector.get_application_events(hours=24, limit=50)
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "events": app_events[:50],
                    "total_count": len(app_events),
                    "data_source": "real_windows_logs"
                },
                details=f"Retrieved {len(app_events)} application events from real Windows Event Logs.",
            )
        except Exception as e:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={},
                details=f"Failed to retrieve application events from Windows Event Log: {str(e)}"
            )

    def get_event_by_id(self, event_id):
        """Get a specific event by ID"""
        try:
            all_events = self._load_local_events()
            event = next((e for e in all_events if e.get("event_id") == event_id), None)
            
            if not event:
                return ToolResponse(
                    tool_name=self.name,
                    status="error",
                    data={},
                    details=f"Event with ID {event_id} not found"
                )
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={"event": event},
                details=f"Retrieved event {event_id}",
            )
        except Exception as e:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={},
                details=f"Failed to retrieve event: {str(e)}"
            )

    def handle_request(self, request: ToolRequest):
        query = request.query.lower()
        
        if query.startswith("get_security_events"):
            return self.get_security_events()
        elif query.startswith("get_system_events"):
            return self.get_system_events()
        elif query.startswith("get_application_events"):
            return self.get_application_events()
        elif query.startswith("get_event_by_id"):
            event_id = request.query.split()[-1]
            return self.get_event_by_id(event_id)
        
        return ToolResponse(
            tool_name=self.name,
            status="error",
            data={},
            details="Unknown Windows Logs operation"
        )
