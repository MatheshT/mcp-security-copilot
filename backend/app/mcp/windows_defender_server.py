import json
import os
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime, timedelta
import random

from .tool_server import BaseMCPServer, ToolRequest, ToolResponse
from ..collectors.windows_defender_collector import get_defender_collector


class WindowsDefenderServer(BaseMCPServer):
    name = "WindowsDefender"
    description = "Windows Defender Antivirus Server"
    supported_features = [
        "get_threats",
        "get_scan_history",
        "get_quarantine_items",
        "get_protection_status",
    ]

    def __init__(self):
        super().__init__()
        
        self.defender_file = Path(__file__).resolve().parents[2] / "windows_defender.json"
        self.hostname = os.getenv("WINDOWS_HOSTNAME", "localhost")

    def _load_local_threats(self):
        """Load local Windows Defender threat data or generate mock data"""
        if not self.defender_file.exists():
            return self._generate_mock_threats()

        try:
            with self.defender_file.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            
            if isinstance(payload, list):
                return payload
            return payload.get("threats", [])
        except Exception:
            return self._generate_mock_threats()

    def _generate_mock_threats(self):
        """Generate realistic Windows Defender threat detections"""
        threats = []
        threat_types = [
            {
                "threat_name": "Trojan:Win32/Emotet",
                "threat_type": "Trojan",
                "severity": "Critical",
                "category": "Malware",
                "description": "Banking Trojan that steals credentials",
                "mitre": "T1059.003"
            },
            {
                "threat_name": "Ransom:Win32/WannaCrypt",
                "threat_type": "Ransomware",
                "severity": "Critical",
                "category": "Ransomware",
                "description": "WannaCry ransomware variant",
                "mitre": "T1486"
            },
            {
                "threat_name": "PUA:Win32/InstallCore",
                "threat_type": "PUA",
                "severity": "Medium",
                "category": "Potentially Unwanted",
                "description": "Potentially unwanted application with adware",
                "mitre": "N/A"
            },
            {
                "threat_name": "Trojan:Win32/FakeSys",
                "threat_type": "Trojan",
                "severity": "High",
                "category": "Malware",
                "description": "Fake system utility trojan",
                "mitre": "T1566.001"
            },
            {
                "threat_name": "Adware:Win32/HotBar",
                "threat_type": "Adware",
                "severity": "Low",
                "category": "Adware",
                "description": "Adware that displays unwanted advertisements",
                "mitre": "N/A"
            },
            {
                "threat_name": "Exploit:Win32/CVE-2023-1234",
                "threat_type": "Exploit",
                "severity": "Critical",
                "category": "Exploit",
                "description": "Exploit kit targeting known vulnerability",
                "mitre": "T1190"
            },
            {
                "threat_name": "Backdoor:Win32/AsyncRAT",
                "threat_type": "Backdoor",
                "severity": "Critical",
                "category": "Malware",
                "description": "Remote Access Trojan with C2 capabilities",
                "mitre": "T1219"
            },
            {
                "threat_name": "Script:PowerShell/Empire",
                "threat_type": "Script",
                "severity": "High",
                "category": "Malware",
                "description": "PowerShell Empire post-exploitation framework",
                "mitre": "T1059.001"
            }
        ]

        file_paths = [
            "C:\\Users\\admin\\Downloads\\suspicious.exe",
            "C:\\Program Files\\malware.dll",
            "C:\\Temp\\payload.ps1",
            "D:\\Documents\\invoice.doc",
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Users\\user\\AppData\\Local\\temp\\malware.exe"
        ]
        
        for i in range(15):
            threat_type = random.choice(threat_types)
            timestamp = datetime.now() - timedelta(hours=random.randint(0, 72))
            
            threat = {
                "threat_id": f"THR-{random.randint(10000, 99999)}",
                "threat_name": threat_type["threat_name"],
                "threat_type": threat_type["threat_type"],
                "severity": threat_type["severity"],
                "category": threat_type["category"],
                "description": threat_type["description"],
                "mitre": threat_type["mitre"],
                "hostname": self.hostname,
                "file_path": random.choice(file_paths),
                "detection_time": timestamp.isoformat(),
                "status": random.choice(["Quarantined", "Removed", "Allowed", "Pending"]),
                "action_taken": random.choice(["Quarantine", "Remove", "Allow", "Block"]),
                "scan_type": random.choice(["Quick Scan", "Full Scan", "Real-time Protection"])
            }
            threats.append(threat)
        
        return sorted(threats, key=lambda x: x["detection_time"], reverse=True)

    def get_threats(self):
        """Get detected threats from Windows Defender - ONLY real data"""
        try:
            print("Attempting to collect real Windows Defender threats...")
            collector = get_defender_collector()
            threats = collector.get_threats(hours=24, limit=50)
            
            print("=" * 50)
            print("Successfully loaded REAL Windows Defender Threats")
            print(f"Total threats: {len(threats)}")
            print(f"Data source: Real Windows Defender")
            print("=" * 50)
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "threats": threats[:50],
                    "total_count": len(threats),
                    "critical_count": len([t for t in threats if t["severity"] == "Critical"]),
                    "high_count": len([t for t in threats if t["severity"] == "High"]),
                    "medium_count": len([t for t in threats if t["severity"] == "Medium"]),
                    "low_count": len([t for t in threats if t["severity"] == "Low"]),
                    "data_source": "real_windows_defender"
                },
                details=f"Retrieved {len(threats)} threats from real Windows Defender.",
            )
        except Exception as e:
            print(f"Error getting real Windows Defender threats: {e}")
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={},
                details=f"Failed to retrieve threats from Windows Defender: {str(e)}"
            )

    def get_scan_history(self):
        """Get Windows Defender scan history - ONLY real data"""
        try:
            collector = get_defender_collector()
            scans = collector.get_scan_history(days=30, limit=50)
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "scans": sorted(scans, key=lambda x: x["start_time"], reverse=True),
                    "data_source": "real_windows_defender"
                },
                details=f"Retrieved {len(scans)} scan history entries from real Windows Defender.",
            )
        except Exception as e:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={},
                details=f"Failed to retrieve scan history from Windows Defender: {str(e)}"
            )

    def get_quarantine_items(self):
        """Get items quarantined by Windows Defender - ONLY real data"""
        try:
            collector = get_defender_collector()
            quarantined = collector.get_quarantine_items(limit=50)
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "quarantine_items": quarantined,
                    "total_count": len(quarantined),
                    "data_source": "real_windows_defender"
                },
                details=f"Retrieved {len(quarantined)} quarantined items from real Windows Defender.",
            )
        except Exception as e:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={},
                details=f"Failed to retrieve quarantine items from Windows Defender: {str(e)}"
            )

    def get_protection_status(self):
        """Get Windows Defender protection status"""
        try:
            # Try to get real protection status from Windows Defender
            collector = get_defender_collector()
            status = collector.get_protection_status()
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={"protection_status": status},
                details="Retrieved Windows Defender protection status.",
            )
        except Exception as e:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={},
                details=f"Failed to retrieve protection status: {str(e)}"
            )

    def handle_request(self, request: ToolRequest):
        query = request.query.lower()
        
        if query.startswith("get_threats"):
            return self.get_threats()
        elif query.startswith("get_scan_history"):
            return self.get_scan_history()
        elif query.startswith("get_quarantine_items"):
            return self.get_quarantine_items()
        elif query.startswith("get_protection_status"):
            return self.get_protection_status()
        
        return ToolResponse(
            tool_name=self.name,
            status="error",
            data={},
            details="Unknown Windows Defender operation"
        )
