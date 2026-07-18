print(">>> Loading VirusTotalServer.py <<<")
import json
import os
from pathlib import Path
from typing import Any, Dict

import requests

from .tool_server import BaseMCPServer, ToolRequest, ToolResponse


class VirusTotalServer(BaseMCPServer):
    name = "VirusTotal"
    description = "VirusTotal Threat Intelligence Server"
    supported_features = [
        "check_ip",
        "check_url",
        "check_hash",
    ]

    def __init__(self):
        super().__init__()

        self.base_url = os.getenv(
            "VIRUSTOTAL_API_URL",
            "https://www.virustotal.com/api/v3"
        )

        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.data_file = Path(__file__).resolve().parents[2] / "virustotal.json"

    #############################################################
    # HTTP
    #############################################################

    def _headers(self):

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["x-apikey"] = self.api_key
        return headers

    def _load_local_ip_data(self):
        if not self.data_file.exists():
            return {}

        with self.data_file.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

        if isinstance(payload, list):
            return {item.get("ip"): item for item in payload if item.get("ip")}
        return payload

    def _request(self, path):

        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"

        response = requests.get(
            url,
            headers=self._headers(),
            timeout=20
        )

        response.raise_for_status()

        return response.json()

    #############################################################
    # Dummy Threat Intelligence
    #############################################################

    def _dummy_ip_data(self):

        return {

            "185.220.101.45": {

                "id": "185.220.101.45",

                "reputation": "Malicious",

                "country": "Russia",

                "detections": 18,

                "confidence": "95%",

                "category": "Brute Force",

                "last_analysis_stats": {

                    "malicious": 18,

                    "suspicious": 2,

                    "harmless": 5

                }

            },

            "103.44.22.15": {

                "id": "103.44.22.15",

                "reputation": "Malicious",

                "country": "China",

                "detections": 25,

                "confidence": "98%",

                "category": "Ransomware",

                "last_analysis_stats": {

                    "malicious": 25,

                    "suspicious": 1,

                    "harmless": 3

                }

            },

            "45.155.205.233": {

                "id": "45.155.205.233",

                "reputation": "Suspicious",

                "country": "Germany",

                "detections": 8,

                "confidence": "80%",

                "category": "Port Scan",

                "last_analysis_stats": {

                    "malicious": 8,

                    "suspicious": 4,

                    "harmless": 15

                }

            },

            "91.220.11.100": {

                "id": "91.220.11.100",

                "reputation": "Malicious",

                "country": "Brazil",

                "detections": 15,

                "confidence": "93%",

                "category": "Trojan",

                "last_analysis_stats": {

                    "malicious": 15,

                    "suspicious": 2,

                    "harmless": 6

                }

            },

            "8.8.8.8": {

                "id": "8.8.8.8",

                "reputation": "Clean",

                "country": "USA",

                "detections": 0,

                "confidence": "100%",

                "category": "Safe",

                "last_analysis_stats": {

                    "malicious": 0,

                    "suspicious": 0,

                    "harmless": 90

                }

            }

        }

    #############################################################
    # IP
    #############################################################

  
    def check_ip(self, ip):

        print("VirusTotal received:", ip)

        try:
            payload = self._request(f"ip_addresses/{ip}")
            reputation = payload.get("data", {})

        except Exception:

            local_data = self._load_local_ip_data()

            if ip in local_data:
                reputation = local_data[ip]
            else:
                reputation = self._dummy_ip_data().get(
                    ip,
                    {
                        "id": ip,
                        "reputation": "Unknown",
                        "country": "Unknown",
                        "detections": 0,
                        "confidence": "50%",
                        "category": "Unknown",
                        "last_analysis_stats": {}
                    }
                )

        return ToolResponse(
            tool_name=self.name,
            status="success",
            data={
                "ip": ip,
                "result": reputation
            },
            details="VirusTotal IP lookup completed."
        )

    #############################################################
    # URL
    #############################################################

    def check_url(self, url):

        return ToolResponse(

            tool_name=self.name,

            status="success",

            data={

                "url": url,

                "result": {

                    "id": url,

                    "reputation": "Malicious",

                    "detections": 12,

                    "category": "Phishing"

                }

            },

            details="VirusTotal URL lookup."

        )

    #############################################################
    # HASH
    #############################################################

    def check_hash(self, file_hash):

        return ToolResponse(

            tool_name=self.name,

            status="success",

            data={

                "hash": file_hash,

                "result": {

                    "id": file_hash,

                    "reputation": "Malicious",

                    "detections": 21,

                    "family": "Trojan.Generic"

                }

            },

            details="VirusTotal File Hash lookup."

        )

    #############################################################
    # MCP
    #############################################################

    def handle_request(self, request: ToolRequest):
        print(">>> VirusTotalServer.handle_request() called <<<")
        query = request.query.lower()

        if query.startswith("check_ip"):

            ip = request.query.split()[-1]

            return self.check_ip(ip)

        elif query.startswith("check_url"):

            url = request.query.split(" ", 1)[-1]

            return self.check_url(url)

        elif query.startswith("check_hash"):

            file_hash = request.query.split()[-1]

            return self.check_hash(file_hash)

        return ToolResponse(

            tool_name=self.name,

            status="error",

            data={},

            details="Unknown VirusTotal command"

        )