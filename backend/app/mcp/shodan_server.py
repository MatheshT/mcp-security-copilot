import json
import os
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

from .tool_server import BaseMCPServer, ToolRequest, ToolResponse


class ShodanServer(BaseMCPServer):
    name = "Shodan"
    description = "Shodan OSINT MCP Server for infrastructure intelligence"
    supported_features = [
        "search",
        "scan",
        "get_host_info",
    ]

    def __init__(self):
        super().__init__()
        self.api_key = os.getenv("SHODAN_API_KEY")
        if self.api_key:
            print("[Shodan MCP] API Key Loaded.")
        else:
            print("[Shodan MCP] Using mock data for demonstration.")

    def search_ip(self, ip: str) -> ToolResponse:
        print(f"[Shodan MCP] Searching infrastructure intelligence for IP: {ip}")

        # Mock dataset for demonstration
        shodan_database = {
            "185.220.101.45": {
                "ip": "185.220.101.45",
                "ports": [22, 80, 443, 9050],
                "vulnerabilities": ["CVE-2023-38606", "CVE-2022-32548"],
                "org": "Tor Project",
                "isp": "Tor Project e.V.",
                "country": "Germany",
                "city": "Frankfurt",
                "os": "Linux",
                "hostnames": ["exit-node.torproject.org"],
                "tags": ["tor", "exit-node", "proxy"],
                "vulns": "High",
                "services": [
                    {"port": 22, "service": "OpenSSH", "version": "8.2p1"},
                    {"port": 80, "service": "nginx", "version": "1.18.0"},
                    {"port": 443, "service": "nginx", "version": "1.18.0"},
                    {"port": 9050, "service": "Tor SOCKS", "version": "0.4.6"}
                ]
            },
            "45.155.205.233": {
                "ip": "45.155.205.233",
                "ports": [22, 80, 3306, 3389],
                "vulnerabilities": ["CVE-2023-23397", "CVE-2022-26923"],
                "org": "Unknown Organization",
                "isp": "DigitalOcean",
                "country": "Netherlands",
                "city": "Amsterdam",
                "os": "Windows Server 2019",
                "hostnames": ["suspicious-host.xyz"],
                "tags": ["ransomware", "c2", "malicious"],
                "vulns": "Critical",
                "services": [
                    {"port": 22, "service": "OpenSSH", "version": "7.4"},
                    {"port": 80, "service": "Apache", "version": "2.4.41"},
                    {"port": 3306, "service": "MySQL", "version": "8.0"},
                    {"port": 3389, "service": "RDP", "version": "Windows"}
                ]
            }
        }

        if ip in shodan_database:
            result = shodan_database[ip]
        else:
            result = {
                "ip": ip,
                "ports": [22, 80, 443],
                "vulnerabilities": ["CVE-2023-XXXX"],
                "org": "Unknown Organization",
                "isp": "Unknown ISP",
                "country": "Unknown",
                "city": "Unknown",
                "os": "Unknown",
                "hostnames": [],
                "tags": ["unclassified"],
                "vulns": "Medium",
                "services": [
                    {"port": 22, "service": "SSH", "version": "Unknown"},
                    {"port": 80, "service": "HTTP", "version": "Unknown"},
                    {"port": 443, "service": "HTTPS", "version": "Unknown"}
                ]
            }

        return ToolResponse(
            tool_name=self.name,
            status="success",
            data={"ip": ip, "result": result},
            details=f"Shodan infrastructure intelligence lookup completed for {ip}."
        )

    def handle_request(self, request: ToolRequest) -> ToolResponse:
        query = request.query.strip()
        print(f"[Shodan MCP Server] Handling request: '{query}'")

        if query.lower().startswith("search") or query.lower().startswith("scan"):
            parts = query.split(maxsplit=1)
            target = parts[1] if len(parts) > 1 else "185.220.101.45"
            return self.search_ip(target)

        return self.search_ip(query)