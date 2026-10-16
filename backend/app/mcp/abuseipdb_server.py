import os
from typing import Any, Dict, Optional
import asyncio
from .tool_server import BaseMCPServer, ToolRequest, ToolResponse
from ..threat_intel.abuseipdb_client import AbuseIPDBClient


class AbuseIPDBServer(BaseMCPServer):
    name = "AbuseIPDB"
    description = "AbuseIPDB MCP Server for IP threat intelligence"
    supported_features = [
        "check_ip",
        "report_ip",
        "get_blacklist",
        "get_report",
    ]

    def __init__(self):
        super().__init__()
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")
        if self.api_key:
            print("[AbuseIPDB MCP] API Key Loaded.")
            self.client = AbuseIPDBClient(self.api_key)
        else:
            print("[AbuseIPDB MCP] Using mock data for demonstration.")
            self.client = None

    def check_ip(self, ip: str) -> ToolResponse:
        """Check an IP address against AbuseIPDB"""
        if not self.client:
            # Mock response for demonstration
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "ip": ip,
                    "result": {
                        "source": "abuseipdb",
                        "ip_address": ip,
                        "abuse_confidence_score": 75,
                        "total_reports": 15,
                        "country_code": "US",
                        "isp": "Mock ISP",
                        "risk_level": "High"
                    }
                },
                details=f"AbuseIPDB check completed for {ip} (mock data)."
            )

        try:
            # Run async function in sync context
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(self.client.check_ip(ip))
            
            if "error" in result:
                # Fall back to mock data on error
                return ToolResponse(
                    tool_name=self.name,
                    status="success",
                    data={
                        "ip": ip,
                        "result": {
                            "source": "abuseipdb",
                            "ip_address": ip,
                            "abuse_confidence_score": 0,
                            "total_reports": 0,
                            "country_code": "Unknown",
                            "isp": "Unknown",
                            "risk_level": "Low",
                            "api_error": result.get('error', 'Unknown error')
                        }
                    },
                    details=f"AbuseIPDB check completed for {ip} (fallback data due to API error)."
                )
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={"ip": ip, "result": result},
                details=f"AbuseIPDB check completed for {ip}."
            )
        except Exception as e:
            # Fall back to mock data on exception
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "ip": ip,
                    "result": {
                        "source": "abuseipdb",
                        "ip_address": ip,
                        "abuse_confidence_score": 0,
                        "total_reports": 0,
                        "country_code": "Unknown",
                        "isp": "Unknown",
                        "risk_level": "Low",
                        "api_error": str(e)
                    }
                },
                details=f"AbuseIPDB check completed for {ip} (fallback data due to exception)."
            )

    def handle_request(self, request: ToolRequest) -> ToolResponse:
        query = request.query.strip()
        print(f"[AbuseIPDB MCP Server] Handling request: '{query}'")

        if query.lower().startswith("check"):
            parts = query.split(maxsplit=1)
            target = parts[1] if len(parts) > 1 else "185.220.101.45"
            return self.check_ip(target)
        elif query.lower().startswith("report"):
            parts = query.split(maxsplit=1)
            target = parts[1] if len(parts) > 1 else "185.220.101.45"
            return self.report_ip(target)
        elif query.lower().startswith("blacklist"):
            return self.get_blacklist()
        elif query.lower().startswith("get_report"):
            parts = query.split(maxsplit=1)
            target = parts[1] if len(parts) > 1 else "185.220.101.45"
            return self.get_report(target)
        
        # Default to IP check
        return self.check_ip(query)

    def report_ip(self, ip: str) -> ToolResponse:
        """Report an IP address to AbuseIPDB"""
        if not self.client:
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={"ip": ip, "result": {"status": "mock"}},
                details=f"AbuseIPDB report for {ip} (mock data)."
            )

        try:
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(
                self.client.report_ip(ip, categories=[22, 23], comment="Reported via MCP")
            )
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={"ip": ip, "result": result},
                details=f"AbuseIPDB report completed for {ip}."
            )
        except Exception as e:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={"ip": ip},
                details=f"AbuseIPDB report error: {str(e)}"
            )

    def get_blacklist(self) -> ToolResponse:
        """Get the AbuseIPDB blacklist"""
        if not self.client:
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={"result": {"blacklist": []}},
                details="AbuseIPDB blacklist (mock data)."
            )

        try:
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(self.client.get_blacklist())
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={"result": result},
                details="AbuseIPDB blacklist retrieved."
            )
        except Exception as e:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={},
                details=f"AbuseIPDB blacklist error: {str(e)}"
            )

    def get_report(self, ip: str) -> ToolResponse:
        """Get detailed report for an IP address"""
        if not self.client:
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={"ip": ip, "result": {"status": "mock"}},
                details=f"AbuseIPDB report for {ip} (mock data)."
            )

        try:
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(self.client.get_report(ip))
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={"ip": ip, "result": result},
                details=f"AbuseIPDB report retrieved for {ip}."
            )
        except Exception as e:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={"ip": ip},
                details=f"AbuseIPDB report error: {str(e)}"
            )