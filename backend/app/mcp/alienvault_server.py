"""
AlienVault OTX MCP Server
Interfaces with AlienVault OTX API for threat intelligence
"""
import asyncio
import os
import logging
from typing import Any, Dict
from .tool_server import BaseMCPServer, ToolRequest, ToolResponse

logger = logging.getLogger(__name__)


class AlienVaultServer(BaseMCPServer):
    name = "AlienVault OTX"
    description = "AlienVault OTX Threat Intelligence Server"
    supported_features = [
        "check_indicator",
        "get_pulse",
        "search_ioc",
        "get_reputation"
    ]

    def __init__(self):
        super().__init__()
        self.api_key = os.getenv("ALIENVAULT_OTX_API_KEY")
        self.client = None
        if self.api_key:
            self._init_client()
        else:
            logger.warning("AlienVault OTX API key not configured")

    def _init_client(self):
        try:
            from ..threat_intel.alienvault_client import AlienVaultClient
            self.client = AlienVaultClient(self.api_key)
            logger.info("[AlienVault OTX MCP] API Key Loaded.")
        except ImportError:
            logger.warning("AlienVault client not available, using mock data")

    def check_indicator(self, indicator: str) -> ToolResponse:
        """Check an indicator against AlienVault OTX"""
        if not self.client:
            # Mock response for demonstration
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "indicator": indicator,
                    "result": {
                        "source": "alienvault",
                        "indicator": indicator,
                        "reputation": "Clean",
                        "pulse_count": 0,
                        "first_seen": "N/A",
                        "last_seen": "N/A",
                        "tags": [],
                        "risk_level": "Low"
                    }
                },
                details=f"AlienVault OTX check completed for {indicator} (mock data)."
            )

        try:
            # Run async function in sync context
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(self.client.check_indicator(indicator))
            
            if "error" in result:
                # Fall back to mock data on error
                return ToolResponse(
                    tool_name=self.name,
                    status="success",
                    data={
                        "indicator": indicator,
                        "result": {
                            "source": "alienvault",
                            "indicator": indicator,
                            "reputation": "Unknown",
                            "pulse_count": 0,
                            "first_seen": "N/A",
                            "last_seen": "N/A",
                            "tags": [],
                            "risk_level": "Medium",
                            "api_error": result.get('error', 'Unknown error')
                        }
                    },
                    details=f"AlienVault OTX check completed for {indicator} (fallback data due to API error)."
                )
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={"indicator": indicator, "result": result},
                details=f"AlienVault OTX check completed for {indicator}."
            )
        except Exception as e:
            # Fall back to mock data on exception
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "indicator": indicator,
                    "result": {
                        "source": "alienvault",
                        "indicator": indicator,
                        "reputation": "Unknown",
                        "pulse_count": 0,
                        "first_seen": "N/A",
                        "last_seen": "N/A",
                        "tags": [],
                        "risk_level": "Medium",
                        "api_error": str(e)
                    }
                },
                details=f"AlienVault OTX check completed for {indicator} (fallback data due to exception)."
            )

    def get_pulse(self, pulse_id: str) -> ToolResponse:
        """Get pulse details from AlienVault OTX"""
        if not self.client:
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "pulse_id": pulse_id,
                    "result": {
                        "source": "alienvault",
                        "pulse_id": pulse_id,
                        "name": "Mock Pulse",
                        "description": "Mock pulse data",
                        "indicators": []
                    }
                },
                details=f"AlienVault OTX pulse retrieved (mock data)."
            )

        try:
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(self.client.get_pulse(pulse_id))
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={"pulse_id": pulse_id, "result": result},
                details=f"AlienVault OTX pulse retrieved successfully."
            )
        except Exception as e:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={"pulse_id": pulse_id},
                details=f"AlienVault OTX pulse retrieval failed: {str(e)}"
            )

    def search_ioc(self, ioc: str) -> ToolResponse:
        """Search for IOCs in AlienVault OTX"""
        if not self.client:
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "ioc": ioc,
                    "result": {
                        "source": "alienvault",
                        "ioc": ioc,
                        "matches": [],
                        "total_matches": 0
                    }
                },
                details=f"AlienVault OTX IOC search completed (mock data)."
            )

        try:
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(self.client.search_ioc(ioc))
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={"ioc": ioc, "result": result},
                details=f"AlienVault OTX IOC search completed successfully."
            )
        except Exception as e:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={"ioc": ioc},
                details=f"AlienVault OTX IOC search failed: {str(e)}"
            )

    def get_reputation(self, indicator: str) -> ToolResponse:
        """Get reputation for an indicator from AlienVault OTX"""
        if not self.client:
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={
                    "indicator": indicator,
                    "result": {
                        "source": "alienvault",
                        "indicator": indicator,
                        "reputation_score": 0,
                        "risk_level": "Low"
                    }
                },
                details=f"AlienVault OTX reputation retrieved (mock data)."
            )

        try:
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(self.client.get_reputation(indicator))
            
            return ToolResponse(
                tool_name=self.name,
                status="success",
                data={"indicator": indicator, "result": result},
                details=f"AlienVault OTX reputation retrieved successfully."
            )
        except Exception as e:
            return ToolResponse(
                tool_name=self.name,
                status="error",
                data={"indicator": indicator},
                details=f"AlienVault OTX reputation retrieval failed: {str(e)}"
            )

    def handle_request(self, request: ToolRequest) -> ToolResponse:
        command = request.query.lower().strip()
        
        if command.startswith("check ") or command.startswith("check_indicator "):
            parts = command.split()
            if len(parts) >= 2:
                indicator = parts[1]
                return self.check_indicator(indicator)
        
        elif command.startswith("pulse ") or command.startswith("get_pulse "):
            parts = command.split()
            if len(parts) >= 2:
                pulse_id = parts[1]
                return self.get_pulse(pulse_id)
        
        elif command.startswith("search ") or command.startswith("search_ioc "):
            parts = command.split()
            if len(parts) >= 2:
                ioc = parts[1]
                return self.search_ioc(ioc)
        
        elif command.startswith("reputation ") or command.startswith("get_reputation "):
            parts = command.split()
            if len(parts) >= 2:
                indicator = parts[1]
                return self.get_reputation(indicator)
        
        return ToolResponse(
            tool_name=self.name,
            status="error",
            data={},
            details=f"Unknown command: {command}. Available: check_indicator, get_pulse, search_ioc, get_reputation"
        )

    def call_tool(self, command: str) -> ToolResponse:
        """Direct tool call interface for MCP client"""
        request = ToolRequest(query=command)
        return self.handle_request(request)