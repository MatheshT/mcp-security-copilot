#!/usr/bin/env python3
"""
Standard MCP Server for AbuseIPDB
Implements the Model Context Protocol for AbuseIPDB integration
"""

import logging
import os
import asyncio
import json
from typing import Any, Dict, List, Optional

import requests
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# AbuseIPDB configuration
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

class AbuseIPDBClient:
    def __init__(self):
        self.api_key = ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2"
        if self.api_key:
            logger.info("AbuseIPDB API Key Loaded")
        else:
            logger.warning("AbuseIPDB API key not set - using mock data")
    
    def get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Key"] = self.api_key
        return headers
    
    def make_request(self, endpoint: str) -> Dict:
        if not self.api_key:
            raise ValueError("ABUSEIPDB_API_KEY is not configured")
        
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            response = requests.get(
                url,
                headers=self.get_headers(),
                timeout=15
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"AbuseIPDB API request failed: {e}")
            raise

# Global AbuseIPDB client
abuseipdb_client = AbuseIPDBClient()

async def list_tools() -> List[Tool]:
    """List available AbuseIPDB tools"""
    return [
        Tool(
            name="check_ip",
            description="Check IP address reputation and abuse reports from AbuseIPDB",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP address to check (e.g., 8.8.8.8)"
                    }
                },
                "required": ["ip"]
            }
        ),
        Tool(
            name="report_ip",
            description="Report an IP address to AbuseIPDB",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP address to report"
                    },
                    "categories": {
                        "type": "array",
                        "description": "Abuse categories",
                        "items": {"type": "integer"}
                    }
                },
                "required": ["ip"]
            }
        ),
        Tool(
            name="get_blacklist",
            description="Get the AbuseIPDB blacklist",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results",
                        "default": 1000
                    }
                },
                "required": []
            }
        )
    ]

async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls"""
    try:
        if name == "check_ip":
            return await check_ip(arguments)
        elif name == "report_ip":
            return await report_ip(arguments)
        elif name == "get_blacklist":
            return await get_blacklist(arguments)
        else:
            return [TextContent(
                type="text",
                text=f"Unknown tool: {name}"
            )]
    except Exception as e:
        logger.error(f"Tool execution error: {e}")
        return [TextContent(
            type="text",
            text=f"Error executing tool {name}: {str(e)}"
        )]

async def check_ip(arguments: Dict[str, Any]) -> List[TextContent]:
    """Check IP address"""
    try:
        ip = arguments.get("ip")
        if not ip:
            return [TextContent(type="text", text="IP address is required")]
        
        if not abuseipdb_client.api_key:
            # Mock response for demonstration
            result = {
                "source": "abuseipdb",
                "ip_address": ip,
                "abuse_confidence_score": 75,
                "total_reports": 15,
                "country_code": "US",
                "isp": "Mock ISP",
                "risk_level": "High"
            }
        else:
            result = abuseipdb_client.make_request(f"check/{ip}")
        
        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error checking IP: {str(e)}"
        )]

async def report_ip(arguments: Dict[str, Any]) -> List[TextContent]:
    """Report IP address"""
    try:
        ip = arguments.get("ip")
        categories = arguments.get("categories", [22, 23])
        
        if not ip:
            return [TextContent(type="text", text="IP address is required")]
        
        if not abuseipdb_client.api_key:
            result = {"status": "mock", "ip": ip}
        else:
            result = abuseipdb_client.make_request(f"report", params={
                "ip": ip,
                "categories": categories,
                "comment": "Reported via MCP"
            })
        
        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error reporting IP: {str(e)}"
        )]

async def get_blacklist(arguments: Dict[str, Any]) -> List[TextContent]:
    """Get blacklist"""
    try:
        limit = arguments.get("limit", 1000)
        
        if not abuseipdb_client.api_key:
            result = {"blacklist": [], "status": "mock"}
        else:
            result = abuseipdb_client.make_request(f"blacklist", params={"limit": limit})
        
        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error getting blacklist: {str(e)}"
        )]

async def main():
    """Main entry point for the MCP server"""
    server = Server(
        "abuseipdb-threat-intel",
        on_list_tools=list_tools,
        on_call_tool=call_tool
    )
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())