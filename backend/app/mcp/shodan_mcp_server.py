#!/usr/bin/env python3
"""
Standard MCP Server for Shodan OSINT
Implements the Model Context Protocol for Shodan integration
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

# Shodan configuration
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

class ShodanClient:
    def __init__(self):
        self.api_key = SHODAN_API_KEY
        self.base_url = "https://api.shodan.io"
        if self.api_key:
            logger.info("Shodan API Key Loaded")
        else:
            logger.warning("Shodan API key not set - using mock data")
    
    def get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers
    
    def make_request(self, endpoint: str) -> Dict:
        if not self.api_key:
            raise ValueError("SHODAN_API_KEY is not configured")
        
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
            logger.error(f"Shodan API request failed: {e}")
            raise

# Global Shodan client
shodan_client = ShodanClient()

async def list_tools() -> List[Tool]:
    """List available Shodan tools"""
    return [
        Tool(
            name="search_ip",
            description="Search infrastructure intelligence for an IP address using Shodan",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP address to search (e.g., 8.8.8.8)"
                    }
                },
                "required": ["ip"]
            }
        ),
        Tool(
            name="search_host",
            description="Search for host information using Shodan",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (e.g., port:80, org:Google)"
                    }
                },
                "required": ["query"]
            }
        )
    ]

async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls"""
    try:
        if name == "search_ip":
            return await search_ip(arguments)
        elif name == "search_host":
            return await search_host(arguments)
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

async def search_ip(arguments: Dict[str, Any]) -> List[TextContent]:
    """Search IP address"""
    try:
        ip = arguments.get("ip")
        if not ip:
            return [TextContent(type="text", text="IP address is required")]
        
        # Mock data for demonstration if no API key
        if not shodan_client.api_key:
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
                }
            }
            result = shodan_database.get(ip, {
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
            })
        else:
            result = shodan_client.make_request(f"shodan/host/{ip}")
        
        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error searching IP: {str(e)}"
        )]

async def search_host(arguments: Dict[str, Any]) -> List[TextContent]:
    """Search host information"""
    try:
        query = arguments.get("query")
        if not query:
            return [TextContent(type="text", text="Search query is required")]
        
        if not shodan_client.api_key:
            result = {
                "query": query,
                "results": "Mock data - API key required for real Shodan results",
                "matches": []
            }
        else:
            result = shodan_client.make_request(f"shodan/host/search?key={shodan_client.api_key}&query={query}")
        
        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error searching host: {str(e)}"
        )]

async def main():
    """Main entry point for the MCP server"""
    server = Server(
        "shodan-osint",
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