#!/usr/bin/env python3
"""
Standard MCP Server for VirusTotal Threat Intelligence
Implements the Model Context Protocol for VirusTotal integration
"""

import logging
import os
import asyncio
import json
import base64
import re
from typing import Any, Dict, List, Optional

import requests
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# VirusTotal configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_API_URL = os.getenv("VIRUSTOTAL_API_URL", "https://www.virustotal.com/api/v3")

class VirusTotalClient:
    def __init__(self):
        self.base_url = VIRUSTOTAL_API_URL.rstrip('/')
        self.api_key = VIRUSTOTAL_API_KEY
        if self.api_key:
            masked = f"{self.api_key[:4]}...{self.api_key[-4:]}"
            logger.info(f"VirusTotal API Key Loaded: {masked}")
        else:
            logger.warning("VirusTotal API key not set")
        
    def get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["x-apikey"] = self.api_key
        return headers
    
    def make_request(self, endpoint: str) -> Dict:
        if not self.api_key:
            raise ValueError("VIRUSTOTAL_API_KEY is not configured")
        
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
            logger.error(f"VirusTotal API request failed: {e}")
            raise

# Global VirusTotal client
virustotal_client = VirusTotalClient()

async def list_tools() -> List[Tool]:
    """List available VirusTotal tools"""
    return [
        Tool(
            name="check_ip",
            description="Check IP address reputation and analysis from VirusTotal",
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
            name="check_domain",
            description="Check domain reputation and analysis from VirusTotal",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain to check (e.g., example.com)"
                    }
                },
                "required": ["domain"]
            }
        ),
        Tool(
            name="check_url",
            description="Check URL reputation and analysis from VirusTotal",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to check (e.g., https://example.com)"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="check_hash",
            description="Check file hash reputation and analysis from VirusTotal",
            inputSchema={
                "type": "object",
                "properties": {
                    "hash": {
                        "type": "string",
                        "description": "File hash to check (MD5, SHA1, or SHA256)"
                    }
                },
                "required": ["hash"]
            }
        )
    ]

async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls"""
    try:
        if name == "check_ip":
            return await check_ip(arguments)
        elif name == "check_domain":
            return await check_domain(arguments)
        elif name == "check_url":
            return await check_url(arguments)
        elif name == "check_hash":
            return await check_hash(arguments)
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
        
        payload = virustotal_client.make_request(f"ip_addresses/{ip}")
        data_obj = payload.get("data", {})
        attributes = data_obj.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        
        if malicious > 0:
            rep_label = "Malicious"
        elif suspicious > 0:
            rep_label = "Suspicious"
        elif harmless > 0:
            rep_label = "Clean"
        else:
            rep_label = "Unknown"
        
        result = {
            "id": ip,
            "ip": ip,
            "reputation": rep_label,
            "country": attributes.get("country", "Unknown"),
            "detections": malicious,
            "confidence": f"{min(99, 60 + malicious * 3)}%",
            "as_owner": attributes.get("as_owner", "Unknown"),
            "tags": attributes.get("tags", []),
            "last_analysis_stats": stats,
            "category": attributes.get("network", "IP Infrastructure")
        }
        
        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error checking IP: {str(e)}"
        )]

async def check_domain(arguments: Dict[str, Any]) -> List[TextContent]:
    """Check domain"""
    try:
        domain = arguments.get("domain")
        if not domain:
            return [TextContent(type="text", text="Domain is required")]
        
        payload = virustotal_client.make_request(f"domains/{domain}")
        data_obj = payload.get("data", {})
        attributes = data_obj.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        rep_label = "Malicious" if malicious > 0 else ("Suspicious" if suspicious > 0 else "Clean")
        
        result = {
            "id": domain,
            "domain": domain,
            "reputation": rep_label,
            "detections": malicious,
            "categories": list(attributes.get("categories", {}).values())[:5],
            "registrar": attributes.get("registrar", "Unknown"),
            "last_analysis_stats": stats
        }
        
        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error checking domain: {str(e)}"
        )]

async def check_url(arguments: Dict[str, Any]) -> List[TextContent]:
    """Check URL"""
    try:
        url = arguments.get("url")
        if not url:
            return [TextContent(type="text", text="URL is required")]
        
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        payload = virustotal_client.make_request(f"urls/{url_id}")
        data_obj = payload.get("data", {})
        attributes = data_obj.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        rep_label = "Malicious" if malicious > 0 else "Clean"
        
        result = {
            "id": url,
            "url": url,
            "reputation": rep_label,
            "detections": malicious,
            "title": attributes.get("title", "N/A"),
            "last_analysis_stats": stats
        }
        
        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error checking URL: {str(e)}"
        )]

async def check_hash(arguments: Dict[str, Any]) -> List[TextContent]:
    """Check file hash"""
    try:
        file_hash = arguments.get("hash")
        if not file_hash:
            return [TextContent(type="text", text="File hash is required")]
        
        payload = virustotal_client.make_request(f"files/{file_hash}")
        data_obj = payload.get("data", {})
        attributes = data_obj.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        rep_label = "Malicious" if malicious > 0 else "Clean"
        
        result = {
            "id": file_hash,
            "hash": file_hash,
            "reputation": rep_label,
            "detections": malicious,
            "meaningful_name": attributes.get("meaningful_name") or attributes.get("type_description"),
            "file_type": attributes.get("type_description", "Executable"),
            "size_bytes": attributes.get("size", 0),
            "last_analysis_stats": stats
        }
        
        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error checking hash: {str(e)}"
        )]

async def main():
    """Main entry point for the MCP server"""
    server = Server(
        "virustotal-security",
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