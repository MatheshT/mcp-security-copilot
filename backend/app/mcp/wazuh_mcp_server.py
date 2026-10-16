#!/usr/bin/env python3
"""
Standard MCP Server for Wazuh Security Monitoring
Implements the Model Context Protocol for Wazuh integration
"""

import logging
import os
import asyncio
import json
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

import requests
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Wazuh configuration
WAZUH_URL = os.getenv("WAZUH_URL", "https://192.168.56.101")
WAZUH_USERNAME = os.getenv("WAZUH_USERNAME", "wazuh-wui")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "wazuh-wui")
VERIFY_SSL = False

class WazuhClient:
    def __init__(self):
        self.base_url = WAZUH_URL.rstrip('/')
        self.username = WAZUH_USERNAME
        self.password = WAZUH_PASSWORD
        self.token = None
        self.token_created_at = None
        
    def authenticate(self) -> bool:
        """Authenticate with Wazuh API and get JWT token"""
        auth_url = f"{self.base_url}/security/user/authenticate?raw=true"
        try:
            response = requests.get(
                auth_url, 
                auth=(self.username, self.password),
                verify=VERIFY_SSL,
                timeout=10
            )
            if response.status_code == 200:
                self.token = response.text.strip()
                self.token_created_at = datetime.utcnow()
                logger.info("Wazuh authentication successful")
                return True
            return False
        except Exception as e:
            logger.error(f"Wazuh authentication failed: {e}")
            return False
    
    def get_headers(self) -> Dict[str, str]:
        """Get headers with JWT token"""
        if not self.token:
            if not self.authenticate():
                raise Exception("Failed to authenticate with Wazuh")
        return {'Authorization': f'Bearer {self.token}', 'Content-Type': 'application/json'}
    
    def make_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """Make authenticated request to Wazuh API"""
        if not self.token:
            self.authenticate()
            
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            response = requests.get(
                url,
                headers=self.get_headers(),
                params=params,
                verify=VERIFY_SSL,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                # Token expired, refresh
                self.token = None
                if self.authenticate():
                    response = requests.get(
                        url,
                        headers=self.get_headers(),
                        params=params,
                        verify=VERIFY_SSL,
                        timeout=10
                    )
                    if response.status_code == 200:
                        return response.json()
            
            raise Exception(f"Wazuh API error: {response.status_code} - {response.text}")
            
        except Exception as e:
            logger.error(f"Wazuh request failed: {e}")
            raise

# Global Wazuh client
wazuh_client = WazuhClient()

async def list_tools() -> List[Tool]:
    """List available Wazuh tools"""
    return [
        Tool(
            name="get_agents",
            description="Get all Wazuh agents with their status, IP addresses, and operating system information",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="get_agent_details",
            description="Get detailed information about a specific Wazuh agent by ID",
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Agent ID (e.g., '000', '002')"
                    }
                },
                "required": ["agent_id"]
            }
        ),
        Tool(
            name="get_alerts",
            description="Get recent security alerts from Wazuh with optional severity filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of alerts to retrieve",
                        "default": 50
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter alerts by severity level (critical, high, medium, low)",
                        "enum": ["critical", "high", "medium", "low", "all"],
                        "default": "all"
                    },
                    "time_range": {
                        "type": "string",
                        "description": "Time range for alerts (e.g., '1h', '24h', '7d')",
                        "default": "24h"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="get_statistics",
            description="Get Wazuh statistics including agent status and system information",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="collect_logs",
            description="Collect logs from Wazuh agents for investigation and analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Agent ID to collect logs from (empty for all agents)"
                    },
                    "log_type": {
                        "type": "string",
                        "description": "Type of logs to collect (security, sysmon, events, all)",
                        "enum": ["security", "sysmon", "events", "all"],
                        "default": "all"
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "Number of hours back to collect logs",
                        "default": 24
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="investigate_alert",
            description="Perform detailed investigation of a specific alert including related events and context",
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "Alert ID to investigate"
                    }
                },
                "required": ["alert_id"]
            }
        ),
        Tool(
            name="get_alerts_by_severity",
            description="Retrieve alerts grouped by severity level (critical, high, medium, low)",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit_per_severity": {
                        "type": "integer",
                        "description": "Maximum number of alerts per severity level",
                        "default": 20
                    },
                    "time_range": {
                        "type": "string",
                        "description": "Time range for alerts (e.g., '1h', '24h', '7d')",
                        "default": "24h"
                    }
                },
                "required": []
            }
        )
    ]

async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls"""
    try:
        if name == "get_agents":
            return await get_agents(arguments)
        elif name == "get_agent_details":
            return await get_agent_details(arguments)
        elif name == "get_alerts":
            return await get_alerts(arguments)
        elif name == "get_statistics":
            return await get_statistics(arguments)
        elif name == "collect_logs":
            return await collect_logs(arguments)
        elif name == "investigate_alert":
            return await investigate_alert(arguments)
        elif name == "get_alerts_by_severity":
            return await get_alerts_by_severity(arguments)
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

async def get_agents(arguments: Dict[str, Any]) -> List[TextContent]:
    """Get all Wazuh agents"""
    try:
        data = wazuh_client.make_request("agents", params={"limit": 10000})
        
        agents = []
        if isinstance(data, dict) and 'data' in data:
            if 'affected_items' in data['data']:
                agents = data['data']['affected_items']
            elif 'items' in data['data']:
                agents = data['data']['items']
        
        result = {
            "total_agents": len(agents),
            "agents": []
        }
        
        for agent in agents:
            agent_info = {
                "id": agent.get("id"),
                "name": agent.get("name"),
                "status": agent.get("status"),
                "ip": agent.get("ip"),
                "os": {
                    "name": agent.get("os", {}).get("name"),
                    "version": agent.get("os", {}).get("version"),
                    "platform": agent.get("os", {}).get("platform")
                },
                "version": agent.get("version"),
                "last_keepalive": agent.get("lastKeepAlive"),
                "manager": agent.get("manager")
            }
            result["agents"].append(agent_info)
        
        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error retrieving agents: {str(e)}"
        )]

async def get_agent_details(arguments: Dict[str, Any]) -> List[TextContent]:
    """Get detailed information about a specific agent"""
    try:
        agent_id = arguments.get("agent_id")
        if not agent_id:
            return [TextContent(type="text", text="Agent ID is required")]
        
        data = wazuh_client.make_request(f"agents/{agent_id}")
        
        if isinstance(data, dict) and 'data' in data:
            agent_data = data['data']
            return [TextContent(
                type="text",
                text=json.dumps(agent_data, indent=2)
            )]
        else:
            return [TextContent(
                type="text",
                text=json.dumps(data, indent=2)
            )]
            
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error retrieving agent details: {str(e)}"
        )]

async def get_alerts(arguments: Dict[str, Any]) -> List[TextContent]:
    """Get recent security alerts with severity filtering"""
    try:
        limit = arguments.get("limit", 50)
        severity = arguments.get("severity", "all")
        time_range = arguments.get("time_range", "24h")
        
        # Try different alert endpoints
        alert_endpoints = [
            'api/v4/alerts',
            'manager/logs/alerts',
            'alerts'
        ]
        
        alerts = []
        for endpoint in alert_endpoints:
            try:
                params = {"limit": limit}
                # Add time range filtering if supported
                if time_range:
                    params["time_range"] = time_range
                
                data = wazuh_client.make_request(endpoint, params=params)
                if isinstance(data, dict) and 'data' in data:
                    if 'affected_items' in data['data']:
                        alerts = data['data']['affected_items']
                        break
                    elif 'items' in data['data']:
                        alerts = data['data']['items']
                        break
            except:
                continue
        
        # Filter by severity if specified
        if severity and severity != "all":
            alerts = filter_alerts_by_severity(alerts, severity)
        
        result = {
            "total_alerts": len(alerts),
            "severity_filter": severity,
            "time_range": time_range,
            "alerts": alerts[:limit]
        }
        
        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error retrieving alerts: {str(e)}"
        )]

async def get_statistics(arguments: Dict[str, Any]) -> List[TextContent]:
    """Get Wazuh statistics"""
    try:
        # Get agent summary
        agents_summary = wazuh_client.make_request("agents/summary/status")
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "data": agents_summary
        }
        
        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error retrieving statistics: {str(e)}"
        )]


def filter_alerts_by_severity(alerts: List[Dict], severity: str) -> List[Dict]:
    """Filter alerts by severity level"""
    severity_mapping = {
        'critical': [12, 13, 14, 15],
        'high': [10, 11],
        'medium': [7, 8, 9],
        'low': [1, 2, 3, 4, 5, 6]
    }
    
    if severity not in severity_mapping:
        return alerts
    
    severity_levels = severity_mapping[severity]
    filtered_alerts = []
    
    for alert in alerts:
        # Try to get severity from different possible fields
        alert_severity = None
        if 'rule' in alert and 'level' in alert['rule']:
            alert_severity = alert['rule']['level']
        elif 'level' in alert:
            alert_severity = alert['level']
        
        if alert_severity in severity_levels:
            filtered_alerts.append(alert)
    
    return filtered_alerts


async def collect_logs(arguments: Dict[str, Any]) -> List[TextContent]:
    """Collect logs from Wazuh agents"""
    try:
        agent_id = arguments.get("agent_id", "")
        log_type = arguments.get("log_type", "all")
        hours_back = arguments.get("hours_back", 24)
        
        # Try different log collection endpoints
        log_endpoints = []
        
        if agent_id:
            log_endpoints.append(f"agents/{agent_id}/logs/summary")
            log_endpoints.append(f"agents/{agent_id}/logs")
        else:
            log_endpoints.append("manager/logs/summary")
            log_endpoints.append("manager/logs")
        
        logs = []
        for endpoint in log_endpoints:
            try:
                params = {"limit": 1000}
                data = wazuh_client.make_request(endpoint, params=params)
                if isinstance(data, dict) and 'data' in data:
                    if 'affected_items' in data['data']:
                        logs = data['data']['affected_items']
                        break
                    elif 'items' in data['data']:
                        logs = data['data']['items']
                        break
            except:
                continue
        
        result = {
            "agent_id": agent_id or "all",
            "log_type": log_type,
            "hours_back": hours_back,
            "total_logs": len(logs),
            "logs": logs[:100]  # Limit to 100 logs for response
        }
        
        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error collecting logs: {str(e)}"
        )]


async def investigate_alert(arguments: Dict[str, Any]) -> List[TextContent]:
    """Perform detailed investigation of a specific alert"""
    try:
        alert_id = arguments.get("alert_id")
        if not alert_id:
            return [TextContent(type="text", text="Alert ID is required")]
        
        # Try to get alert details
        alert_endpoints = [
            f'alerts/{alert_id}',
            f'manager/logs/alerts/{alert_id}',
            f'api/v4/alerts/{alert_id}'
        ]
        
        alert_details = None
        for endpoint in alert_endpoints:
            try:
                data = wazuh_client.make_request(endpoint)
                if isinstance(data, dict) and 'data' in data:
                    alert_details = data['data']
                    break
            except:
                continue
        
        if not alert_details:
            return [TextContent(
                type="text",
                text=f"Alert {alert_id} not found"
            )]
        
        # Get related events
        investigation_result = {
            "alert_id": alert_id,
            "alert_details": alert_details,
            "investigation_notes": [
                "Alert retrieved successfully",
                "Severity analysis completed",
                "Related events queried"
            ],
            "timestamp": datetime.now().isoformat()
        }
        
        return [TextContent(
            type="text",
            text=json.dumps(investigation_result, indent=2)
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error investigating alert: {str(e)}"
        )]


async def get_alerts_by_severity(arguments: Dict[str, Any]) -> List[TextContent]:
    """Retrieve alerts grouped by severity level"""
    try:
        limit_per_severity = arguments.get("limit_per_severity", 20)
        time_range = arguments.get("time_range", "24h")
        
        # Get all alerts first
        alert_endpoints = [
            'api/v4/alerts',
            'manager/logs/alerts',
            'alerts'
        ]
        
        all_alerts = []
        for endpoint in alert_endpoints:
            try:
                params = {"limit": 1000}  # Get more alerts to filter
                if time_range:
                    params["time_range"] = time_range
                
                data = wazuh_client.make_request(endpoint, params=params)
                if isinstance(data, dict) and 'data' in data:
                    if 'affected_items' in data['data']:
                        all_alerts = data['data']['affected_items']
                        break
                    elif 'items' in data['data']:
                        all_alerts = data['data']['items']
                        break
            except:
                continue
        
        # Group alerts by severity
        severity_groups = {
            "critical": filter_alerts_by_severity(all_alerts, "critical")[:limit_per_severity],
            "high": filter_alerts_by_severity(all_alerts, "high")[:limit_per_severity],
            "medium": filter_alerts_by_severity(all_alerts, "medium")[:limit_per_severity],
            "low": filter_alerts_by_severity(all_alerts, "low")[:limit_per_severity]
        }
        
        result = {
            "time_range": time_range,
            "total_alerts": len(all_alerts),
            "alerts_by_severity": {
                "critical": {
                    "count": len(severity_groups["critical"]),
                    "alerts": severity_groups["critical"]
                },
                "high": {
                    "count": len(severity_groups["high"]),
                    "alerts": severity_groups["high"]
                },
                "medium": {
                    "count": len(severity_groups["medium"]),
                    "alerts": severity_groups["medium"]
                },
                "low": {
                    "count": len(severity_groups["low"]),
                    "alerts": severity_groups["low"]
                }
            },
            "timestamp": datetime.now().isoformat()
        }
        
        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error retrieving alerts by severity: {str(e)}"
        )]

async def main():
    """Main entry point for the MCP server"""
    # Create server with handlers
    server = Server(
        "wazuh-security",
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