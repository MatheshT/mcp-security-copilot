"""
Model Context Protocol (MCP) Management & Tool Execution Router
Provides REST endpoints for querying active MCP tools, execution benches,
and inspecting free open-source SOC intelligence connectors.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from ..mcp.registry import mcp_registry

router = APIRouter(prefix="/mcp", tags=["Model Context Protocol (MCP)"])


class ToolExecuteRequest(BaseModel):
    tool_name: str = Field(..., description="Name of the MCP tool to execute (e.g., MalwareBazaar, CISA_KEV, IP_Intel, Wazuh)")
    query: str = Field(..., description="Command or indicator string to send to the tool")
    metadata: Optional[Dict[str, Any]] = Field(default={}, description="Optional metadata or context")


@router.get("/tools", summary="List All Active Model Context Protocol (MCP) Tools")
async def list_mcp_tools():
    """
    Returns the comprehensive registry of tools connected to the AI Copilot via MCP,
    including free open-source SOC tools and local SIEM/EDR endpoints.
    """
    tools_list = []
    
    # Metadata catalog for categorized SOC presentation
    tool_metadata = {
        "MalwareBazaar": {
            "category": "Free Threat Intelligence",
            "provider": "abuse.ch",
            "tier": "100% Free / No API Key Required",
            "icon": "🦠",
            "description": "Searches abuse.ch MalwareBazaar and URLhaus for malware samples, file hashes, and active C2 URLs."
        },
        "CISA_KEV": {
            "category": "Vulnerability Intelligence",
            "provider": "US CISA / DHS",
            "tier": "100% Free / Government Open Data",
            "icon": "🛡️",
            "description": "Validates if CVEs are weaponized in the wild, listed in CISA KEV, or linked to known ransomware campaigns."
        },
        "IP_Intel": {
            "category": "Network & Geolocation Intelligence",
            "provider": "ip-api.com",
            "tier": "100% Free / No API Key Required",
            "icon": "🌐",
            "description": "Real-time Autonomous System Number (ASN), ISP, country, city, reverse DNS PTR, and datacenter/proxy detection."
        },
        "CVE_Search": {
            "category": "Vulnerability Intelligence",
            "provider": "CIRCL / OSV",
            "tier": "100% Free Open Source",
            "icon": "🔍",
            "description": "Free open-source CVE search, CVSS v3 vectors, CWE classifications, and mitigation guidelines."
        },
        "MITRE_ATTACK": {
            "category": "Adversary TTP Framework",
            "provider": "MITRE Corporation",
            "tier": "100% Free Enterprise Matrix",
            "icon": "🗺️",
            "description": "Tactical knowledge engine for adversary tactics, techniques, detection analytics, and defensive mitigations."
        },
        "ML_Threat_Engine": {
            "category": "Machine Learning Anomaly Detection",
            "provider": "scikit-learn / SentinelAI",
            "tier": "Local AI Core / Real-time",
            "icon": "🧠",
            "description": "IsolationForest anomaly scoring, RandomForest severity prediction, and UEBA behavioral drift detection."
        },
        "Wazuh": {
            "category": "SIEM & Fleet Telemetry",
            "provider": "Wazuh v4.14.7",
            "tier": "Open Source SIEM / Enterprise",
            "icon": "🚨",
            "description": "Queries real connected Wazuh agents, active rule alerts, syscheck FIM, and vulnerability detections."
        },
        "SOAR": {
            "category": "Automated Active Defense",
            "provider": "SentinelAI Active Containment",
            "tier": "Autonomous Defense Playbook",
            "icon": "⚡",
            "description": "Executes active firewall blackholing, endpoint isolation, and automated incident response countermeasures."
        },
        "WindowsLogs": {
            "category": "Endpoint Forensics",
            "provider": "Windows Event Collector",
            "tier": "Local OS Telemetry",
            "icon": "💻",
            "description": "Collects live Windows Security (4624/4625), System, and Application event logs."
        },
        "WindowsDefender": {
            "category": "Endpoint Protection (EDR)",
            "provider": "Microsoft Defender",
            "tier": "Local OS Security",
            "icon": "🛡️",
            "description": "Retrieves live Defender antivirus status, real-time protection telemetry, and detected active threats."
        },
        "VirusTotal": {
            "category": "Commercial Threat Intelligence",
            "provider": "VirusTotal / Google Cloud",
            "tier": "Public / Enterprise API",
            "icon": "🔬",
            "description": "Global multi-engine antivirus scanner reports for file hashes, domains, and IP addresses."
        },
        "AbuseIPDB": {
            "category": "Commercial Threat Intelligence",
            "provider": "AbuseIPDB",
            "tier": "Community API",
            "icon": "🎯",
            "description": "Crowdsourced IP reputation and abuse confidence reporting."
        },
        "AlienVault OTX": {
            "category": "Threat Intelligence",
            "provider": "AT&T AlienVault OTX",
            "tier": "Community Pulses",
            "icon": "📡",
            "description": "Open Threat Exchange pulses, adversary campaigns, and related indicators of compromise."
        }
    }

    registered_names = mcp_registry.list_tools()
    
    for name in registered_names:
        meta = tool_metadata.get(name, {
            "category": "Security Tool",
            "provider": "Integrated MCP Server",
            "tier": "Standard",
            "icon": "🔧",
            "description": f"MCP Tool Server for {name}"
        })
        
        tools_list.append({
            "name": name,
            "status": "ONLINE",
            "category": meta["category"],
            "provider": meta["provider"],
            "tier": meta["tier"],
            "icon": meta["icon"],
            "description": meta["description"],
            "is_free": "Free" in meta["tier"] or "Local" in meta["tier"] or "Open Source" in meta["tier"]
        })

    return {
        "status": "success",
        "total_tools": len(tools_list),
        "free_soc_tools_count": len([t for t in tools_list if t["is_free"]]),
        "tools": tools_list
    }


@router.post("/execute", summary="Execute an MCP Tool Directly")
async def execute_mcp_tool(req: ToolExecuteRequest):
    """
    Executes an action against an individual MCP tool and returns raw and normalized tool outputs.
    """
    try:
        response = mcp_registry.call_tool(req.tool_name, req.query, req.metadata)
        return {
            "status": "success",
            "tool_name": response.tool_name,
            "execution_status": response.status,
            "data": response.data,
            "details": response.details
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MCP execution failed: {str(e)}")
