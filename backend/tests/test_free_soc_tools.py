import pytest
from app.mcp.registry import mcp_registry

def test_mcp_registry_contains_all_16_tools():
    assert mcp_registry is not None
    tools = mcp_registry.list_tools()
    assert len(tools) >= 12
    
    # Check Free Community SOC Tools
    assert "MalwareBazaar" in tools
    assert "URLhaus" in tools
    assert "CISA_KEV" in tools
    assert "IP_Intel" in tools
    assert "CVE_Search" in tools
    assert "MITRE_ATTACK" in tools
    assert "ML_Threat_Engine" in tools

def test_cisa_kev_tool_call():
    res = mcp_registry.call_tool("CISA_KEV", "CVE-2021-44228")
    assert res is not None
    assert res.status in ["success", "operational"]

def test_ipapi_private_ip_call():
    res = mcp_registry.call_tool("IP_Intel", "192.168.1.1")
    assert res is not None
    assert res.status in ["success", "operational"]

def test_circl_cve_tool_call():
    res = mcp_registry.call_tool("CVE_Search", "CVE-2021-44228")
    assert res is not None
    assert res.status in ["success", "operational"]

def test_mitre_attack_tool_call():
    res = mcp_registry.call_tool("MITRE_ATTACK", "T1110")
    assert res is not None
    assert res.status in ["success", "operational"]
