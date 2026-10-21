from .mcp_client import MCPClient
from .virustotal_server import VirusTotalServer
from .windows_logs_server import WindowsLogsServer
from .windows_defender_server import WindowsDefenderServer
from .wazuh_server import WazuhServer
from .misp_server import MISPServer
from .shodan_server import ShodanServer
from .abuseipdb_server import AbuseIPDBServer
from .alienvault_server import AlienVaultServer
from .soar_server import SOARServer

# Free SOC Tools MCP Servers
from .abusech_server import AbuseCHServer
from .cisa_kev_server import CISAKEVServer
from .ipapi_server import IPAPIServer
from .circl_cve_server import CIRCLCveServer
from .mitre_attack_server import MitreAttackServer
from .ml_threat_server import MLThreatMCPServer


def create_mcp_client() -> MCPClient:
    client = MCPClient()
    # Core Endpoint & SIEM Tools
    client.register_tool("WindowsLogs", WindowsLogsServer())
    client.register_tool("WindowsDefender", WindowsDefenderServer())
    client.register_tool("Wazuh", WazuhServer())
    client.register_tool("SOAR", SOARServer())

    # Free Community SOC Tools (Zero API Key Required)
    abuse_server = AbuseCHServer()
    client.register_tool("MalwareBazaar", abuse_server)
    client.register_tool("URLhaus", abuse_server)
    client.register_tool("CISA_KEV", CISAKEVServer())
    client.register_tool("IP_Intel", IPAPIServer())
    client.register_tool("CVE_Search", CIRCLCveServer())
    client.register_tool("MITRE_ATTACK", MitreAttackServer())
    client.register_tool("ML_Threat_Engine", MLThreatMCPServer())

    # Commercial / API Key Threat Intel Tools
    client.register_tool("VirusTotal", VirusTotalServer())
    client.register_tool("MISP", MISPServer())
    client.register_tool("Shodan", ShodanServer())
    client.register_tool("AbuseIPDB", AbuseIPDBServer())
    client.register_tool("AlienVault OTX", AlienVaultServer())

    return client


# Global registry instance
mcp_registry = create_mcp_client()
