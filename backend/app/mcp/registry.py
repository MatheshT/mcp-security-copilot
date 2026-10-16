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


def create_mcp_client() -> MCPClient:
    client = MCPClient()
    client.register_tool("WindowsLogs", WindowsLogsServer())
    client.register_tool("WindowsDefender", WindowsDefenderServer())
    client.register_tool("Wazuh", WazuhServer())
    client.register_tool("VirusTotal", VirusTotalServer())
    client.register_tool("MISP", MISPServer())
    client.register_tool("Shodan", ShodanServer())
    client.register_tool("AbuseIPDB", AbuseIPDBServer())
    client.register_tool("AlienVault OTX", AlienVaultServer())
    client.register_tool("SOAR", SOARServer())
    return client


# Global registry instance
mcp_registry = create_mcp_client()