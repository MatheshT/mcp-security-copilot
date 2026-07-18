from .mcp_client import MCPClient
from .virustotal_server import VirusTotalServer
from .wazuh_server import WazuhServer


def create_mcp_client() -> MCPClient:
    client = MCPClient()
    client.register_tool("Wazuh", WazuhServer())
    client.register_tool("VirusTotal", VirusTotalServer())
    return client


# Global registry instance
mcp_registry = create_mcp_client()