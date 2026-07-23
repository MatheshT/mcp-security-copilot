from .mcp_client import MCPClient
from .virustotal_server import VirusTotalServer
from .wazuh_server import WazuhServer
from .misp_server import MISPServer


def create_mcp_client() -> MCPClient:
    client = MCPClient()
    client.register_tool("Wazuh", WazuhServer())
    client.register_tool("VirusTotal", VirusTotalServer())
    client.register_tool("MISP", MISPServer())
    return client


# Global registry instance
mcp_registry = create_mcp_client()