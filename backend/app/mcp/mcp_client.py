import os
from typing import Any, Dict, Optional, List
import logging
from .tool_server import ToolRequest, ToolResponse

logger = logging.getLogger(__name__)

class MCPClient:
    TOOL_ALIASES = {
        'wazuh_get_alerts': 'Wazuh',
        'virustotal_lookup': 'VirusTotal',
        'wazuh_alerts': 'Wazuh',
        'virustotal': 'VirusTotal',
        'wazuh': 'Wazuh',
        'malwarebazaar': 'MalwareBazaar',
        'malware_bazaar': 'MalwareBazaar',
        'urlhaus': 'MalwareBazaar',
        'abusech': 'MalwareBazaar',
        'cisa': 'CISA_KEV',
        'cisa_kev': 'CISA_KEV',
        'kev': 'CISA_KEV',
        'ip_intel': 'IP_Intel',
        'ipapi': 'IP_Intel',
        'ip_api': 'IP_Intel',
        'ip_lookup': 'IP_Intel',
        'cve_search': 'CVE_Search',
        'circl': 'CVE_Search',
        'cve': 'CVE_Search',
        'mitre': 'MITRE_ATTACK',
        'mitre_attack': 'MITRE_ATTACK',
        'ttp': 'MITRE_ATTACK',
        'ml': 'ML_Threat_Engine',
        'ml_threat': 'ML_Threat_Engine',
        'ml_engine': 'ML_Threat_Engine',
        'ml_threat_engine': 'ML_Threat_Engine',
        'mldetection': 'ML_Threat_Engine',
        'soar': 'SOAR',
        'windowslogs': 'WindowsLogs',
        'windowsdefender': 'WindowsDefender',
        'abuseipdb': 'AbuseIPDB',
        'alienvault': 'AlienVault OTX',
        'alienvault_otx': 'AlienVault OTX'
    }

    def __init__(self, registry: Optional[Dict[str, Any]] = None):
        self.registry = registry or {}
        self.provider = os.getenv('MCP_PROVIDER', 'local').lower()
        self._cache = {}
        logger.info(f"MCP Client initialized with provider: {self.provider}")

    def register_tool(self, tool_name: str, tool_server: Any) -> None:
        self.registry[tool_name] = tool_server
        logger.info(f"Registered tool: {tool_name}")

    def get_tool(self, tool_name: str) -> Any:
        actual_name = self.TOOL_ALIASES.get(tool_name, tool_name)
        tool = self.registry.get(actual_name)
        if not tool:
            raise ValueError(f'Tool not registered: {tool_name}')
        return tool

    def call_tool(self, tool_name: str, query: str, metadata: Optional[Dict[str, Any]] = None) -> ToolResponse:
        """Call a tool with the given query and metadata"""
        try:
            tool = self.get_tool(tool_name)
            request = ToolRequest(query=query, metadata=metadata or {})
            response = tool.handle_request(request)
            
            # Cache successful responses for dashboard
            if tool_name in ['wazuh_alerts', 'virustotal_lookup']:
                cache_key = f"{tool_name}:{query}"
                self._cache[cache_key] = response
            
            return response
        except Exception as e:
            logger.error(f"Error calling tool {tool_name}: {e}")
            return ToolResponse(
                tool_name=tool_name,
                status='error',
                data={},
                details=str(e)
            )

    def list_tools(self) -> List[str]:
        return list(self.registry.keys())

    def get_cached_response(self, tool_name: str, query: str) -> Optional[ToolResponse]:
        """Get cached response for a tool"""
        cache_key = f"{tool_name}:{query}"
        return self._cache.get(cache_key)

    async def call_tool_async(self, tool_name: str, query: str, metadata: Optional[Dict[str, Any]] = None) -> ToolResponse:
        """Async version of call_tool"""
        return self.call_tool(tool_name, query, metadata)

    def batch_call_tools(self, tool_calls: List[Dict[str, Any]]) -> Dict[str, ToolResponse]:
        """Call multiple tools in batch"""
        results = {}
        for call in tool_calls:
            tool_name = call.get('tool_name')
            query = call.get('query', '')
            metadata = call.get('metadata', {})
            
            try:
                results[tool_name] = self.call_tool(tool_name, query, metadata)
            except Exception as e:
                results[tool_name] = ToolResponse(
                    tool_name=tool_name,
                    status='error',
                    data={},
                    details=str(e)
                )
        return results

    def clear_cache(self) -> None:
        """Clear the cache"""
        self._cache.clear()
        logger.info("Cache cleared")

    def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> ToolResponse:
        """Execute a tool with parameters (alias for call_tool)"""
        query = params.get('query', '')
        metadata = params.get('metadata', {})
        return self.call_tool(tool_name, query, metadata)