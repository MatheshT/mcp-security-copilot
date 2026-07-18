import os
import re
from typing import Any, Dict, List, Optional

from .correlation_engine import build_unified_investigation_result
from .llm_client import LLMClient
from .mcp.registry import create_mcp_client
from .mcp.tool_server import ToolResponse
from .report_generator import generate_report_json, generate_report_html


class SecurityCopilotOrchestrator:
    def __init__(self):
        self.llm_client = LLMClient()
        self.mcp_client = create_mcp_client()
        self.default_tools = [
            tool.strip() 
            for tool in os.getenv('DEFAULT_SECURITY_TOOLS', 'Wazuh,VirusTotal').split(',') 
            if tool.strip()
        ]

    def analyze_query(self, query: str) -> Dict[str, Any]:
        """
        Main orchestration method that processes user queries through:
        1. LLM intent analysis
        2. Tool execution (Wazuh, VirusTotal, etc.)
        3. Correlation and report generation
        4. Natural language response generation
        """
        # Step 1: Get intent and required tools from LLM
        llm_result = self.llm_client.get_intent_and_tools(query)
        tools = llm_result.get('required_tools') or self.default_tools
        
        # Step 2: Execute tools
        responses: List[ToolResponse] = []
        extracted_data = {
            'source_ip': None,
            'destination_ip': None,
            'affected_host': None,
            'alerts': [],
            'iocs': [],
            'vt_results': {}
        }
        
        for tool_name in tools:
            tool_name = tool_name.strip()
            tool_name_lower = tool_name.lower()  # Convert to lowercase for case-insensitive matching
            
            if tool_name_lower == "wazuh":
                print("=" * 50)
                print("CALLING WAZUH")
                
                # Get alerts from Wazuh
                wazuh_response = self.mcp_client.call_tool("Wazuh", "get_alerts")
                responses.append(wazuh_response)
                
                # Extract data from Wazuh response
                if wazuh_response.data:
                    alerts = wazuh_response.data.get("alerts", [])
                    print("Alerts:", alerts)
                    
                    # Find the specific alert requested in the query
                    requested_alert = self._extract_alert_id(query)
                    selected_alert = None
                    
                    if requested_alert:
                        selected_alert = next(
                            (
                                alert
                                for alert in alerts
                                if str(alert.get("alert_id")) == requested_alert
                            ),
                            None,
                        )
                    
                    # If no specific alert found, use the first one
                    if selected_alert is None and alerts:
                        selected_alert = alerts[0]
                    
                    alert_source_ip = None
                    
                    if selected_alert:
                        alert_source_ip = selected_alert.get("source_ip")
                        extracted_data['alerts'] = [selected_alert]
                        
                        # Extract data from selected alert
                        raw = selected_alert.get("raw", {})
                        
                        # Extract source IP
                        extracted_data['source_ip'] = (
                            selected_alert.get("source_ip") 
                            or raw.get("src_ip") 
                            or raw.get("source_ip")
                            or raw.get("ip")
                        )
                        
                        # Extract destination IP
                        extracted_data['destination_ip'] = (
                            selected_alert.get("destination_ip") 
                            or raw.get("dst_ip") 
                            or raw.get("destination_ip")
                        )
                        
                        # Extract affected host (prioritize hostname over agent)
                        extracted_data['affected_host'] = (
                            selected_alert.get("hostname")
                            or raw.get("hostname")
                            or selected_alert.get("agent")
                            or raw.get("agent")
                            or raw.get("computer")
                            or raw.get("host")
                        )
                        
                        # Extract IOCs from alert
                        for field in ["src_ip", "source_ip", "ip", "dst_ip", "destination_ip"]:
                            if field in raw and raw[field]:
                                extracted_data['iocs'].append({
                                    "indicator": raw[field],
                                    "type": "ip"
                                })
                        
                        # Extract hashes if present
                        for field in ["hash", "md5", "sha1", "sha256"]:
                            if field in raw and raw[field]:
                                extracted_data['iocs'].append({
                                    "indicator": raw[field],
                                    "type": "hash"
                                })
                        
                        print(f"Selected Alert ID: {selected_alert.get('alert_id')}")
                        print(f"Extracted Source IP: {extracted_data['source_ip']}")
                        print(f"Extracted Destination IP: {extracted_data['destination_ip']}")
                        print(f"Extracted Affected Host: {extracted_data['affected_host']}")
                        print(f"Extracted IOCs: {extracted_data['iocs']}")
                    else:
                        # No alerts found
                        print("No alerts found in Wazuh response")
                
                print("=" * 50)
            
            elif tool_name_lower == "virustotal":
                print("=" * 50)
                print("CALLING VIRUSTOTAL")
                
                # Use extracted source IP or fallback to query extraction
                ip_to_check = (
                    extracted_data['source_ip'] 
                    or self._extract_ip(query) 
                    or '8.8.8.8'
                )
                
                print(f"Checking IP: {ip_to_check}")
                
                vt_response = self.mcp_client.call_tool(
                    "VirusTotal",
                    f"check_ip {ip_to_check}"
                )
                responses.append(vt_response)
                
                # Extract VT results
                if vt_response.data:
                    extracted_data['vt_results'] = vt_response.data
                    print(f"VT Results: {extracted_data['vt_results']}")
                
                print("=" * 50)
            
            elif tool_name_lower == "shodan":
                print("=" * 50)
                print("CALLING SHODAN")
                
                ip_to_check = (
                    extracted_data['source_ip'] 
                    or self._extract_ip(query) 
                    or '8.8.8.8'
                )
                
                shodan_response = self.mcp_client.call_tool(
                    "Shodan",
                    f"search {ip_to_check}"
                )
                responses.append(shodan_response)
                
                print("=" * 50)
            
            elif tool_name_lower == "misp":
                print("=" * 50)
                print("CALLING MISP")
                
                # Check for hashes or IPs in MISP
                indicators = []
                if extracted_data['iocs']:
                    for ioc in extracted_data['iocs']:
                        indicators.append(ioc['indicator'])
                
                # If no IOCs, extract from query
                if not indicators:
                    ip = self._extract_ip(query)
                    if ip and ip != '8.8.8.8':
                        indicators.append(ip)
                    hash_val = self._extract_hash(query)
                    if hash_val:
                        indicators.append(hash_val)
                
                for indicator in indicators[:3]:  # Limit to 3 indicators
                    misp_response = self.mcp_client.call_tool(
                        "MISP",
                        f"search {indicator}"
                    )
                    responses.append(misp_response)
                
                print("=" * 50)
        
        # Step 3: Build unified investigation result
        tool_dicts = [response.dict() for response in responses]
        unified = build_unified_investigation_result(tool_dicts)
        
        # Step 4: Enhance unified data with extracted fields
        if extracted_data['source_ip']:
            unified['source_ip'] = extracted_data['source_ip']
        if extracted_data['destination_ip']:
            unified['destination_ip'] = extracted_data['destination_ip']
        if extracted_data['affected_host']:
            unified['affected_host'] = extracted_data['affected_host']
        if extracted_data['iocs']:
            unified['ioc_data'] = extracted_data['iocs']
        if extracted_data['vt_results']:
            unified['vt_results'] = extracted_data['vt_results']
        if extracted_data['alerts']:
            if 'details' not in unified:
                unified['details'] = {}
            unified['details']['alerts'] = extracted_data['alerts']
        
        # Step 5: Generate report
        report_json = generate_report_json(
            unified,
            alert_id=unified.get('alert_id'),
            timestamp=None,  # Will use current time
            attack_type=unified.get('attack_type'),  # Will be detected by _detect_attack
            recommendations=[llm_result.get('recommendation')] if llm_result.get('recommendation') else []
        )
        report_html = generate_report_html(report_json)
        
        # Step 6: Generate AI natural language response
        ai_answer = self.llm_client.generate_response(
            query,
            report_json
        )
        
        # Step 7: Return complete result with AI answer
        return {
            'llm': llm_result,
            'tool_responses': tool_dicts,
            'unified_investigation': unified,
            'report_json': report_json,
            'report_html': report_html,
            'ai_answer': ai_answer,
            'extracted_data': extracted_data
        }

    def _extract_ip(self, query: str) -> Optional[str]:
        """Extract IP address from query string"""
        # IPv4 pattern
        ipv4_pattern = r'(\b(?:\d{1,3}\.){3}\d{1,3}\b)'
        match = re.search(ipv4_pattern, query)
        
        if match:
            ip = match.group(0)
            # Validate IP (simple check)
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return ip
        
        return None

    def _extract_alert_id(self, query: str) -> Optional[str]:
        """Extract alert ID from query string"""
        match = re.search(r"\b(\d+)\b", query)
        return match.group(1) if match else None

    def _extract_hash(self, query: str) -> Optional[str]:
        """Extract hash (MD5, SHA1, SHA256) from query string"""
        # MD5: 32 hex chars
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        # SHA1: 40 hex chars
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        # SHA256: 64 hex chars
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        
        patterns = [md5_pattern, sha1_pattern, sha256_pattern]
        
        for pattern in patterns:
            match = re.search(pattern, query)
            if match:
                return match.group(0)
        
        return None

    def _extract_domain(self, query: str) -> Optional[str]:
        """Extract domain from query string"""
        # Simple domain pattern (not perfect but works for most cases)
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        match = re.search(domain_pattern, query)
        
        if match:
            domain = match.group(0)
            # Exclude common false positives
            if domain not in ['localhost', 'example.com']:
                return domain
        
        return None