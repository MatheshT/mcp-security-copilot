import os
import re
from typing import Any, Dict, List, Optional

from .correlation_engine import build_unified_investigation_result
from .file_analyzer import FileAnalyzer
from .llm_client import LLMClient
from .mcp.registry import create_mcp_client
from .report_generator import generate_report_json, generate_report_html
from .predictive_analytics import PredictiveSecurityEngine

ToolResponse = Dict[str, Any]


class EnhancedSecurityCopilotOrchestrator:
    """
    Enhanced orchestrator with comprehensive tool integration for Wazuh data investigation.
    Supports all security tools with detailed data collection and reporting.
    """
    
    def __init__(self):
        self.llm_client = LLMClient()
        self.mcp_client = create_mcp_client()
        self.file_analyzer = FileAnalyzer()
        self.predictive_engine = PredictiveSecurityEngine()

    def analyze_file_upload(self, filename: str, content_bytes: bytes) -> Dict[str, Any]:
        """
        Processes uploaded files/images with comprehensive tool integration.
        """
        print(f"\n==================== ENHANCED FILE UPLOAD ANALYSIS ====================")
        print(f"File: {filename} ({len(content_bytes)} bytes)")

        analysis = self.file_analyzer.analyze(filename, content_bytes)
        target = analysis['primary_indicator']

        query_str = f"Check file hash {analysis['sha256']}" if target == analysis['sha256'] else f"Check indicator {target}"
        result = self.analyze_query(query_str)

        # Inject file upload metadata into report
        result['file_analysis'] = analysis
        if result.get('report_json'):
            result['report_json']['file_analysis'] = analysis

        return result

    def analyze_query(self, query: str) -> Dict[str, Any]:
        """
        Enhanced Intent-Driven Orchestration Flow with all tool integrations:
        1. LLM Intent Analysis & Tool Planning
        2. Comprehensive Tool Execution (Wazuh, VirusTotal, MISP, Shodan, etc.)
        3. Detailed Data Collection from All Tools
        4. Comprehensive Report Generation
        5. Natural Language Response Generation
        """
        try:
            print(f"\n==================== ENHANCED QUERY ANALYSIS ====================")
            print(f"Query: {query}")

            # Step 1: Get intent, query_type, and tool plan from LLM
            llm_result = self.llm_client.get_intent_and_tools(query)
            tools = llm_result.get('required_tools', [])
            tool_commands = llm_result.get('tool_commands', {})
            entities = llm_result.get('entities', {})

            print(f"Intent: {llm_result.get('intent')}")
            print(f"Query Type: {llm_result.get('query_type')}")
            print(f"Required Tools: {tools}")
            print(f"Planned Commands: {tool_commands}")

            # Step 2: Handle Direct LLM Questions
            if not tools:
                print("Direct LLM response (No tool calls required).")
                return self._generate_llm_only_response(query, llm_result, entities)

            # Step 3: Execute All Planned Tools with Enhanced Data Collection
            responses: List[ToolResponse] = []
            extracted_data = self._initialize_extracted_data(entities)

            for tool_name in tools:
                tool_response = self._execute_tool(tool_name, tool_commands, extracted_data, entities)
                if tool_response:
                    responses.append(tool_response)

            # Step 4: Generate Comprehensive Reports
            report_json = self._generate_comprehensive_report(extracted_data, responses, llm_result)
            report_html = generate_report_html(report_json)
            
            # Step 5: Generate a detailed, evidence-backed response for every tool investigation.
            ai_answer = self._generate_tool_separated_response(extracted_data, query, responses)

            return {
                'llm': llm_result,
                'tool_responses': responses,
                'unified_investigation': extracted_data,
                'report_json': report_json,
                'report_html': report_html,
                'ai_answer': ai_answer,
                'extracted_data': extracted_data
            }
        except Exception as e:
            import traceback
            print(f"Error in analyze_query: {e}")
            traceback.print_exc()
            
            # Return fallback response
            return {
                'llm': llm_result if 'llm_result' in locals() else {},
                'tool_responses': [],
                'unified_investigation': {},
                'report_json': {"error": str(e)},
                'report_html': f"<p>Error: {str(e)}</p>",
                'ai_answer': f"An error occurred: {str(e)}",
                'extracted_data': {}
            }

    def _initialize_extracted_data(self, entities: Dict) -> Dict:
        """Initialize the data extraction dictionary with base entities."""
        return {
            'source_ip': entities.get('ip'),
            'destination_ip': None,
            'affected_host': None,
            'alerts': [],
            'vt_results': {},
            'wazuh_data': {},
            'virustotal_data': {},
            'misp_data': {},
            'shodan_data': {},
            'abuseipdb_data': {},
            'alienvault_data': {},
            'windows_defender_data': {},
            'windows_logs_data': {},
            'malwarebazaar_data': {},
            'cisa_kev_data': {},
            'ip_intel_data': {},
            'cve_search_data': {},
            'mitre_attack_data': {},
            'ml_threat_data': {},
            'tool_usage_log': []
        }

    def _execute_tool(self, tool_name: str, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> Optional[ToolResponse]:
        """Execute a single tool with comprehensive data collection."""
        tool_name_lower = tool_name.lower().strip()
        
        try:
            if tool_name_lower == "wazuh":
                return self._execute_wazuh(tool_commands, extracted_data, entities)
            elif tool_name_lower == "virustotal":
                return self._execute_virustotal(tool_commands, extracted_data, entities)
            elif tool_name_lower == "misp":
                return self._execute_misp(tool_commands, extracted_data, entities)
            elif tool_name_lower == "shodan":
                return self._execute_shodan(tool_commands, extracted_data, entities)
            elif tool_name_lower == "abuseipdb":
                return self._execute_abuseipdb(tool_commands, extracted_data, entities)
            elif tool_name_lower in ["alienvault", "alienvault otx"]:
                return self._execute_alienvault(tool_commands, extracted_data, entities)
            elif tool_name_lower in ["windowsdefender", "defender"]:
                return self._execute_windows_defender(tool_commands, extracted_data, entities)
            elif tool_name_lower in ["windowslogs", "windows_event"]:
                return self._execute_windows_logs(tool_commands, extracted_data, entities)
            elif tool_name_lower == "soar":
                return self._execute_soar(tool_commands, extracted_data, entities)
            elif tool_name_lower in ["malwarebazaar", "urlhaus", "abusech"]:
                return self._execute_malwarebazaar(tool_commands, extracted_data, entities)
            elif tool_name_lower in ["cisa_kev", "cisa", "kev"]:
                return self._execute_cisa_kev(tool_commands, extracted_data, entities)
            elif tool_name_lower in ["ip_intel", "ipapi", "ip_api"]:
                return self._execute_ip_intel(tool_commands, extracted_data, entities)
            elif tool_name_lower in ["cve_search", "circl", "cve"]:
                return self._execute_cve_search(tool_commands, extracted_data, entities)
            elif tool_name_lower in ["mitre_attack", "mitre", "ttp"]:
                return self._execute_mitre_attack(tool_commands, extracted_data, entities)
            elif tool_name_lower in ["ml_threat_engine", "ml", "ml_threat", "mldetection"]:
                return self._execute_ml_threat_engine(tool_commands, extracted_data, entities)
            else:
                print(f"Unknown tool: {tool_name}")
                return None
        except Exception as e:
            print(f"Error executing tool {tool_name}: {e}")
            extracted_data['tool_usage_log'].append({
                'tool': tool_name,
                'status': 'error',
                'error': str(e)
            })
            return None

    def _execute_wazuh(self, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> ToolResponse:
        """Execute Wazuh with comprehensive data collection."""
        print(">>> EXECUTING ENHANCED WAZUH MCP TOOL <<<")
        wazuh_commands = tool_commands.get('Wazuh', ['get_alerts', 'get_agents', 'get_statistics'])
        
        wazuh_data = {}
        extracted_data['tool_usage_log'].append({'tool': 'Wazuh', 'status': 'started'})
        
        for cmd in wazuh_commands:
            try:
                wazuh_response = self.mcp_client.call_tool("Wazuh", cmd)
                
                # Handle both ToolResponse objects and raw responses
                response_data = {}
                if hasattr(wazuh_response, 'data'):
                    response_data = wazuh_response.data
                elif isinstance(wazuh_response, dict):
                    response_data = wazuh_response
                else:
                    response_data = wazuh_response
                
                # Collect different types of Wazuh data
                if cmd.startswith('get_alerts'):
                    wazuh_data['alerts'] = response_data.get("alerts", []) if isinstance(response_data, dict) else []
                elif cmd.startswith('get_agents'):
                    wazuh_data['agents'] = response_data.get("agents", []) if isinstance(response_data, dict) else []
                elif cmd.startswith('get_statistics'):
                    wazuh_data['statistics'] = response_data
                elif cmd.startswith('get_rules'):
                    wazuh_data['rules'] = response_data.get("rules", []) if isinstance(response_data, dict) else []
                elif cmd.startswith('get_vulnerabilities'):
                    wazuh_data['vulnerabilities'] = response_data.get("vulnerabilities", []) if isinstance(response_data, dict) else []
                elif cmd.startswith('get_syscheck'):
                    wazuh_data['syscheck'] = response_data.get("syscheck", []) if isinstance(response_data, dict) else []
                    
            except Exception as e:
                print(f"Error executing Wazuh command {cmd}: {e}")
                continue
        
        # Extract comprehensive data from Wazuh
        if wazuh_data.get("alerts"):
            alerts = wazuh_data["alerts"]
            requested_alert = entities.get('alert_id')
            selected_alert = None
            
            if requested_alert:
                selected_alert = next((a for a in alerts if str(a.get("alert_id") or a.get("id")) == str(requested_alert)), None)
            if selected_alert is None and alerts:
                selected_alert = alerts[0]

            if selected_alert:
                raw = selected_alert.get("raw", {})
                extracted_data['source_ip'] = selected_alert.get("source_ip") or raw.get("src_ip") or extracted_data['source_ip']
                extracted_data['destination_ip'] = selected_alert.get("destination_ip") or raw.get("dst_ip") or selected_alert.get("dest_ip")
                extracted_data['affected_host'] = selected_alert.get("agent", {}).get("name") or selected_alert.get("hostname")
                extracted_data['alert_details'] = selected_alert
                extracted_data['alerts'] = alerts
        
        # Add comprehensive Wazuh information
        extracted_data['wazuh_data'] = wazuh_data
        if wazuh_data.get("agents"):
            extracted_data['wazuh_agents'] = wazuh_data["agents"]
            extracted_data['agent_count'] = len(wazuh_data["agents"])
            extracted_data['active_agents'] = len([a for a in wazuh_data["agents"] if a.get("status") == "active"])
        
        if wazuh_data.get("statistics"):
            extracted_data['wazuh_statistics'] = wazuh_data["statistics"]
        
        if wazuh_data.get("rules"):
            extracted_data['wazuh_rules'] = wazuh_data["rules"]
        
        if wazuh_data.get("vulnerabilities"):
            extracted_data['wazuh_vulnerabilities'] = wazuh_data["vulnerabilities"]
        
        extracted_data['tool_usage_log'].append({'tool': 'Wazuh', 'status': 'completed', 'data_points': len(wazuh_data)})
        
        return self._tool_result("Wazuh", str(wazuh_commands), wazuh_data, wazuh_response)

    def _execute_virustotal(self, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> ToolResponse:
        """Execute VirusTotal with comprehensive data collection."""
        print(">>> EXECUTING ENHANCED VIRUSTOTAL MCP TOOL <<<")
        cmd_list = tool_commands.get('VirusTotal', [])
        
        if cmd_list:
            cmd = cmd_list[0]
        else:
            target = extracted_data['source_ip'] or entities.get('ip') or entities.get('hash') or '185.220.101.45'
            cmd = f"check_ip {target}"

        print(f"Calling VirusTotal MCP: {cmd}")
        vt_response = self.mcp_client.call_tool("VirusTotal", cmd)
        
        # Handle both ToolResponse objects and raw responses
        vt_data = {}
        if hasattr(vt_response, 'data'):
            if vt_response.data and vt_response.data.get("result"):
                vt_data = vt_response.data.get("result")
                extracted_data['virustotal_data'] = vt_data
                extracted_data['vt_results'] = vt_data
        elif isinstance(vt_response, dict):
            if vt_response.get("result"):
                vt_data = vt_response.get("result")
                extracted_data['virustotal_data'] = vt_data
                extracted_data['vt_results'] = vt_data
        else:
            vt_data = vt_response
            extracted_data['virustotal_data'] = vt_data
            extracted_data['vt_results'] = vt_data
        
        extracted_data['tool_usage_log'].append({'tool': 'VirusTotal', 'status': 'completed', 'command': cmd})
        
        return self._tool_result("VirusTotal", cmd, vt_data, vt_response)

    def _execute_misp(self, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> ToolResponse:
        """Execute MISP with comprehensive data collection."""
        print(">>> EXECUTING ENHANCED MISP MCP TOOL <<<")
        target = extracted_data['source_ip'] or entities.get('ip') or entities.get('hash') or '185.220.101.45'
        misp_response = self.mcp_client.call_tool("MISP", f"search {target}")
        
        # Handle both ToolResponse objects and raw responses
        misp_data = {}
        if hasattr(misp_response, 'data'):
            misp_data = misp_response.data
            extracted_data['misp_data'] = misp_data
        elif isinstance(misp_response, dict):
            misp_data = misp_response
            extracted_data['misp_data'] = misp_data
        else:
            misp_data = misp_response
            extracted_data['misp_data'] = misp_data
        
        extracted_data['tool_usage_log'].append({'tool': 'MISP', 'status': 'completed', 'target': target})
        
        return self._tool_result("MISP", f"search {target}", misp_data, misp_response)

    def _execute_shodan(self, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> ToolResponse:
        """Execute Shodan with comprehensive data collection."""
        print(">>> EXECUTING ENHANCED SHODAN MCP TOOL <<<")
        target = extracted_data['source_ip'] or entities.get('ip') or '185.220.101.45'
        shodan_response = self.mcp_client.call_tool("Shodan", f"search {target}")
        
        # Handle both ToolResponse objects and raw responses
        shodan_data = {}
        if hasattr(shodan_response, 'data'):
            shodan_data = shodan_response.data
            extracted_data['shodan_data'] = shodan_data
        elif isinstance(shodan_response, dict):
            shodan_data = shodan_response
            extracted_data['shodan_data'] = shodan_data
        else:
            shodan_data = shodan_response
            extracted_data['shodan_data'] = shodan_data
        
        extracted_data['tool_usage_log'].append({'tool': 'Shodan', 'status': 'completed', 'target': target})
        
        return self._tool_result("Shodan", f"search {target}", shodan_data, shodan_response)

    def _execute_abuseipdb(self, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> ToolResponse:
        """Execute AbuseIPDB with comprehensive data collection."""
        print(">>> EXECUTING ENHANCED ABUSEIPDB MCP TOOL <<<")
        target = extracted_data['source_ip'] or entities.get('ip') or '185.220.101.45'
        abuseipdb_response = self.mcp_client.call_tool("AbuseIPDB", f"check {target}")
        
        # Handle both ToolResponse objects and raw responses
        abuseipdb_data = {}
        if hasattr(abuseipdb_response, 'data'):
            abuseipdb_data = abuseipdb_response.data
            extracted_data['abuseipdb_data'] = abuseipdb_data
        elif isinstance(abuseipdb_response, dict):
            abuseipdb_data = abuseipdb_response
            extracted_data['abuseipdb_data'] = abuseipdb_data
        else:
            abuseipdb_data = abuseipdb_response
            extracted_data['abuseipdb_data'] = abuseipdb_data
        
        extracted_data['tool_usage_log'].append({'tool': 'AbuseIPDB', 'status': 'completed', 'target': target})
        
        return self._tool_result("AbuseIPDB", f"check {target}", abuseipdb_data, abuseipdb_response)

    def _execute_alienvault(self, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> ToolResponse:
        """Execute AlienVault OTX with comprehensive data collection."""
        print(">>> EXECUTING ENHANCED ALIENVAULT OTX MCP TOOL <<<")
        target = extracted_data['source_ip'] or entities.get('ip') or entities.get('hash') or '185.220.101.45'
        alienvault_response = self.mcp_client.call_tool("AlienVault OTX", f"check {target}")
        
        # Handle both ToolResponse objects and raw responses
        alienvault_data = {}
        if hasattr(alienvault_response, 'data'):
            alienvault_data = alienvault_response.data
            extracted_data['alienvault_data'] = alienvault_data
        elif isinstance(alienvault_response, dict):
            alienvault_data = alienvault_response
            extracted_data['alienvault_data'] = alienvault_data
        else:
            alienvault_data = alienvault_response
            extracted_data['alienvault_data'] = alienvault_data
        
        extracted_data['tool_usage_log'].append({'tool': 'AlienVault OTX', 'status': 'completed', 'target': target})
        
        return self._tool_result("AlienVault OTX", f"check {target}", alienvault_data, alienvault_response)

    def _execute_windows_defender(self, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> ToolResponse:
        """Execute Windows Defender with comprehensive data collection."""
        print(">>> EXECUTING ENHANCED WINDOWS DEFENDER MCP TOOL <<<")
        
        defender_response = self.mcp_client.call_tool("WindowsDefender", "get_status")
        defender_data = {'status': defender_response.data if hasattr(defender_response, 'data') and defender_response.data else defender_response}
        
        # Get threats if available
        threats_response = self.mcp_client.call_tool("WindowsDefender", "get_threats")
        defender_data['threats'] = threats_response.data if hasattr(threats_response, 'data') and threats_response.data else threats_response
        
        # Get scan history
        try:
            scan_response = self.mcp_client.call_tool("WindowsDefender", "get_scan_history")
            defender_data['scan_history'] = scan_response.data if hasattr(scan_response, 'data') and scan_response.data else scan_response
        except:
            defender_data['scan_history'] = None
        
        extracted_data['windows_defender_data'] = defender_data
        extracted_data['tool_usage_log'].append({'tool': 'WindowsDefender', 'status': 'completed'})
        
        return self._tool_result("WindowsDefender", "get_status, get_threats", defender_data, defender_response)

    def _execute_windows_logs(self, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> ToolResponse:
        """Execute Windows Logs with comprehensive data collection."""
        print(">>> EXECUTING ENHANCED WINDOWS LOGS MCP TOOL <<<")
        
        logs_data = {}
        security_response = None
        
        # Get security events
        try:
            security_response = self.mcp_client.call_tool("WindowsLogs", "get_security_events")
            security_data = security_response.data if hasattr(security_response, 'data') else security_response
            logs_data['security_events'] = security_data.get('events', []) if isinstance(security_data, dict) else (security_data if isinstance(security_data, list) else [])
        except:
            logs_data['security_events'] = []
        
        # Get system events
        try:
            system_response = self.mcp_client.call_tool("WindowsLogs", "get_system_events")
            system_data = system_response.data if hasattr(system_response, 'data') else system_response
            logs_data['system_events'] = system_data.get('events', []) if isinstance(system_data, dict) else (system_data if isinstance(system_data, list) else [])
        except:
            logs_data['system_events'] = []
        
        # Get application events
        try:
            app_response = self.mcp_client.call_tool("WindowsLogs", "get_application_events")
            app_data = app_response.data if hasattr(app_response, 'data') else app_response
            logs_data['application_events'] = app_data.get('events', []) if isinstance(app_data, dict) else (app_data if isinstance(app_data, list) else [])
        except:
            logs_data['application_events'] = []
        
        extracted_data['windows_logs_data'] = logs_data
        extracted_data['tool_usage_log'].append({'tool': 'WindowsLogs', 'status': 'completed', 'event_types': len(logs_data)})
        
        return self._tool_result("WindowsLogs", "get_security_events, get_system_events, get_application_events", logs_data, security_response)

    def _execute_soar(self, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> ToolResponse:
        """Execute SOAR active defense with automated containment."""
        print(">>> EXECUTING ENHANCED SOAR MCP TOOL <<<")
        soar_commands = tool_commands.get('SOAR', ['get_playbooks'])
        soar_data = {}
        cmd = soar_commands[0] if soar_commands else "get_playbooks"
        soar_response = None
        
        try:
            soar_response = self.mcp_client.call_tool("SOAR", cmd)
            if hasattr(soar_response, 'data'):
                soar_data = soar_response.data
            elif isinstance(soar_response, dict):
                soar_data = soar_response
            else:
                soar_data = {"result": str(soar_response)}
        except Exception as e:
            soar_data = {"error": str(e)}

        extracted_data['soar_data'] = soar_data
        extracted_data['tool_usage_log'].append({'tool': 'SOAR', 'status': 'completed', 'command': cmd})
        return self._tool_result("SOAR", cmd, soar_data, soar_response)

    def _execute_malwarebazaar(self, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> ToolResponse:
        """Execute MalwareBazaar & URLhaus free threat intelligence."""
        cmds = tool_commands.get('MalwareBazaar') or tool_commands.get('URLhaus') or ['lookup_hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']
        cmd = cmds[0] if isinstance(cmds, list) and cmds else str(cmds)
        extracted_data['tool_usage_log'].append({'tool': 'MalwareBazaar', 'status': 'started', 'command': cmd})
        try:
            resp = self.mcp_client.call_tool("MalwareBazaar", cmd)
            data = resp.data if hasattr(resp, 'data') else resp
        except Exception as e:
            data = {"error": str(e)}
            resp = None
        extracted_data['malwarebazaar_data'] = data
        extracted_data['tool_usage_log'].append({'tool': 'MalwareBazaar', 'status': 'completed', 'command': cmd})
        return self._tool_result("MalwareBazaar", cmd, data, resp)

    def _execute_cisa_kev(self, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> ToolResponse:
        """Execute CISA Known Exploited Vulnerabilities catalog check."""
        cmds = tool_commands.get('CISA_KEV') or tool_commands.get('cisa') or ['check_cve CVE-2023-34362']
        cmd = cmds[0] if isinstance(cmds, list) and cmds else str(cmds)
        extracted_data['tool_usage_log'].append({'tool': 'CISA_KEV', 'status': 'started', 'command': cmd})
        try:
            resp = self.mcp_client.call_tool("CISA_KEV", cmd)
            data = resp.data if hasattr(resp, 'data') else resp
        except Exception as e:
            data = {"error": str(e)}
            resp = None
        extracted_data['cisa_kev_data'] = data
        extracted_data['tool_usage_log'].append({'tool': 'CISA_KEV', 'status': 'completed', 'command': cmd})
        return self._tool_result("CISA_KEV", cmd, data, resp)

    def _execute_ip_intel(self, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> ToolResponse:
        """Execute free IP Geolocation, ASN and Reverse DNS threat enrichment."""
        cmds = tool_commands.get('IP_Intel') or ['lookup_ip 185.220.101.5']
        cmd = cmds[0] if isinstance(cmds, list) and cmds else str(cmds)
        extracted_data['tool_usage_log'].append({'tool': 'IP_Intel', 'status': 'started', 'command': cmd})
        try:
            resp = self.mcp_client.call_tool("IP_Intel", cmd)
            data = resp.data if hasattr(resp, 'data') else resp
        except Exception as e:
            data = {"error": str(e)}
            resp = None
        extracted_data['ip_intel_data'] = data
        extracted_data['tool_usage_log'].append({'tool': 'IP_Intel', 'status': 'completed', 'command': cmd})
        return self._tool_result("IP_Intel", cmd, data, resp)

    def _execute_cve_search(self, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> ToolResponse:
        """Execute free CIRCL / OSV vulnerability search."""
        cmds = tool_commands.get('CVE_Search') or ['search_cve CVE-2021-44228']
        cmd = cmds[0] if isinstance(cmds, list) and cmds else str(cmds)
        extracted_data['tool_usage_log'].append({'tool': 'CVE_Search', 'status': 'started', 'command': cmd})
        try:
            resp = self.mcp_client.call_tool("CVE_Search", cmd)
            data = resp.data if hasattr(resp, 'data') else resp
        except Exception as e:
            data = {"error": str(e)}
            resp = None
        extracted_data['cve_search_data'] = data
        extracted_data['tool_usage_log'].append({'tool': 'CVE_Search', 'status': 'completed', 'command': cmd})
        return self._tool_result("CVE_Search", cmd, data, resp)

    def _execute_mitre_attack(self, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> ToolResponse:
        """Execute MITRE ATT&CK TTP taxonomy navigation."""
        cmds = tool_commands.get('MITRE_ATTACK') or ['lookup_technique T1059']
        cmd = cmds[0] if isinstance(cmds, list) and cmds else str(cmds)
        extracted_data['tool_usage_log'].append({'tool': 'MITRE_ATTACK', 'status': 'started', 'command': cmd})
        try:
            resp = self.mcp_client.call_tool("MITRE_ATTACK", cmd)
            data = resp.data if hasattr(resp, 'data') else resp
        except Exception as e:
            data = {"error": str(e)}
            resp = None
        extracted_data['mitre_attack_data'] = data
        extracted_data['tool_usage_log'].append({'tool': 'MITRE_ATTACK', 'status': 'completed', 'command': cmd})
        return self._tool_result("MITRE_ATTACK", cmd, data, resp)

    def _execute_ml_threat_engine(self, tool_commands: Dict, extracted_data: Dict, entities: Dict) -> ToolResponse:
        """Execute local Machine Learning IsolationForest + RandomForest UEBA threat scoring."""
        cmds = tool_commands.get('ML_Threat_Engine') or ['detect_anomaly']
        cmd = cmds[0] if isinstance(cmds, list) and cmds else str(cmds)
        extracted_data['tool_usage_log'].append({'tool': 'ML_Threat_Engine', 'status': 'started', 'command': cmd})
        try:
            resp = self.mcp_client.call_tool("ML_Threat_Engine", cmd)
            data = resp.data if hasattr(resp, 'data') else resp
        except Exception as e:
            data = {"error": str(e)}
            resp = None
        extracted_data['ml_threat_data'] = data
        extracted_data['tool_usage_log'].append({'tool': 'ML_Threat_Engine', 'status': 'completed', 'command': cmd})
        return self._tool_result("ML_Threat_Engine", cmd, data, resp)

    def _generate_comprehensive_report(self, extracted_data: Dict, responses: List, llm_result: Dict) -> Dict:
        """Generate comprehensive report with all tool data."""
        
        # Build base report
        report_json = {
            "alert_id": extracted_data.get('alert_details', {}).get('id') or 'N/A',
            "timestamp": extracted_data.get('alert_details', {}).get('timestamp') or None,
            "severity": self._calculate_severity(extracted_data),
            "attack_type": self._determine_attack_type(extracted_data),
            "affected_host": extracted_data.get('affected_host') or 'N/A',
            "source_ip": extracted_data.get('source_ip') or 'N/A',
            "destination_ip": extracted_data.get('destination_ip') or 'N/A',
            "mitre_technique": self._extract_mitre_technique(extracted_data),
            "status": "Investigation Complete",
            "confidence": self._calculate_confidence(extracted_data),
            "indicators_of_compromise": self._extract_iocs(extracted_data),
            "threat_intelligence": self._extract_threat_intelligence(extracted_data),
            "investigation_summary": self._generate_investigation_summary(extracted_data),
            "recommendations": self._generate_recommendations(extracted_data),
            "tool_reports": {
                "wazuh_report": self._generate_wazuh_report(extracted_data),
                "virustotal_report": self._generate_virustotal_report(extracted_data),
                "misp_report": self._generate_misp_report(extracted_data),
                "shodan_report": self._generate_shodan_report(extracted_data),
                "abuseipdb_report": self._generate_abuseipdb_report(extracted_data),
                "alienvault_report": self._generate_alienvault_report(extracted_data),
                "windows_defender_report": self._generate_windows_defender_report(extracted_data),
                "windows_logs_report": self._generate_windows_logs_report(extracted_data)
            },
            "visual_data": {
                "threat_score": self._calculate_threat_score(extracted_data),
                "timeline": self._extract_timeline(extracted_data),
                "attack_graph": self._extract_attack_graph(extracted_data),
                "tool_usage": extracted_data.get('tool_usage_log', [])
            },
            "tools_used": list(dict.fromkeys(
                log['tool'] for log in extracted_data.get('tool_usage_log', [])
                if isinstance(log, dict) and log.get('tool')
            )),
            "data_collection_summary": self._generate_data_collection_summary(extracted_data)
        }
        
        return report_json

    def _generate_llm_only_response(self, query: str, llm_result: Dict, entities: Dict) -> Dict:
        """Generate response for LLM-only queries with comprehensive Wazuh support."""
        query_lower = query.lower()
        
        # Check if this is a Wazuh-related query
        if any(keyword in query_lower for keyword in ['agent', 'alert', 'event', 'log', 'rule', 'vulnerability', 'endpoint', 'host']):
            try:
                # Determine which Wazuh data to fetch based on query
                wazuh_data = {}
                tool_responses = []
                
                # Get agents if query mentions agents, endpoints, hosts, or general status
                if any(keyword in query_lower for keyword in ['agent', 'endpoint', 'host', 'connected', 'how many', 'count', 'status']):
                    try:
                        agents_response = self.mcp_client.call_tool("Wazuh", "get_agents")
                        agents_data = self._extract_response_data(agents_response)
                        wazuh_data['agents'] = agents_data
                        tool_responses.append(self._convert_to_dict(agents_response, "Wazuh", "get_agents"))
                    except Exception as e:
                        print(f"Error getting Wazuh agents: {e}")
                
                # Get alerts if query mentions alerts, events, or security incidents
                if any(keyword in query_lower for keyword in ['alert', 'event', 'security', 'incident']):
                    try:
                        alerts_response = self.mcp_client.call_tool("Wazuh", "get_alerts")
                        alerts_data = self._extract_response_data(alerts_response)
                        wazuh_data['alerts'] = alerts_data
                        tool_responses.append(self._convert_to_dict(alerts_response, "Wazuh", "get_alerts"))
                    except Exception as e:
                        print(f"Error getting Wazuh alerts: {e}")
                
                # Get statistics for general Wazuh queries
                if any(keyword in query_lower for keyword in ['wazuh', 'overview', 'summary', 'dashboard', 'statistics']):
                    try:
                        stats_response = self.mcp_client.call_tool("Wazuh", "get_statistics")
                        stats_data = self._extract_response_data(stats_response)
                        wazuh_data['statistics'] = stats_data
                        tool_responses.append(self._convert_to_dict(stats_response, "Wazuh", "get_statistics"))
                    except Exception as e:
                        print(f"Error getting Wazuh statistics: {e}")
                
                # Get rules if query mentions rules
                if 'rule' in query_lower:
                    try:
                        rules_response = self.mcp_client.call_tool("Wazuh", "get_rules")
                        rules_data = self._extract_response_data(rules_response)
                        wazuh_data['rules'] = rules_data
                        tool_responses.append(self._convert_to_dict(rules_response, "Wazuh", "get_rules"))
                    except Exception as e:
                        print(f"Error getting Wazuh rules: {e}")
                
                # Get vulnerabilities if query mentions vulnerabilities or specific agent
                if 'vulnerability' in query_lower or 'agent-00' in query_lower:
                    try:
                        # Extract agent ID if mentioned
                        agent_id = None
                        import re
                        agent_match = re.search(r'agent[-_]?(\d+)', query_lower)
                        if agent_match:
                            agent_id = agent_match.group(1)
                        
                        if agent_id:
                            vulns_response = self.mcp_client.call_tool("Wazuh", f"get_vulnerabilities agent-{agent_id}")
                        else:
                            vulns_response = self.mcp_client.call_tool("Wazuh", "get_vulnerabilities")
                        
                        vulns_data = self._extract_response_data(vulns_response)
                        wazuh_data['vulnerabilities'] = vulns_data
                        tool_responses.append(self._convert_to_dict(vulns_response, "Wazuh", "get_vulnerabilities"))
                    except Exception as e:
                        print(f"Error getting Wazuh vulnerabilities: {e}")
                
                # Generate comprehensive report
                report_json = self._generate_wazuh_comprehensive_report(wazuh_data, query)
                ai_answer = self._generate_wazuh_ai_answer(wazuh_data, query)
                
                return {
                    'llm': llm_result,
                    'tool_responses': tool_responses,
                    'unified_investigation': wazuh_data,
                    'report_json': report_json,
                    'report_html': generate_report_html(report_json),
                    'ai_answer': ai_answer,
                    'extracted_data': wazuh_data
                }
            except Exception as e:
                print(f"Error in Wazuh query handling: {e}")
                import traceback
                traceback.print_exc()
                return self._generate_fallback_wazuh_response(query, llm_result, str(e))
        
        # Default LLM-only response for non-Wazuh queries
        report_json = {
            "alert_id": "N/A",
            "timestamp": None,
            "severity": "Info",
            "attack_type": "Knowledge Base Query",
            "affected_host": "N/A",
            "source_ip": entities.get('ip') or "N/A",
            "destination_ip": "N/A",
            "mitre_technique": "N/A",
            "status": "Informational",
            "confidence": "100%",
            "indicators_of_compromise": [],
            "threat_intelligence": [],
            "investigation_summary": f"General security query regarding '{query}'. Processed directly by Copilot AI Engine.",
            "recommendations": ["Follow standard security best practices for prevention and monitoring."],
            "tool_reports": {
                "virustotal_report": None,
                "wazuh_report": None,
                "misp_report": None,
                "shodan_report": None,
                "abuseipdb_report": None,
                "alienvault_report": None,
                "windows_defender_report": None,
                "windows_logs_report": None
            },
            "visual_data": {
                "threat_score": 0,
                "timeline": [],
                "attack_graph": [],
                "tool_usage": []
            },
            "tools_used": [],
            "data_collection_summary": "LLM knowledge base query only - no external tools used"
        }

        report_html = generate_report_html(report_json)
        ai_answer = self.llm_client.generate_response(query, report_json)

        return {
            'llm': llm_result,
            'tool_responses': [],
            'unified_investigation': {
                "alert_id": "N/A",
                "severity": "Info",
                "attack_type": "Knowledge Base Query",
                "affected_host": "N/A",
                "source_ip": "N/A",
                "destination_ip": "N/A",
                "summary": f"Answered query '{query}' via Copilot AI Knowledge Base.",
                "tool_reports": report_json['tool_reports']
            },
            'report_json': report_json,
            'report_html': report_html,
            'ai_answer': ai_answer,
            'extracted_data': entities
        }
    
    def _extract_response_data(self, response) -> Dict:
        """Extract data from MCP response handling both ToolResponse and raw responses"""
        if hasattr(response, 'data'):
            return response.data
        elif isinstance(response, dict):
            return response
        elif isinstance(response, list):
            return {"data": response}
        else:
            return {"data": response}
    
    def _convert_to_dict(self, response, tool_name: str, command: str) -> Dict:
        """Convert MCP response to dict format for tool_responses"""
        if hasattr(response, 'dict'):
            return response.dict()
        elif isinstance(response, dict):
            return response
        else:
            return {"tool": tool_name, "command": command, "data": response}
    
    def _generate_wazuh_comprehensive_report(self, wazuh_data: Dict, query: str) -> Dict:
        """Generate comprehensive Wazuh report based on collected data"""
        # Handle different data structures from MCP responses
        agents_data = wazuh_data.get('agents', {})
        if isinstance(agents_data, dict):
            agents = agents_data.get('agents', [])
        elif isinstance(agents_data, list):
            agents = agents_data
        else:
            agents = []
        
        alerts_data = wazuh_data.get('alerts', {})
        if isinstance(alerts_data, dict):
            alerts = alerts_data.get('alerts', [])
        elif isinstance(alerts_data, list):
            alerts = alerts_data
        else:
            alerts = []
        
        stats = wazuh_data.get('statistics', {})
        
        stats = stats if isinstance(stats, dict) else {}
        total_agents = len(agents) if isinstance(agents, list) and agents else int(stats.get('total_agents', 0) or 0)
        active_agents = (
            len([a for a in agents if isinstance(a, dict) and a.get('status') == 'active'])
            if isinstance(agents, list) and agents
            else int(stats.get('active_agents', 0) or 0)
        )
        total_alerts = len(alerts) if isinstance(alerts, list) and alerts else int(stats.get('total_alerts', 0) or 0)
        
        return {
            "alert_id": "N/A",
            "timestamp": None,
            "severity": self._calculate_wazuh_severity(alerts),
            "attack_type": "Wazuh Security Analysis",
            "affected_host": "N/A",
            "source_ip": "N/A",
            "destination_ip": "N/A",
            "mitre_technique": "N/A",
            "status": "Informational",
            "confidence": "100%",
            "indicators_of_compromise": [],
            "threat_intelligence": [],
            "investigation_summary": f"Wazuh analysis for query: '{query}'. Total agents: {total_agents}, Active agents: {active_agents}, Total alerts: {total_alerts}",
            "recommendations": self._generate_wazuh_recommendations(wazuh_data),
            "tool_reports": {
                "virustotal_report": None,
                "wazuh_report": {
                    "total_agents": total_agents,
                    "active_agents": active_agents,
                    "total_alerts": total_alerts,
                    "statistics": stats,
                    "agent_details": agents,
                    "alert_details": alerts
                },
                "misp_report": None,
                "shodan_report": None,
                "abuseipdb_report": None,
                "alienvault_report": None,
                "windows_defender_report": None,
                "windows_logs_report": None
            },
            "visual_data": {
                "threat_score": 0,
                "timeline": [],
                "attack_graph": [],
                "tool_usage": ["Wazuh"]
            },
            "tools_used": ["Wazuh"],
            "data_collection_summary": "Wazuh data collected successfully"
        }
    
    def _calculate_wazuh_severity(self, alerts: list) -> str:
        """Calculate severity based on Wazuh alerts"""
        if not isinstance(alerts, list):
            return "Low"
        
        if len(alerts) == 0:
            return "Low"
        
        high_severity = 0
        medium_severity = 0
        
        for alert in alerts:
            if isinstance(alert, dict):
                rule = alert.get('rule', {})
                if isinstance(rule, dict):
                    level = rule.get('level', 0)
                    # Ensure level is an integer
                    try:
                        level_int = int(level) if level is not None else 0
                        if level_int >= 10:
                            high_severity += 1
                        elif level_int >= 5:
                            medium_severity += 1
                    except (ValueError, TypeError):
                        pass  # Skip invalid level values
        
        if high_severity > 0:
            return "High"
        elif medium_severity > 0 or len(alerts) > 5:
            return "Medium"
        else:
            return "Low"
    
    def _generate_wazuh_recommendations(self, wazuh_data: Dict) -> List:
        """Generate recommendations based on Wazuh data"""
        recommendations = []
        
        # Handle different data structures from MCP responses
        agents_data = wazuh_data.get('agents', {})
        if isinstance(agents_data, dict):
            agents = agents_data.get('agents', [])
        elif isinstance(agents_data, list):
            agents = agents_data
        else:
            agents = []
        
        alerts_data = wazuh_data.get('alerts', {})
        if isinstance(alerts_data, dict):
            alerts = alerts_data.get('alerts', [])
        elif isinstance(alerts_data, list):
            alerts = alerts_data
        else:
            alerts = []
        
        if isinstance(agents, list):
            active_agents = len([a for a in agents if isinstance(a, dict) and a.get('status') == 'active'])
            disconnected_agents = len(agents) - active_agents
            if disconnected_agents > 0:
                recommendations.append(f"Check {disconnected_agents} disconnected Wazuh agents")
        
        if isinstance(alerts, list) and len(alerts) > 0:
            recommendations.append("Review and triage recent security alerts")
            recommendations.append("Investigate high-severity alerts")
        
        recommendations.append("Monitor agent connectivity regularly")
        recommendations.append("Review Wazuh rules and configurations")
        
        return recommendations
    
    def _generate_wazuh_ai_answer(self, wazuh_data: Dict, query: str) -> str:
        """Generate clear, specific AI answer based on Wazuh data"""
        # Handle different data structures from both MCP responses and tool execution path
        agents_data = wazuh_data.get('agents', {})
        if isinstance(agents_data, dict):
            agents = agents_data.get('agents', [])
        elif isinstance(agents_data, list):
            agents = agents_data
        else:
            agents = []
        
        alerts_data = wazuh_data.get('alerts', {})
        if isinstance(alerts_data, dict):
            alerts = alerts_data.get('alerts', [])
        elif isinstance(alerts_data, list):
            alerts = alerts_data
        else:
            alerts = []
        
        # Also check for wazuh_data nested structure from tool execution path
        if not agents and 'wazuh_data' in wazuh_data:
            wazuh_nested = wazuh_data.get('wazuh_data', {})
            if isinstance(wazuh_nested, dict):
                agents_data = wazuh_nested.get('agents', {})
                if isinstance(agents_data, dict):
                    agents = agents_data.get('agents', [])
                elif isinstance(agents_data, list):
                    agents = agents_data
        
        if not alerts and 'wazuh_data' in wazuh_data:
            wazuh_nested = wazuh_data.get('wazuh_data', {})
            if isinstance(wazuh_nested, dict):
                alerts_data = wazuh_nested.get('alerts', {})
                if isinstance(alerts_data, dict):
                    alerts = alerts_data.get('alerts', [])
                elif isinstance(alerts_data, list):
                    alerts = alerts_data
        
        stats = wazuh_data.get('statistics', {})
        if not stats and 'wazuh_data' in wazuh_data:
            wazuh_nested = wazuh_data.get('wazuh_data', {})
            if isinstance(wazuh_nested, dict):
                stats = wazuh_nested.get('statistics', {})
        
        stats = stats if isinstance(stats, dict) else {}
        total_agents = len(agents) if isinstance(agents, list) and agents else int(stats.get('total_agents', 0) or 0)
        active_agents = (
            len([a for a in agents if isinstance(a, dict) and a.get('status') == 'active'])
            if isinstance(agents, list) and agents
            else int(stats.get('active_agents', 0) or 0)
        )
        total_alerts = len(alerts) if isinstance(alerts, list) and alerts else int(stats.get('total_alerts', 0) or 0)
        
        answer = ""
        
        # Agent-specific queries
        if 'agent' in query.lower() or 'endpoint' in query.lower() or 'host' in query.lower() or 'connected' in query.lower():
            if total_agents > 0:
                answer = f"**Wazuh Agent Status:**\n\n"
                answer += f"• **Total Agents:** {total_agents}\n"
                answer += f"• **Active Agents:** {active_agents}\n"
                answer += f"• **Disconnected Agents:** {total_agents - active_agents}\n\n"
                
                if isinstance(agents, list) and len(agents) > 0:
                    answer += "**Agent Details:**\n"
                    for agent in agents[:5]:  # Show first 5 agents
                        if isinstance(agent, dict):
                            name = agent.get('name', 'Unknown')
                            status = agent.get('status', 'Unknown')
                            ip = agent.get('ip', 'N/A')
                            os_info = agent.get('os', {})
                            os_name = os_info.get('name', 'Unknown') if isinstance(os_info, dict) else 'Unknown'
                            os_version = os_info.get('version', '') if isinstance(os_info, dict) else ''
                            
                            status_emoji = "✅" if status == 'active' else "❌"
                            answer += f"• {status_emoji} **{name}** ({ip}) - {os_name} {os_version} - Status: {status}\n"
                
                if total_agents == active_agents:
                    answer += "\n✅ All agents are healthy and reporting properly."
                else:
                    answer += f"\n⚠️ {total_agents - active_agents} agent(s) need attention."
            else:
                answer = "No Wazuh agents are currently configured or connected."
        
        # Alert-specific queries
        elif 'alert' in query.lower() or 'event' in query.lower() or 'security' in query.lower():
            if total_alerts > 0:
                answer = f"**Wazuh Security Alerts:**\n\n"
                answer += f"• **Total Alerts:** {total_alerts}\n\n"
                
                # Categorize alerts by severity
                high_severity = []
                medium_severity = []
                low_severity = []
                
                for alert in alerts if isinstance(alerts, list) else []:
                    if isinstance(alert, dict):
                        rule = alert.get('rule', {})
                        if isinstance(rule, dict):
                            level = rule.get('level', 0)
                            # Ensure level is an integer
                            try:
                                level_int = int(level) if level is not None else 0
                                if level_int >= 10:
                                    high_severity.append(alert)
                                elif level_int >= 5:
                                    medium_severity.append(alert)
                                else:
                                    low_severity.append(alert)
                            except (ValueError, TypeError):
                                low_severity.append(alert)  # Default to low severity for invalid levels
                
                answer += f"• **High Severity (≥10):** {len(high_severity)}\n"
                answer += f"• **Medium Severity (5-9):** {len(medium_severity)}\n"
                answer += f"• **Low Severity (<5):** {len(low_severity)}\n\n"
                
                if high_severity:
                    answer += "🚨 **High Priority Alerts:**\n"
                    for alert in high_severity[:3]:
                        if isinstance(alert, dict):
                            rule = alert.get('rule', {})
                            if isinstance(rule, dict):
                                answer += f"• {rule.get('description', 'Unknown')} (Level {rule.get('level', 0)})\n"
                
                if isinstance(alerts, list) and len(alerts) > 0:
                    answer += "\n**Recent Alerts:**\n"
                    for alert in alerts[:5]:
                        if isinstance(alert, dict):
                            rule = alert.get('rule', {})
                            agent = alert.get('agent', {})
                            if isinstance(rule, dict) and isinstance(agent, dict):
                                description = rule.get('description', 'Unknown')
                                level = rule.get('level', 0)
                                agent_name = agent.get('name', 'Unknown')
                                timestamp = alert.get('timestamp', 'Unknown')
                                answer += f"• **{description}** (Level {level}) from {agent_name} at {timestamp}\n"
            else:
                answer = "✅ **No Security Alerts:** Your Wazuh system has not detected any recent security events. All monitored systems appear to be operating normally."
        
        # Overview/summary queries
        elif 'overview' in query.lower() or 'summary' in query.lower() or 'dashboard' in query.lower():
            answer = f"**Wazuh Security Overview:**\n\n"
            answer += f"• **Monitored Endpoints:** {total_agents}\n"
            answer += f"• **Active Connections:** {active_agents}\n"
            answer += f"• **Recent Alerts:** {total_alerts}\n"
            
            if total_alerts == 0:
                answer += f"• **Security Status:** ✅ Healthy\n\n"
                answer += "Your Wazuh deployment is operating normally with no detected security threats."
            else:
                answer += f"• **Security Status:** ⚠️ Attention Required\n\n"
                answer += f"Your Wazuh system has detected {total_alerts} security events that require review."
        
        # Default response
        else:
            answer = f"**Wazuh Query Results:**\n\n"
            answer += f"• **Agents:** {total_agents} total, {active_agents} active\n"
            answer += f"• **Alerts:** {total_alerts} recent events\n"
            
            if total_agents > 0 and total_alerts > 0:
                answer += f"\nYour Wazuh system is actively monitoring {active_agents} endpoints and has detected {total_alerts} security events."
            elif total_agents > 0:
                answer += f"\nYour Wazuh system is actively monitoring {active_agents} endpoints with no recent security events."
            else:
                answer += f"\nNo Wazuh data is currently available."
        
        return answer
    
    def _generate_fallback_wazuh_response(self, query: str, llm_result: Dict, error: str) -> Dict:
        """Generate fallback response when Wazuh query fails"""
        return {
            'llm': llm_result,
            'tool_responses': [],
            'unified_investigation': {},
            'report_json': {
                "alert_id": "N/A",
                "timestamp": None,
                "severity": "Info",
                "attack_type": "Wazuh Query Error",
                "affected_host": "N/A",
                "source_ip": "N/A",
                "destination_ip": "N/A",
                "mitre_technique": "N/A",
                "status": "Error",
                "confidence": "100%",
                "indicators_of_compromise": [],
                "threat_intelligence": [],
                "investigation_summary": f"Wazuh query failed: {query}. Error: {error}",
                "recommendations": ["Check Wazuh server connectivity", "Verify API credentials", "Review Wazuh configuration"],
                "tool_reports": {
                    "virustotal_report": None,
                    "wazuh_report": None,
                    "misp_report": None,
                    "shodan_report": None,
                    "abuseipdb_report": None,
                    "alienvault_report": None,
                    "windows_defender_report": None,
                    "windows_logs_report": None
                },
                "visual_data": {
                    "threat_score": 0,
                    "timeline": [],
                    "attack_graph": [],
                    "tool_usage": []
                },
                "tools_used": [],
                "data_collection_summary": f"Error: {error}"
            },
            'report_html': f"<p>Error: {error}</p>",
            'ai_answer': f"I encountered an error while processing your Wazuh query: {error}. Please check your Wazuh server connectivity and configuration.",
            'extracted_data': {}
        }
        
        # Default LLM-only response for non-Wazuh queries
        report_json = {
            "alert_id": "N/A",
            "timestamp": None,
            "severity": "Info",
            "attack_type": "Knowledge Base Query",
            "affected_host": "N/A",
            "source_ip": entities.get('ip') or "N/A",
            "destination_ip": "N/A",
            "mitre_technique": "N/A",
            "status": "Informational",
            "confidence": "100%",
            "indicators_of_compromise": [],
            "threat_intelligence": [],
            "investigation_summary": f"General security query regarding '{query}'. Processed directly by Copilot AI Engine.",
            "recommendations": ["Follow standard security best practices for prevention and monitoring."],
            "tool_reports": {
                "virustotal_report": None,
                "wazuh_report": None,
                "misp_report": None,
                "shodan_report": None,
                "abuseipdb_report": None,
                "alienvault_report": None,
                "windows_defender_report": None,
                "windows_logs_report": None
            },
            "visual_data": {
                "threat_score": 0,
                "timeline": [],
                "attack_graph": [],
                "tool_usage": []
            },
            "tools_used": [],
            "data_collection_summary": "LLM knowledge base query only - no external tools used"
        }

        report_html = generate_report_html(report_json)
        ai_answer = self.llm_client.generate_response(query, report_json)

        return {
            'llm': llm_result,
            'tool_responses': [],
            'unified_investigation': {
                "alert_id": "N/A",
                "severity": "Info",
                "attack_type": "Knowledge Base Query",
                "affected_host": "N/A",
                "source_ip": "N/A",
                "destination_ip": "N/A",
                "summary": f"Answered query '{query}' via Copilot AI Knowledge Base.",
                "tool_reports": report_json['tool_reports']
            },
            'report_json': report_json,
            'report_html': report_html,
            'ai_answer': ai_answer,
            'extracted_data': entities
        }

    @staticmethod
    def _tool_result(tool: str, command: str, data: Dict, response: Any = None) -> Dict:
        """Normalize executed tool results for the chat API and investigation report."""
        if isinstance(response, dict):
            status = response.get("status")
            details = response.get("details")
        else:
            status = getattr(response, "status", None)
            details = getattr(response, "details", None)

        return {
            "tool": tool,
            "command": command,
            "data": data,
            "success": status not in ("error", "failed"),
            "status": status or "completed",
            "details": details,
        }

    def _generate_tool_separated_response(self, extracted_data: Dict, query: str, responses: List) -> str:
        """Generate a detailed investigation summary grounded in executed tool results."""
        answer = f"**Investigation Report**\n\n**Requested investigation:** {query}\n\n"
        tool_usage_log = extracted_data.get('tool_usage_log', [])
        unique_tools = list(dict.fromkeys(
            log.get('tool', 'Unknown Tool') if isinstance(log, dict) else str(log)
            for log in tool_usage_log
        ))

        if not unique_tools:
            return answer + "No security tools were executed and no live investigation findings are available."

        answer += f"**Assessment:** {self._calculate_severity(extracted_data)} severity\n\n"
        answer += f"**Investigation summary:** {self._generate_investigation_summary(extracted_data)}\n\n"
        answer += f"**Tools used:** {len(unique_tools)}\n"

        response_by_tool = {
            response.get("tool"): response
            for response in responses
            if isinstance(response, dict) and response.get("tool")
        }

        for tool_name in unique_tools:
            tool_response = response_by_tool.get(tool_name, {})
            status = "completed" if tool_response.get("success", True) else "failed"
            command = tool_response.get("command")
            answer += f"- **{tool_name}:** {status}"
            if command:
                answer += f" (`{command}`)"
            if tool_response.get("details"):
                answer += f". {tool_response['details']}"
            answer += "\n"

        for tool_name in unique_tools:
            answer += f"\n---\n\n## {tool_name} findings\n\n"
            if tool_name == "Wazuh":
                answer += self._format_wazuh_results(extracted_data)
            elif tool_name == "VirusTotal":
                answer += self._format_virustotal_results(extracted_data)
            elif tool_name == "MISP":
                answer += self._format_misp_results(extracted_data)
            elif tool_name == "Shodan":
                answer += self._format_shodan_results(extracted_data)
            elif tool_name == "AbuseIPDB":
                answer += self._format_abuseipdb_results(extracted_data)
            elif tool_name == "AlienVault OTX":
                answer += self._format_alienvault_results(extracted_data)
            elif tool_name == "WindowsDefender":
                answer += self._format_windows_defender_results(extracted_data)
            elif tool_name == "WindowsLogs":
                answer += self._format_windows_logs_results(extracted_data)
            elif tool_name == "SOAR":
                answer += self._format_soar_results(extracted_data)
            elif tool_name in ["MalwareBazaar", "URLhaus"]:
                answer += self._format_malwarebazaar_results(extracted_data)
            elif tool_name == "CISA_KEV":
                answer += self._format_cisa_kev_results(extracted_data)
            elif tool_name == "IP_Intel":
                answer += self._format_ip_intel_results(extracted_data)
            elif tool_name == "CVE_Search":
                answer += self._format_cve_search_results(extracted_data)
            elif tool_name == "MITRE_ATTACK":
                answer += self._format_mitre_attack_results(extracted_data)
            elif tool_name == "ML_Threat_Engine":
                answer += self._format_ml_threat_results(extracted_data)
            else:
                answer += "Tool completed without a configured findings formatter.\n"

        recommendations = self._generate_recommendations(extracted_data)
        answer += "\n---\n\n**Recommended actions**\n"
        if recommendations:
            answer += "".join(f"- {recommendation}\n" for recommendation in recommendations)
        else:
            answer += "- No specific remediation was generated from the available evidence.\n"
        answer += (
            "\n**Data limitations:** Findings reflect only the telemetry returned by the configured tools. "
            "An empty result means no matching data was returned; it does not prove that the activity did not occur.\n"
        )
        return answer
    
    def _format_wazuh_results(self, extracted_data: Dict) -> str:
        """Format Wazuh results in easy-to-read format."""
        wazuh_data = extracted_data.get('wazuh_data', {})
        if not isinstance(wazuh_data, dict):
            wazuh_data = {}
        
        result = ""
        
        # Agent information
        agents_data = wazuh_data.get('agents', {})
        if isinstance(agents_data, dict):
            agents = agents_data.get('agents', [])
        elif isinstance(agents_data, list):
            agents = agents_data
        else:
            agents = []
        
        if not agents and extracted_data.get('wazuh_agents'):
            agents = extracted_data['wazuh_agents']
        
        if agents:
            result += "### 📊 Protected Endpoints (Wazuh Fleet)\n"
            for agent in agents[:5]:  # Show first 5
                if isinstance(agent, dict):
                    name = agent.get('name', 'Unknown')
                    status = agent.get('status', 'Unknown')
                    ip = agent.get('ip', 'N/A')
                    os_info = agent.get('os', {})
                    os_name = os_info.get('name', 'Unknown') if isinstance(os_info, dict) else 'Unknown'
                    status_emoji = "✅" if status == 'active' else "❌"
                    result += f"- {status_emoji} **{name}** (`{ip}`) — OS: *{os_name}* — Status: **{status.upper()}**\n"
            result += "\n"
        
        # Alert information
        alerts_data = wazuh_data.get('alerts', {})
        if isinstance(alerts_data, dict):
            alerts = alerts_data.get('alerts', [])
        elif isinstance(alerts_data, list):
            alerts = alerts_data
        else:
            alerts = []
        
        if not alerts and extracted_data.get('alerts'):
            alerts = extracted_data['alerts']
        
        stats = wazuh_data.get('statistics', {})
        total_alerts_stat = int(stats.get('total_alerts', 0) if isinstance(stats, dict) else 0)

        if alerts:
            result += "### 🚨 Live Wazuh Security Alerts\n"
            result += f"**Total Active Alerts Detected:** `{max(len(alerts), total_alerts_stat)}`\n\n"
            for alert in alerts[:6]:  # Show top 6
                if isinstance(alert, dict):
                    rule = alert.get('rule', {})
                    description = rule.get('description', alert.get('description', 'Security Event')) if isinstance(rule, dict) else 'Security Event'
                    level = rule.get('level', alert.get('level', 3)) if isinstance(rule, dict) else 3
                    agent = alert.get('agent', {})
                    agent_name = agent.get('name', alert.get('agent_name', 'wazuh-server')) if isinstance(agent, dict) else 'wazuh-server'
                    severity = alert.get('severity', 'Medium' if level >= 5 else 'Low')
                    result += f"- **{description}** (Severity: `{severity}`, Level `{level}`) from `{agent_name}`\n"
            result += "\n"
        elif total_alerts_stat > 0:
            result += f"### 🚨 Live Wazuh Security Alerts\n**Total Real Alerts Ingested:** `{total_alerts_stat}`\n\n"

        # Statistics
        if stats:
            result += "### 📈 Wazuh SIEM Telemetry Statistics\n"
            if isinstance(stats, dict):
                total_alerts = stats.get('total_alerts', len(alerts))
                total_agents = stats.get('total_agents', len(agents))
                active_agents = stats.get('active_agents', len([a for a in agents if a.get('status') == 'active']))
                result += f"- **Total Monitored Endpoints:** {total_agents}\n"
                result += f"- **Active Connected Agents:** {active_agents}\n"
                result += f"- **Real Security Alerts:** {total_alerts}\n"
                sev_dist = stats.get('severity_distribution')
                if isinstance(sev_dist, dict):
                    result += f"- **Severity Breakdown:** Critical: {sev_dist.get('Critical', 0)} | High: {sev_dist.get('High', 0)} | Medium: {sev_dist.get('Medium', 0)} | Low: {sev_dist.get('Low', 0)}\n"
            result += "\n"
        
        if not result:
            result = "No Wazuh telemetry events detected.\n"
        
        return result
    
    def _format_virustotal_results(self, extracted_data: Dict) -> str:
        """Format VirusTotal results in easy-to-read format."""
        vt_data = extracted_data.get('virustotal_data', {})
        if not isinstance(vt_data, dict):
            vt_data = {}
        
        result = "### 🔍 Threat Analysis\n"
        
        if vt_data.get('malicious'):
            result += "- **Status**: 🚨 MALICIOUS\n"
        elif vt_data.get('suspicious'):
            result += "- **Status**: ⚠️ SUSPICIOUS\n"
        else:
            result += "- **Status**: ✅ CLEAN\n"
        
        detections = vt_data.get('detections', 0)
        result += f"- **Detections**: {detections}\n"
        
        if vt_data.get('id'):
            result += f"- **Target**: {vt_data.get('id')}\n"
        
        result += "\n"
        return result
    
    def _format_misp_results(self, extracted_data: Dict) -> str:
        """Format MISP results in easy-to-read format."""
        misp_data = extracted_data.get('misp_data', {})
        if not isinstance(misp_data, dict):
            misp_data = {}
        
        result = "### 🎯 Threat Intelligence\n"
        
        events = misp_data.get('events', [])
        if isinstance(events, list) and events:
            result += f"- **Events Found**: {len(events)}\n"
            for event in events[:3]:  # Show first 3
                if isinstance(event, dict):
                    info = event.get('info', 'Unknown')
                    result += f"- {info}\n"
        else:
            result += "- No threat intelligence events found.\n"
        
        result += "\n"
        return result
    
    def _format_shodan_results(self, extracted_data: Dict) -> str:
        """Format Shodan results in easy-to-read format."""
        shodan_data = extracted_data.get('shodan_data', {})
        if not isinstance(shodan_data, dict):
            shodan_data = {}
        
        result = "### 🌐 Network Intelligence\n"
        
        if shodan_data.get('ip'):
            result += f"- **IP**: {shodan_data.get('ip')}\n"
        
        if shodan_data.get('hostnames'):
            hostnames = shodan_data.get('hostnames', [])
            if isinstance(hostnames, list):
                result += f"- **Hostnames**: {', '.join(hostnames[:3])}\n"
        
        if shodan_data.get('ports'):
            ports = shodan_data.get('ports', [])
            if isinstance(ports, list):
                result += f"- **Open Ports**: {', '.join(map(str, ports[:5]))}\n"
        
        result += "\n"
        return result
    
    def _format_abuseipdb_results(self, extracted_data: Dict) -> str:
        """Format AbuseIPDB results in easy-to-read format."""
        abuse_data = extracted_data.get('abuseipdb_data', {})
        if not isinstance(abuse_data, dict):
            abuse_data = {}
        
        result = "### 🛡️ IP Reputation\n"
        
        if abuse_data.get('abuse_confidence_score'):
            score = abuse_data.get('abuse_confidence_score')
            result += f"- **Abuse Score**: {score}%\n"
            if score > 50:
                result += "- **Status**: 🚨 HIGH RISK\n"
            elif score > 25:
                result += "- **Status**: ⚠️ MEDIUM RISK\n"
            else:
                result += "- **Status**: ✅ LOW RISK\n"
        
        if abuse_data.get('total_reports'):
            result += f"- **Total Reports**: {abuse_data.get('total_reports')}\n"
        
        result += "\n"
        return result
    
    def _format_alienvault_results(self, extracted_data: Dict) -> str:
        """Format AlienVault OTX results in easy-to-read format."""
        otx_data = extracted_data.get('alienvault_data', {})
        if not isinstance(otx_data, dict):
            otx_data = {}
        
        result = "### 🎭 Threat Intelligence (OTX)\n"
        
        pulses = otx_data.get('pulses', [])
        if isinstance(pulses, list) and pulses:
            result += f"- **Threat Pulses**: {len(pulses)}\n"
            for pulse in pulses[:3]:
                if isinstance(pulse, dict):
                    name = pulse.get('name', 'Unknown')
                    result += f"- {name}\n"
        else:
            result += "- No threat pulses found.\n"
        
        result += "\n"
        return result
    
    def _format_windows_defender_results(self, extracted_data: Dict) -> str:
        """Format Windows Defender results in easy-to-read format."""
        defender_data = extracted_data.get('windows_defender_data', {})
        if not isinstance(defender_data, dict):
            defender_data = {}
        
        result = "### 🪟 Endpoint Protection\n"
        
        status = defender_data.get('status', {})
        if isinstance(status, dict):
            result += f"- **Real-time Protection**: {'✅ Enabled' if status.get('real_time_protection') else '❌ Disabled'}\n"
            result += f"- **Quick Scan Status**: {status.get('quick_scan_status', 'Unknown')}\n"
        
        threats = defender_data.get('threats', [])
        if isinstance(threats, list) and threats:
            result += f"- **Threats Found**: {len(threats)}\n"
        else:
            result += "- **Threats Found**: 0\n"
        
        result += "\n"
        return result
    
    def _format_windows_logs_results(self, extracted_data: Dict) -> str:
        """Format Windows Logs results in easy-to-read format."""
        logs_data = extracted_data.get('windows_logs_data', {})
        if not isinstance(logs_data, dict):
            logs_data = {}
        
        result = "### 📋 System Logs\n"
        
        security_events = logs_data.get('security_events', [])
        if isinstance(security_events, list) and security_events:
            result += f"- **Security Events**: {len(security_events)}\n"
        else:
            result += "- **Security Events**: 0\n"
        
        system_events = logs_data.get('system_events', [])
        if isinstance(system_events, list) and system_events:
            result += f"- **System Events**: {len(system_events)}\n"
        else:
            result += "- **System Events**: 0\n"

        application_events = logs_data.get('application_events', [])
        if isinstance(application_events, list) and application_events:
            result += f"- **Application Events**: {len(application_events)}\n"
        else:
            result += "- **Application Events**: 0\n"
        
        result += "\n"
        return result

    def _format_soar_results(self, extracted_data: Dict) -> str:
        """Format SOAR active defense results."""
        soar_data = extracted_data.get('soar_data', {})
        if not isinstance(soar_data, dict):
            soar_data = {}

        result = "### 🛡️ SOAR Active Defense & Countermeasures\n"
        action = soar_data.get('action')
        status = soar_data.get('status', 'executed')
        target = soar_data.get('ip') or soar_data.get('host') or soar_data.get('file') or soar_data.get('target', 'Target')

        if action == 'block_ip':
            result += f"- **Action Executed:** 🚫 IP Blackhole Containment\n"
            result += f"- **Target IP:** `{target}`\n"
            result += f"- **Status:** `{status}`\n"
            if soar_data.get('firewall_rule'):
                result += f"- **Firewall Rule:** `{soar_data['firewall_rule']}`\n"
            result += f"- **Mitigation:** {soar_data.get('mitigation', 'Perimeter edge firewall rule enforced.')}\n"
        elif action == 'isolate_host':
            result += f"- **Action Executed:** 🔒 Host Network Isolation\n"
            result += f"- **Target Host:** `{target}`\n"
            result += f"- **Status:** `{status}`\n"
            if soar_data.get('isolation_rule'):
                result += f"- **Isolation Rule:** `{soar_data['isolation_rule']}`\n"
            result += f"- **Mitigation:** {soar_data.get('mitigation', 'Network adapter isolated from enterprise LAN.')}\n"
        elif action == 'run_playbook':
            result += f"- **Playbook Executed:** ⚡ `{soar_data.get('playbook', 'automated_response')}`\n"
            result += f"- **Status:** `{status}`\n"
            steps = soar_data.get('steps_completed', [])
            if steps:
                result += f"- **Steps Completed:** {', '.join(steps)}\n"
        elif 'playbooks' in soar_data:
            pbs = soar_data.get('playbooks', [])
            result += f"- **Available Playbooks:** {len(pbs)} automated mitigation workflows loaded\n"
            for pb in pbs[:4]:
                if isinstance(pb, dict):
                    result += f"  - `{pb.get('id')}`: {pb.get('name')}\n"
        elif 'actions' in soar_data:
            acts = soar_data.get('actions', [])
            result += f"- **Recent Automated Actions:** {len(acts)} defensive responses recorded\n"
            for a in acts[-3:]:
                if isinstance(a, dict):
                    result += f"  - `{a.get('action')}` on `{a.get('target')}` ({a.get('status')})\n"
        else:
            msg = soar_data.get('message') or soar_data.get('result') or 'SOAR defensive actions synchronized.'
            result += f"- {msg}\n"

        result += "\n"
        return result

    # Helper methods for report generation
    def _calculate_severity(self, extracted_data: Dict) -> str:
        """Calculate overall severity based on all tool data."""
        # Check Wazuh alert severity
        wazuh_data = extracted_data.get('wazuh_data', {})
        if not isinstance(wazuh_data, dict):
            wazuh_data = {}
        
        alerts = wazuh_data.get('alerts', [])
        if isinstance(alerts, list) and alerts:
            high_severity_alerts = []
            for a in alerts:
                if isinstance(a, dict):
                    rule = a.get('rule', {})
                    if isinstance(rule, dict):
                        level = rule.get('level', 0)
                        try:
                            level_int = int(level) if level is not None else 0
                            if level_int >= 10:
                                high_severity_alerts.append(a)
                        except (ValueError, TypeError):
                            pass
            if high_severity_alerts:
                return 'Critical'
            elif len(alerts) > 5:
                return 'High'
            elif len(alerts) > 0:
                return 'Medium'
        
        # Check VirusTotal results
        vt_data = extracted_data.get('virustotal_data', {})
        if not isinstance(vt_data, dict):
            vt_data = {}
        
        if vt_data.get('malicious') or vt_data.get('suspicious'):
            return 'High'
        
        # Default to Low if no threats detected
        return 'Low'

    def _determine_attack_type(self, extracted_data: Dict) -> str:
        """Determine attack type based on collected data."""
        wazuh_data = extracted_data.get('wazuh_data', {})
        if not isinstance(wazuh_data, dict):
            wazuh_data = {}
        
        alerts = wazuh_data.get('alerts', [])
        if isinstance(alerts, list) and alerts:
            return 'Security Event'
        return 'Unknown'

    def _extract_mitre_technique(self, extracted_data: Dict) -> str:
        """Extract MITRE technique from collected data."""
        wazuh_data = extracted_data.get('wazuh_data', {})
        if not isinstance(wazuh_data, dict):
            wazuh_data = {}
        
        rules = wazuh_data.get('rules', [])
        if isinstance(rules, list) and rules:
            return 'T1234'  # Placeholder
        return 'N/A'

    def _calculate_confidence(self, extracted_data: Dict) -> str:
        """Calculate confidence based on data sources."""
        tool_usage_log = extracted_data.get('tool_usage_log', [])
        if not isinstance(tool_usage_log, list):
            tool_usage_log = []
        
        tool_count = len(tool_usage_log)
        if tool_count >= 4:
            return 'High'
        elif tool_count >= 2:
            return 'Medium'
        return 'Low'

    def _extract_iocs(self, extracted_data: Dict) -> List:
        """Extract indicators of compromise from all tools."""
        iocs = []
        
        if extracted_data.get('source_ip'):
            iocs.append(f"IP: {extracted_data['source_ip']}")
        
        vt_data = extracted_data.get('virustotal_data', {})
        if isinstance(vt_data, dict) and vt_data.get('hash'):
            iocs.append(f"Hash: {vt_data['hash']}")
        
        return iocs

    def _extract_threat_intelligence(self, extracted_data: Dict) -> List:
        """Extract threat intelligence from all sources."""
        intel = []
        
        # Add VirusTotal findings
        vt_data = extracted_data.get('virustotal_data', {})
        if isinstance(vt_data, dict) and vt_data.get('detections'):
            intel.append(f"VirusTotal: {vt_data['detections']} detections")
        
        # Add AbuseIPDB findings
        abuse_data = extracted_data.get('abuseipdb_data', {})
        if isinstance(abuse_data, dict) and abuse_data.get('abuse_confidence'):
            intel.append(f"AbuseIPDB: {abuse_data['abuse_confidence']}% abuse confidence")
        
        return intel

    def _generate_investigation_summary(self, extracted_data: Dict) -> str:
        """Generate comprehensive investigation summary."""
        tool_usage_log = extracted_data.get('tool_usage_log', [])
        if not isinstance(tool_usage_log, list):
            tool_usage_log = []
        
        # Get unique tools used
        tools_used = list(set([log.get('tool', 'Unknown') if isinstance(log, dict) else str(log) for log in tool_usage_log]))
        summary = f"Comprehensive investigation using {len(tools_used)} security tools: {', '.join(tools_used)}. "
        
        wazuh_data = extracted_data.get('wazuh_data', {})
        if isinstance(wazuh_data, dict) and 'Wazuh' in tools_used:
            alerts = wazuh_data.get('alerts', [])
            alert_count = len(alerts) if isinstance(alerts, list) else 0
            summary += f"Wazuh analyzed {alert_count} alerts. "

        windows_logs = extracted_data.get('windows_logs_data', {})
        if isinstance(windows_logs, dict) and windows_logs:
            event_counts = {
                category: len(events) if isinstance(events, list) else 0
                for category, events in windows_logs.items()
            }
            total_events = sum(event_counts.values())
            summary += (
                f"Collected {total_events} Windows events "
                f"(security: {event_counts.get('security_events', 0)}, "
                f"system: {event_counts.get('system_events', 0)}, "
                f"application: {event_counts.get('application_events', 0)}). "
            )
        
        if extracted_data.get('source_ip'):
            summary += f"Primary investigation target: {extracted_data['source_ip']}. "
        
        return summary

    def _generate_recommendations(self, extracted_data: Dict) -> List:
        """Generate recommendations based on all tool findings."""
        recommendations = []
        
        severity = self._calculate_severity(extracted_data)
        if severity == 'Critical':
            recommendations.append("IMMEDIATE: Isolate affected systems from network")
            recommendations.append("IMMEDIATE: Escalate to incident response team")
        
        wazuh_data = extracted_data.get('wazuh_data', {})
        if isinstance(wazuh_data, dict) and wazuh_data.get('vulnerabilities'):
            recommendations.append("Address Wazuh-detected vulnerabilities")
        
        windows_defender_data = extracted_data.get('windows_defender_data', {})
        if isinstance(windows_defender_data, dict) and windows_defender_data.get('threats'):
            recommendations.append("Review and remediate Windows Defender threats")
        
        recommendations.append("Continue monitoring for related alerts")
        recommendations.append("Document all investigation findings")
        
        return recommendations

    def _generate_wazuh_report(self, extracted_data: Dict) -> Dict:
        """Generate detailed Wazuh report."""
        wazuh_data = extracted_data.get('wazuh_data', {})
        if not isinstance(wazuh_data, dict):
            wazuh_data = {}
        
        return {
            "alerts_count": len(wazuh_data.get('alerts', [])) if isinstance(wazuh_data.get('alerts', []), list) else 0,
            "agents_count": len(wazuh_data.get('agents', [])) if isinstance(wazuh_data.get('agents', []), list) else 0,
            "active_agents": extracted_data.get('active_agents', 0),
            "statistics": wazuh_data.get('statistics', {}),
            "vulnerabilities": len(wazuh_data.get('vulnerabilities', [])) if isinstance(wazuh_data.get('vulnerabilities', []), list) else 0,
            "rules_count": len(wazuh_data.get('rules', [])) if isinstance(wazuh_data.get('rules', []), list) else 0,
            "data_sources": list(wazuh_data.keys()) if isinstance(wazuh_data, dict) else []
        }

    def _generate_virustotal_report(self, extracted_data: Dict) -> Dict:
        """Generate detailed VirusTotal report."""
        vt_data = extracted_data.get('virustotal_data', {})
        if not isinstance(vt_data, dict):
            vt_data = {}
        
        return {
            "scans": vt_data.get('scans', {}),
            "detections": vt_data.get('detections', 0),
            "malicious": vt_data.get('malicious', False),
            "suspicious": vt_data.get('suspicious', False),
            "scan_date": vt_data.get('scan_date'),
            "hash": vt_data.get('hash')
        }

    def _generate_misp_report(self, extracted_data: Dict) -> Dict:
        """Generate detailed MISP report."""
        misp_data = extracted_data.get('misp_data', {})
        if not isinstance(misp_data, dict):
            misp_data = {}
        
        return {
            "events_count": len(misp_data.get('events', [])) if isinstance(misp_data.get('events', []), list) else 0,
            "attributes_count": len(misp_data.get('attributes', [])) if isinstance(misp_data.get('attributes', []), list) else 0,
            "threat_level": misp_data.get('threat_level'),
            "analysis": misp_data.get('analysis')
        }

    def _generate_shodan_report(self, extracted_data: Dict) -> Dict:
        """Generate detailed Shodan report."""
        shodan_data = extracted_data.get('shodan_data', {})
        if not isinstance(shodan_data, dict):
            shodan_data = {}
        
        return {
            "ports": shodan_data.get('ports', []) if isinstance(shodan_data.get('ports', []), list) else [],
            "vulnerabilities": shodan_data.get('vulnerabilities', []) if isinstance(shodan_data.get('vulnerabilities', []), list) else [],
            "services": shodan_data.get('services', []) if isinstance(shodan_data.get('services', []), list) else [],
            "hostnames": shodan_data.get('hostnames', []) if isinstance(shodan_data.get('hostnames', []), list) else []
        }

    def _generate_abuseipdb_report(self, extracted_data: Dict) -> Dict:
        """Generate detailed AbuseIPDB report."""
        abuse_data = extracted_data.get('abuseipdb_data', {})
        if not isinstance(abuse_data, dict):
            abuse_data = {}
        
        return {
            "abuse_confidence": abuse_data.get('abuse_confidence'),
            "reports_count": abuse_data.get('reports_count'),
            "last_report": abuse_data.get('last_report'),
            "country": abuse_data.get('country')
        }

    def _generate_alienvault_report(self, extracted_data: Dict) -> Dict:
        """Generate detailed AlienVault report."""
        alienvault_data = extracted_data.get('alienvault_data', {})
        if not isinstance(alienvault_data, dict):
            alienvault_data = {}
        
        return {
            "pulses": alienvault_data.get('pulses', []) if isinstance(alienvault_data.get('pulses', []), list) else [],
            "threat_score": alienvault_data.get('threat_score'),
            "reputation": alienvault_data.get('reputation')
        }

    def _generate_windows_defender_report(self, extracted_data: Dict) -> Dict:
        """Generate detailed Windows Defender report."""
        defender_data = extracted_data.get('windows_defender_data', {})
        if not isinstance(defender_data, dict):
            defender_data = {}
        
        threats = defender_data.get('threats', [])
        scan_history = defender_data.get('scan_history', {})
        if not isinstance(scan_history, dict):
            scan_history = {}
        
        status = defender_data.get('status', {})
        if not isinstance(status, dict):
            status = {}
        
        return {
            "status": defender_data.get('status'),
            "threats_count": len(threats) if isinstance(threats, list) else 0,
            "last_scan": scan_history.get('last_scan'),
            "real_time_protection": status.get('real_time_protection')
        }

    def _generate_windows_logs_report(self, extracted_data: Dict) -> Dict:
        """Generate detailed Windows Logs report."""
        logs_data = extracted_data.get('windows_logs_data', {})
        if not isinstance(logs_data, dict):
            logs_data = {}
        
        security_events = logs_data.get('security_events', [])
        system_events = logs_data.get('system_events', [])
        application_events = logs_data.get('application_events', [])
        
        return {
            "security_events_count": len(security_events) if isinstance(security_events, list) else 0,
            "system_events_count": len(system_events) if isinstance(system_events, list) else 0,
            "application_events_count": len(application_events) if isinstance(application_events, list) else 0,
            "recent_events": security_events[:5] if isinstance(security_events, list) else []
        }

    def _calculate_threat_score(self, extracted_data: Dict) -> int:
        """Calculate overall threat score based on all tool data."""
        score = 0
        
        # Wazuh contribution
        wazuh_data = extracted_data.get('wazuh_data', {})
        if not isinstance(wazuh_data, dict):
            wazuh_data = {}
        
        alerts = wazuh_data.get('alerts', [])
        if isinstance(alerts, list) and alerts:
            high_severity = len([a for a in alerts if isinstance(a, dict) and a.get('rule', {}).get('level', 0) >= 10])
            score += min(high_severity * 10, 30)
        
        # VirusTotal contribution
        vt_data = extracted_data.get('virustotal_data', {})
        if not isinstance(vt_data, dict):
            vt_data = {}
        
        if vt_data.get('malicious'):
            score += 25
        elif vt_data.get('suspicious'):
            score += 15
        
        # AbuseIPDB contribution
        abuse_data = extracted_data.get('abuseipdb_data', {})
        if isinstance(abuse_data, dict) and abuse_data.get('abuse_confidence'):
            score += int(abuse_data['abuse_confidence'] / 4)
        
        return min(score, 100)

    def _extract_timeline(self, extracted_data: Dict) -> List:
        """Extract timeline from Wazuh alerts."""
        timeline = []
        wazuh_data = extracted_data.get('wazuh_data', {})
        if not isinstance(wazuh_data, dict):
            wazuh_data = {}
        
        alerts = wazuh_data.get('alerts', [])
        if not isinstance(alerts, list):
            alerts = []
        
        for alert in alerts[:10]:
            if isinstance(alert, dict):
                rule = alert.get('rule', {})
                if isinstance(rule, dict):
                    timeline.append({
                        'timestamp': alert.get('timestamp'),
                        'event': rule.get('description'),
                        'severity': rule.get('level')
                    })
        
        return timeline

    def _extract_attack_graph(self, extracted_data: Dict) -> List:
        """Extract attack graph from collected data."""
        # Placeholder for attack graph generation
        return []

    def _generate_data_collection_summary(self, extracted_data: Dict) -> Dict:
        """Generate summary of data collection from all tools."""
        tool_usage_log = extracted_data.get('tool_usage_log', [])
        if not isinstance(tool_usage_log, list):
            tool_usage_log = []
        
        # Calculate total data points safely
        total_data_points = 0
        for data in extracted_data.values():
            if isinstance(data, list):
                # Skip tool_usage_log list
                if data is not tool_usage_log:
                    total_data_points += len(data)
            elif isinstance(data, dict):
                # Skip if it's the tool_usage_log dict
                if not (data == tool_usage_log or 'tool_usage_log' in data):
                    total_data_points += len(data)
        
        wazuh_data = extracted_data.get('wazuh_data', {})
        if not isinstance(wazuh_data, dict):
            wazuh_data = {}
        
        # Calculate tool success rate safely
        completed_tools = len([log for log in tool_usage_log if isinstance(log, dict) and log.get('status') == 'completed'])
        tool_success_rate = completed_tools / max(len(tool_usage_log), 1)
        
        return {
            "tools_used": len(tool_usage_log),
            "total_data_points": total_data_points,
            "wazuh_data_types": list(wazuh_data.keys()),
            "tool_success_rate": tool_success_rate
        }
    def _format_malwarebazaar_results(self, extracted_data: Dict) -> str:
        """Format abuse.ch MalwareBazaar & URLhaus findings."""
        mb = extracted_data.get('malwarebazaar_data', {})
        if not mb or not isinstance(mb, dict):
            return "No MalwareBazaar intelligence records retrieved.\n"
        res = "### 🦠 abuse.ch MalwareBazaar / URLhaus Threat Intelligence (100% Free)\n"
        res += f"- **Target Queried:** `{mb.get('hash') or mb.get('target', 'N/A')}`\n"
        res += f"- **Verdict:** **{mb.get('verdict', 'UNKNOWN')}** (Risk: `{mb.get('risk_level', 'Low')}`)\n"
        if mb.get('threat_name'):
            res += f"- **Threat Classification:** {mb.get('threat_name')}\n"
        if mb.get('signature'):
            res += f"- **Malware Signature:** `{mb.get('signature')}` (File Type: `{mb.get('file_type', 'exe')}`)\n"
        if mb.get('tags'):
            res += f"- **Adversary Tags:** `{', '.join(mb.get('tags', []))}`\n"
        if mb.get('delivery'):
            res += f"- **Observed Delivery Vector:** {mb.get('delivery')}\n"
        if mb.get('note'):
            res += f"- **Intelligence Note:** {mb.get('note')}\n"
        res += f"- **Source:** {mb.get('threat_source', 'abuse.ch Community Feed')}\n\n"
        return res

    def _format_cisa_kev_results(self, extracted_data: Dict) -> str:
        """Format CISA Known Exploited Vulnerabilities Catalog findings."""
        kev = extracted_data.get('cisa_kev_data', {})
        if not kev or not isinstance(kev, dict):
            return "No CISA KEV records retrieved.\n"
        res = "### 🛡️ CISA Known Exploited Vulnerabilities (KEV) Catalog (US DHS / CISA)\n"
        cve = kev.get('cve_id', 'N/A')
        in_kev = kev.get('in_cisa_kev', False)
        if in_kev:
            res += f"- **Vulnerability:** **{cve}** — `{kev.get('product', 'Unknown Product')}` by *{kev.get('vendor', 'Unknown')}*\n"
            res += f"- **Exploitation Status:** 🚨 **CONFIRMED ACTIVELY EXPLOITED IN THE WILD (CISA KEV)**\n"
            res += f"- **Vulnerability Name:** {kev.get('vulnerability_name')}\n"
            res += f"- **Known Ransomware Campaign Use:** **{kev.get('known_ransomware_campaign_use', 'Suspected')}**\n"
            res += f"- **Remediation Action Required:** {kev.get('required_action')}\n"
            res += f"- **Federal Compliance Due Date:** `{kev.get('remediation_due_date', 'Immediate')}`\n"
            res += f"- **CVSS v3 Baseline:** `{kev.get('cvss_score', 9.0)} / 10.0 (CRITICAL)`\n"
        else:
            res += f"- **CVE Identifier:** `{cve}`\n"
            res += f"- **CISA KEV Status:** Clean — Not currently cataloged as a weaponized in-the-wild exploit.\n"
            res += f"- **Guidance:** {kev.get('guidance', 'Standard patch cadence applies.')}\n"
        res += f"- **Authoritative Body:** {kev.get('authority', 'CISA Cybersecurity Division')}\n\n"
        return res

    def _format_ip_intel_results(self, extracted_data: Dict) -> str:
        """Format free IP-API Geolocation, ASN and Reverse DNS findings."""
        ip_data = extracted_data.get('ip_intel_data', {})
        if not ip_data or not isinstance(ip_data, dict):
            return "No IP intelligence records retrieved.\n"
        res = "### 🌐 IP-API Network Geolocation & ASN Intelligence (100% Free)\n"
        res += f"- **Target IP:** `{ip_data.get('ip', 'N/A')}`\n"
        res += f"- **Location:** 📍 **{ip_data.get('city', 'Unknown')}, {ip_data.get('country', 'Unknown')}** (TZ: `{ip_data.get('timezone', 'UTC')}`)\n"
        res += f"- **Autonomous System (ASN):** `{ip_data.get('asn', 'Unknown')}`\n"
        res += f"- **Internet Service Provider (ISP):** `{ip_data.get('isp', 'Unknown')}` (Org: *{ip_data.get('organization', 'N/A')}*)\n"
        res += f"- **Reverse DNS PTR:** `{ip_data.get('reverse_dns', 'None')}`\n"
        res += f"- **Hosting / Datacenter Node:** `{'YES (Potential VPS / Disposable C2)' if ip_data.get('is_datacenter_hosting') else 'No (Residential / Access Net)'}`\n"
        res += f"- **Proxy / VPN / Anonymizer Flag:** `{'YES' if ip_data.get('is_proxy_vpn') else 'No'}`\n"
        res += f"- **Calculated Threat Rating:** `{ip_data.get('risk_level', 'Low').upper()} (Score: {ip_data.get('risk_score', 10)}/100)`\n\n"
        return res

    def _format_cve_search_results(self, extracted_data: Dict) -> str:
        """Format CIRCL / OSV vulnerability search findings."""
        cve = extracted_data.get('cve_search_data', {})
        if not cve or not isinstance(cve, dict):
            return "No CVE search records retrieved.\n"
        res = "### 🔍 CIRCL / OSV Open Vulnerability Intelligence (Free CVE Database)\n"
        res += f"- **Vulnerability:** `{cve.get('cve_id', 'N/A')}`\n"
        res += f"- **CVSS v3 Score:** **`{cve.get('cvss_v3', 'N/A')} / 10.0`** (Severity: **{cve.get('severity', 'HIGH')}**)\n"
        if cve.get('cwe'):
            res += f"- **Weakness Enumeration:** `{cve.get('cwe')}`\n"
        if cve.get('summary'):
            res += f"- **Technical Summary:** {cve.get('summary')}\n"
        if cve.get('remediation'):
            res += f"- **Remediation Strategy:** {cve.get('remediation')}\n"
        if cve.get('exploit_status'):
            res += f"- **Public Exploit Availability:** ⚠️ *{cve.get('exploit_status')}*\n"
        res += f"- **Source:** {cve.get('source', 'CIRCL.lu Open API')}\n\n"
        return res

    def _format_mitre_attack_results(self, extracted_data: Dict) -> str:
        """Format MITRE ATT&CK Matrix findings."""
        mitre = extracted_data.get('mitre_attack_data', {})
        if not mitre or not isinstance(mitre, dict):
            return "No MITRE ATT&CK records retrieved.\n"
        res = "### 🗺️ MITRE ATT&CK Enterprise Matrix Framework\n"
        res += f"- **Technique:** **{mitre.get('technique_id', 'N/A')} — {mitre.get('technique_name', 'Adversary Technique')}**\n"
        res += f"- **Tactic Phase:** `{mitre.get('tactic', 'Execution')}`\n"
        if mitre.get('description'):
            res += f"- **Adversary Behavior:** {mitre.get('description')}\n"
        if mitre.get('detection_strategy'):
            res += f"- **Detection Analytics:** 🛡️ {mitre.get('detection_strategy')}\n"
        if mitre.get('mitigations'):
            mit_str = '; '.join(mitre.get('mitigations', [])) if isinstance(mitre.get('mitigations'), list) else str(mitre.get('mitigations'))
            res += f"- **Defensive Mitigations:** {mit_str}\n"
        res += f"- **Framework Standard:** {mitre.get('framework', 'MITRE ATT&CK v14')}\n\n"
        return res

    def _format_ml_threat_results(self, extracted_data: Dict) -> str:
        """Format Machine Learning IsolationForest and UEBA analytics."""
        ml = extracted_data.get('ml_threat_data', {})
        if not ml or not isinstance(ml, dict):
            return "No ML threat scoring records retrieved.\n"
        iso = ml.get('isolation_forest', {})
        rf = ml.get('random_forest', {})
        ueba = ml.get('ueba', {})
        res = "### 🧠 Sentinel-AI Enterprise Machine Learning Engine (scikit-learn MCP)\n"
        score = iso.get('anomaly_score', 0)
        is_ano = iso.get('is_anomaly', False)
        status_tag = "🚨 ANOMALOUS BEHAVIOR CONFIRMED" if is_ano or score > 40 else "✅ BENIGN BASELINE"
        res += f"- **IsolationForest Anomaly Status:** **{status_tag}** (Score: `{score}/100`)\n"
        res += f"- **RandomForest Triage Prediction:** Severity **{rf.get('predicted_severity', 'MEDIUM')}** (False Positive Probability: `{rf.get('false_positive_probability', 0.1):.1%}`)\n"
        if iso.get('driving_factors'):
            res += f"- **Driving Anomaly Features:** {', '.join(iso.get('driving_factors', []))}\n"
        if ueba:
            res += f"- **UEBA Behavioral Risk:** `{ueba.get('ueba_risk_score', 10.0)}/100` (User: `{ueba.get('entity_user', 'admin')}`, Host: `{ueba.get('entity_host', 'workstation')}`)\n"
            if ueba.get('anomalous_factors'):
                res += f"- **Behavioral Drift Factors:** {', '.join(ueba.get('anomalous_factors', []))}\n"
        res += f"- **ML Pipeline:** IsolationForest (100 estimators) + RandomForest (120 depth 8 trees) + UEBA Baseline Deviation\n\n"
        return res
