import os
import re
from typing import Any, Dict, List, Optional

from .correlation_engine import build_unified_investigation_result
from .file_analyzer import FileAnalyzer
from .llm_client import LLMClient
from .mcp.registry import create_mcp_client
from .mcp.tool_server import ToolResponse
from .report_generator import generate_report_json, generate_report_html
from .predictive_analytics import PredictiveSecurityEngine


class SecurityCopilotOrchestrator:
    def __init__(self):
        self.llm_client = LLMClient()
        self.mcp_client = create_mcp_client()
        self.file_analyzer = FileAnalyzer()
        self.predictive_engine = PredictiveSecurityEngine()

    def analyze_file_upload(self, filename: str, content_bytes: bytes) -> Dict[str, Any]:
        """
        Processes uploaded files/images:
        1. Analyzes file (extracts SHA256, MD5, IPs, URLs, Log snippet)
        2. Triggers intent-driven investigation using primary indicator or file hash
        3. Generates per-tool reports and unified SOC report
        """
        print(f"\n==================== FILE UPLOAD ANALYSIS ====================")
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
        Modular Intent-Driven Orchestration Flow:
        1. LLM Intent Analysis & Tool Planning via ToolPlanner
        2. Modular Tool Execution (Wazuh, VirusTotal, MISP, Shodan)
        3. Correlation Engine Modular Per-Tool & Unified SOC Report Generation
        4. Natural Language Response Generation
        """
        print(f"\n==================== NEW QUERY ====================")
        print(f"Query: {query}")

        # Step 1: Get intent, query_type, and tool plan from LLM + ToolPlanner
        llm_result = self.llm_client.get_intent_and_tools(query)
        tools = llm_result.get('required_tools', [])
        tool_commands = llm_result.get('tool_commands', {})
        entities = llm_result.get('entities', {})

        print(f"Intent: {llm_result.get('intent')}")
        print(f"Query Type: {llm_result.get('query_type')}")
        print(f"Required Tools: {tools}")
        print(f"Planned Commands: {tool_commands}")

        # Step 2: Handle Direct LLM Questions (No external tool execution needed)
        if not tools:
            print("Direct LLM response (No tool calls required).")

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
                    "shodan_report": None
                },
                "visual_data": {
                    "threat_score": 0,
                    "timeline": [],
                    "attack_graph": []
                }
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

        # Step 3: Execute Planned Tools
        responses: List[ToolResponse] = []
        extracted_data = {
            'source_ip': entities.get('ip'),
            'destination_ip': None,
            'affected_host': None,
            'alerts': [],
            'vt_results': {}
        }

        for tool_name in tools:
            tool_name_lower = tool_name.lower().strip()

            if tool_name_lower == "wazuh":
                print(">>> EXECUTING WAZUH MCP TOOL <<<")
                cmd = tool_commands.get('Wazuh', ['get_alerts'])[0]
                wazuh_response = self.mcp_client.call_tool("Wazuh", cmd)
                responses.append(wazuh_response)

                if wazuh_response.data and wazuh_response.data.get("alerts"):
                    alerts = wazuh_response.data.get("alerts", [])
                    requested_alert = entities.get('alert_id')
                    selected_alert = None
                    if requested_alert:
                        selected_alert = next((a for a in alerts if str(a.get("alert_id") or a.get("id")) == str(requested_alert)), None)
                    if selected_alert is None and alerts:
                        selected_alert = alerts[0]

                    if selected_alert:
                        raw = selected_alert.get("raw", {})
                        extracted_data['source_ip'] = selected_alert.get("source_ip") or raw.get("src_ip") or extracted_data['source_ip']

            elif tool_name_lower == "virustotal":
                print(">>> EXECUTING VIRUSTOTAL MCP TOOL <<<")
                cmd_list = tool_commands.get('VirusTotal', [])
                if cmd_list:
                    cmd = cmd_list[0]
                else:
                    target = extracted_data['source_ip'] or entities.get('ip') or entities.get('hash') or '185.220.101.45'
                    cmd = f"check_ip {target}"

                print(f"Calling VirusTotal MCP: {cmd}")
                vt_response = self.mcp_client.call_tool("VirusTotal", cmd)
                responses.append(vt_response)

                if vt_response.data and vt_response.data.get("result"):
                    extracted_data['vt_results'] = vt_response.data.get("result")

            elif tool_name_lower == "misp":
                print(">>> EXECUTING MISP MCP TOOL <<<")
                target = extracted_data['source_ip'] or entities.get('ip') or entities.get('hash') or '185.220.101.45'
                misp_response = self.mcp_client.call_tool("MISP", f"search {target}")
                responses.append(misp_response)

            elif tool_name_lower == "shodan":
                print(">>> EXECUTING SHODAN MCP TOOL <<<")
                target = extracted_data['source_ip'] or entities.get('ip') or '185.220.101.45'
                shodan_response = self.mcp_client.call_tool("Shodan", f"search {target}")
                responses.append(shodan_response)

            elif tool_name_lower in ["windowslogs", "windows_event"]:
                print(">>> EXECUTING WINDOWS LOGS MCP TOOL <<<")
                cmd_list = tool_commands.get('WindowsLogs', [])
                cmd = cmd_list[0] if cmd_list else "get_security_events"
                print(f"Calling WindowsLogs MCP: {cmd}")
                win_response = self.mcp_client.call_tool("WindowsLogs", cmd)
                responses.append(win_response)

            elif tool_name_lower in ["windowsdefender", "defender"]:
                print(">>> EXECUTING WINDOWS DEFENDER MCP TOOL <<<")
                cmd_list = tool_commands.get('WindowsDefender', [])
                cmd = cmd_list[0] if cmd_list else "get_threats"
                print(f"Calling WindowsDefender MCP: {cmd}")
                def_response = self.mcp_client.call_tool("WindowsDefender", cmd)
                responses.append(def_response)

        # Step 4: Build Modular Tool Reports & Unified SOC Report
        tool_dicts = [response.dict() for response in responses]
        unified = build_unified_investigation_result(tool_dicts)

        # Step 5: Generate Report JSON with per-tool report objects
        report_json = generate_report_json(
            unified,
            alert_id=unified.get('alert_id'),
            timestamp=None,
            attack_type=unified.get('attack_type'),
            recommendations=unified.get('recommendations', [])
        )

        # Inject per-tool reports into report_json for UI rendering
        report_json['tool_reports'] = unified.get('tool_reports', {})
        report_json['virustotal_report'] = unified.get('virustotal_report')
        report_json['wazuh_report'] = unified.get('wazuh_report')
        report_json['misp_report'] = unified.get('misp_report')
        report_json['shodan_report'] = unified.get('shodan_report')

        # Step 6: Generate Predictive Analytics (NEW UNIQUE FEATURE)
        wazuh_alerts = []
        for response in responses:
            if hasattr(response, 'tool_name') and response.tool_name == "Wazuh":
                if response.data and "alerts" in response.data:
                    wazuh_alerts.extend(response.data["alerts"])
        
        predictive_insights = self.predictive_engine.predict_threat_probability({
            "alerts": wazuh_alerts,
            "tool_reports": unified.get('tool_reports', {})
        })

        report_json['predictive_analytics'] = predictive_insights

        report_html = generate_report_html(report_json)
        ai_answer = self.llm_client.generate_response(query, report_json)

        return {
            'llm': llm_result,
            'tool_responses': tool_dicts,
            'unified_investigation': unified,
            'report_json': report_json,
            'report_html': report_html,
            'ai_answer': ai_answer,
            'extracted_data': extracted_data
        }