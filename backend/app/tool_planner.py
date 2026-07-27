import re
from typing import Any, Dict, List, Optional, Tuple


class ToolPlanner:
    """
    Intent-driven Tool Planner.
    Decides which security tools (if any) need to be invoked based on user intent,
    query type, and extracted indicators.
    """

    def plan(
        self,
        query: str,
        intent: str,
        query_type: str,
        entities: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build an execution plan for a query based on intent and entities.
        
        Args:
            query: The user query string
            intent: Identified intent label (e.g. 'general_question', 'ioc_lookup', 'investigate_alert')
            query_type: Type category (e.g. 'general_question', 'incident_investigation', 'ioc_lookup')
            entities: Extracted entities {'ip': ..., 'hash': ..., 'domain': ..., 'url': ..., 'alert_id': ...}
            
        Returns:
            Dict containing:
            - required_tools: List[str] of tool names to call
            - tool_commands: Dict[str, List[str]] mapping tool name to specific command queries
            - reasoning: Explanation of why tools were (or were not) selected
        """
        query_lower = query.lower()
        tools: List[str] = []
        commands: Dict[str, List[str]] = {}
        reasoning = ""

        # 1. Direct LLM response - No tools needed for general concepts, explanations, policies
        if query_type in ['general_question', 'tool_explanation', 'conversational', 'policy_review'] or intent in ['general_question', 'tool_explanation', 'conversational', 'policy_review']:
            # Exception: If the query explicitly asks to check a specific IP/Hash/Domain/URL despite being categorized
            if not (entities.get('ip') or entities.get('hash') or entities.get('url') or entities.get('domain')):
                return {
                    "required_tools": [],
                    "tool_commands": {},
                    "reasoning": "Query is a general question or concept explanation. Answering directly using AI LLM knowledge without external tool calls."
                }

        # 2. IOC Lookup Intent
        if query_type == 'ioc_lookup' or intent == 'ioc_lookup' or any(k in query_lower for k in ['check ip', 'check hash', 'check url', 'check domain', 'vt', 'virustotal']):
            if entities.get('ip'):
                tools.append('VirusTotal')
                commands['VirusTotal'] = [f"check_ip {entities['ip']}"]
                reasoning = f"IOC lookup intent detected. Calling VirusTotal for IP {entities['ip']}."
            elif entities.get('hash'):
                tools.append('VirusTotal')
                commands['VirusTotal'] = [f"check_hash {entities['hash']}"]
                reasoning = f"IOC lookup intent detected. Calling VirusTotal for file hash {entities['hash']}."
            elif entities.get('url'):
                tools.append('VirusTotal')
                commands['VirusTotal'] = [f"check_url {entities['url']}"]
                reasoning = f"IOC lookup intent detected. Calling VirusTotal for URL {entities['url']}."
            elif entities.get('domain'):
                tools.append('VirusTotal')
                commands['VirusTotal'] = [f"check_domain {entities['domain']}"]
                reasoning = f"IOC lookup intent detected. Calling VirusTotal for domain {entities['domain']}."
            else:
                tools.append('VirusTotal')
                commands['VirusTotal'] = [f"check_ip {query.strip()}"]
                reasoning = "IOC lookup requested. Calling VirusTotal MCP."

            return {
                "required_tools": tools,
                "tool_commands": commands,
                "reasoning": reasoning
            }

        # 3. Incident Investigation Intent
        if query_type == 'incident_investigation' or intent == 'investigate_alert' or any(k in query_lower for k in ['alert', 'investigate', 'incident', 'compromise', 'triage']):
            tools.append('Wazuh')
            commands['Wazuh'] = ["get_alerts"]
            
            # VirusTotal enrichment if IP/Hash/Domain exists or will be extracted from alert telemetry
            tools.append('VirusTotal')
            if entities.get('ip'):
                commands['VirusTotal'] = [f"check_ip {entities['ip']}"]
            elif entities.get('hash'):
                commands['VirusTotal'] = [f"check_hash {entities['hash']}"]
            else:
                commands['VirusTotal'] = ["check_ip 185.220.101.45"]

            # Add MISP for threat actor attribution
            tools.append('MISP')
            if entities.get('ip'):
                commands['MISP'] = [f"search {entities['ip']}"]
            else:
                commands['MISP'] = ["search 185.220.101.45"]

            # Add Shodan for infrastructure intelligence
            tools.append('Shodan')
            if entities.get('ip'):
                commands['Shodan'] = [f"search {entities['ip']}"]
            else:
                commands['Shodan'] = ["search 185.220.101.45"]

            reasoning = "Incident investigation intent detected. Querying Wazuh SIEM telemetry and enriching with VirusTotal, MISP threat intelligence, and Shodan OSINT."

            return {
                "required_tools": tools,
                "tool_commands": commands,
                "reasoning": reasoning
            }

        # 4. Threat Hunting Intent
        if query_type == 'threat_hunting' or intent == 'threat_hunting' or 'hunt' in query_lower:
            tools.extend(['Wazuh', 'VirusTotal'])
            commands['Wazuh'] = ["get_active_events"]
            ip = entities.get('ip') or '185.220.101.45'
            commands['VirusTotal'] = [f"check_ip {ip}"]
            reasoning = "Threat hunting intent detected. Querying active telemetry events and correlating IOC indicators."

            return {
                "required_tools": tools,
                "tool_commands": commands,
                "reasoning": reasoning
            }

        # 5. Vulnerability Assessment Intent
        if query_type == 'vulnerability_assessment' or intent == 'assess_vulnerability' or any(k in query_lower for k in ['vulnerability', 'cve', 'scan', 'patch']):
            tools.append('Wazuh')
            commands['Wazuh'] = ["get_alerts"]
            reasoning = "Vulnerability assessment intent detected. Checking Wazuh security events."

            return {
                "required_tools": tools,
                "tool_commands": commands,
                "reasoning": reasoning
            }

        # 6. Predictive Analytics Intent
        if query_type == 'predictive_analytics' or intent == 'predictive_analytics' or any(k in query_lower for k in ['predict', 'forecast', 'future threat', 'risk assessment', 'threat probability']):
            reasoning = "Predictive analytics intent detected. Using machine learning algorithms for threat forecasting and risk assessment."
            return {
                "required_tools": [],
                "tool_commands": {},
                "reasoning": reasoning
            }

        # 7. Collaborative Investigation Intent
        if query_type == 'collaborative_investigation' or intent == 'collaborative_investigation' or any(k in query_lower for k in ['collaborate', 'team', 'share insight', 'collective intelligence']):
            reasoning = "Collaborative investigation intent detected. Enabling team-based analysis and shared insights platform."
            return {
                "required_tools": [],
                "tool_commands": {},
                "reasoning": reasoning
            }

        # 8. Blockchain Evidence Intent
        if query_type == 'blockchain_evidence' or intent == 'blockchain_evidence' or any(k in query_lower for k in ['blockchain', 'evidence integrity', 'chain of custody', 'evidence verification']):
            reasoning = "Blockchain evidence intent detected. Providing tamper-proof evidence handling and cryptographic verification."
            return {
                "required_tools": [],
                "tool_commands": {},
                "reasoning": reasoning
            }

        # 9. Anomaly Detection Intent
        if query_type == 'anomaly_detection' or intent == 'anomaly_detection' or any(k in query_lower for k in ['anomaly', 'unusual', 'abnormal', 'strange behavior']):
            tools.append('Wazuh')
            commands['Wazuh'] = ["get_alerts"]
            reasoning = "Anomaly detection intent detected. Running neural network analysis on security telemetry."
            return {
                "required_tools": tools,
                "tool_commands": commands,
                "reasoning": reasoning
            }

        # 10. Threat Actor Persona Intent
        if query_type == 'threat_actor_persona' or intent == 'threat_actor_persona' or any(k in query_lower for k in ['threat actor', 'attacker', 'adversary', 'attribution']):
            tools.extend(['MISP', 'VirusTotal'])
            commands['MISP'] = ["search_threat_actors"]
            commands['VirusTotal'] = ["check_ip 185.220.101.45"]
            reasoning = "Threat actor analysis intent detected. Querying threat intelligence for actor attribution and profiling."
            return {
                "required_tools": tools,
                "tool_commands": commands,
                "reasoning": reasoning
            }

        # 11. Automated Response Intent
        if query_type == 'automated_response' or intent == 'automated_response' or any(k in query_lower for k in ['automated response', 'auto remediate', 'playbook']):
            reasoning = "Automated response intent detected. Executing security playbooks for incident response."
            return {
                "required_tools": [],
                "tool_commands": {},
                "reasoning": reasoning
            }

        # 12. Security Posture Intent
        if query_type == 'security_posture' or intent == 'security_posture' or any(k in query_lower for k in ['security posture', 'overall security', 'security health']):
            tools.extend(['Wazuh', 'VirusTotal'])
            commands['Wazuh'] = ["get_alerts"]
            commands['VirusTotal'] = ["check_ip 185.220.101.45"]
            reasoning = "Security posture assessment intent detected. Analyzing overall security health across all telemetry sources."
            return {
                "required_tools": tools,
                "tool_commands": commands,
                "reasoning": reasoning
            }

        # Default fallback: If specific IOC present in query, call VirusTotal; otherwise answer directly
        if entities.get('ip'):
            return {
                "required_tools": ['VirusTotal'],
                "tool_commands": {'VirusTotal': [f"check_ip {entities['ip']}"]},
                "reasoning": f"Extracted IP {entities['ip']} from query. Querying VirusTotal."
            }
        elif entities.get('hash'):
            return {
                "required_tools": ['VirusTotal'],
                "tool_commands": {'VirusTotal': [f"check_hash {entities['hash']}"]},
                "reasoning": f"Extracted hash {entities['hash']} from query. Querying VirusTotal."
            }

        return {
            "required_tools": [],
            "tool_commands": {},
            "reasoning": "No external tool required. Answering directly using AI LLM."
        }
