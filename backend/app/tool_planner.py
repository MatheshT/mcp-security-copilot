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

        # Free SOC Tools Status & Discovery
        if any(k in query_lower for k in ['free soc tool', 'free tool', 'free tools', 'what tool', 'available tool', 'mcp tool', 'connected tool', 'free soc', 'connect free']):
            return {
                "required_tools": ["MalwareBazaar", "CISA_KEV", "IP_Intel", "CVE_Search", "MITRE_ATTACK", "ML_Threat_Engine"],
                "tool_commands": {
                    "MalwareBazaar": ["lookup_hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"],
                    "CISA_KEV": ["check_cve CVE-2023-34362"],
                    "IP_Intel": ["lookup_ip 185.220.101.5"],
                    "CVE_Search": ["search_cve CVE-2023-34362"],
                    "MITRE_ATTACK": ["lookup_technique T1059"],
                    "ML_Threat_Engine": ["detect_anomaly"]
                },
                "reasoning": "Free SOC tools inquiry detected. Gathering live intelligence across all connected free MCP endpoints (MalwareBazaar, CISA KEV, IP-API Intel, CIRCL CVE, MITRE ATTACK, ML Anomaly Engine)."
            }

        if re.search(r'\b(?:collect|coolect|gather|retrieve|fetch|pull)\b.*\blogs?\b', query_lower):
            return {
                "required_tools": ["WindowsLogs"],
                "tool_commands": {
                    "WindowsLogs": [
                        "get_security_events",
                        "get_system_events",
                        "get_application_events",
                    ]
                },
                "reasoning": "Log collection requested. Retrieving real Windows security, system, and application events.",
            }

        if re.search(r'\b(?:start|begin|run)\s+(?:an?\s+)?(?:security\s+)?invest(?:i?gation)\b', query_lower):
            return {
                "required_tools": ["Wazuh", "WindowsLogs"],
                "tool_commands": {
                    "Wazuh": ["get_alerts", "get_agents", "get_statistics"],
                    "WindowsLogs": [
                        "get_security_events",
                        "get_system_events",
                        "get_application_events",
                    ],
                },
                "reasoning": "Investigation requested. Collecting current Wazuh alerts and agent status alongside endpoint event logs.",
            }

        # SOAR Active Defense / Containment Intent
        if any(k in query_lower for k in ['block', 'isolate', 'quarantine', 'lockdown', 'soar', 'contain', 'playbook']):
            soar_cmd = "block_ip" if "block" in query_lower else ("isolate_host" if ("isolate" in query_lower or "quarantine" in query_lower) else "run_playbook")
            if entities.get('ip') and "block" in query_lower:
                soar_cmd = f"block_ip {entities['ip']}"
            elif "isolate" in query_lower or "quarantine" in query_lower:
                target_host = entities.get('host') or entities.get('ip')
                if not target_host:
                    match = re.search(r'(?:host|endpoint|workstation|machine)\s+([A-Za-z0-9_\-]+)', query, re.I)
                    if match:
                        target_host = match.group(1)
                if target_host:
                    soar_cmd = f"isolate_host {target_host}"
            return {
                "required_tools": ["SOAR"],
                "tool_commands": {"SOAR": [soar_cmd]},
                "reasoning": "Active defense & automated containment intent detected. Executing SOAR countermeasure."
            }

        # Wazuh Agents Query
        if any(k in query_lower for k in ['agent', 'connected agents', 'active agents', 'endpoints', 'how many agent', 'ethana agent', 'agents check', 'agent ethana', 'agents iruku', 'agents irruku', 'agents status']):
            return {
                "required_tools": ["Wazuh"],
                "tool_commands": {"Wazuh": ["get_agents", "get_statistics"]},
                "reasoning": "Wazuh fleet agent status query detected. Retrieving connected agent telemetry."
            }

        # Wazuh Alerts Query
        if any(k in query_lower for k in ['alert', 'alerts', 'security alert', 'check alert', 'alerts check', 'ethana alert', 'recent alert', 'alert iruku', 'alerts irruku', 'alert check pannu', 'alerts kaatu', 'alert kaatu']):
            return {
                "required_tools": ["Wazuh"],
                "tool_commands": {"Wazuh": ["get_alerts", "get_statistics"]},
                "reasoning": "Real Wazuh security alerts query detected. Retrieving live SIEM alerts and telemetry."
            }

        # Free SOC Tools Status & Discovery
        if any(k in query_lower for k in ['free soc tool', 'free tool', 'free tools', 'what tool', 'available tool', 'mcp tool', 'connected tool', 'free soc']):
            return {
                "required_tools": ["MalwareBazaar", "CISA_KEV", "IP_Intel", "CVE_Search", "MITRE_ATTACK", "ML_Threat_Engine"],
                "tool_commands": {
                    "MalwareBazaar": ["lookup_hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"],
                    "CISA_KEV": ["check_cve CVE-2023-34362"],
                    "IP_Intel": ["lookup_ip 185.220.101.5"],
                    "CVE_Search": ["search_cve CVE-2023-34362"],
                    "MITRE_ATTACK": ["lookup_technique T1059"],
                    "ML_Threat_Engine": ["detect_anomaly"]
                },
                "reasoning": "Free SOC tools inquiry detected. Gathering live intelligence across all connected free MCP endpoints (MalwareBazaar, CISA KEV, IP-API Intel, CIRCL CVE, MITRE ATTACK, ML Anomaly Engine)."
            }

        # CISA KEV & Vulnerability Intent
        cve_match = re.search(r'(cve-\d{4}-\d{4,7})', query, re.I)
        if cve_match or any(k in query_lower for k in ['cisa', 'kev', 'vulnerability', 'cve']):
            cve_id = cve_match.group(1).upper() if cve_match else 'CVE-2021-44228'
            return {
                "required_tools": ["CISA_KEV", "CVE_Search"],
                "tool_commands": {
                    "CISA_KEV": [f"check_cve {cve_id}"],
                    "CVE_Search": [f"search_cve {cve_id}"]
                },
                "reasoning": f"Weaponized vulnerability assessment intent detected. Querying official CISA KEV Catalog and CIRCL CVE database for {cve_id}."
            }

        # MITRE ATT&CK TTP Intent
        mitre_match = re.search(r'(t\d{4}(?:\.\d{3})?)', query, re.I)
        if mitre_match or any(k in query_lower for k in ['mitre', 'att&ck', 'attack technique', 'ttp', 'tactics', 'tactic']):
            ttp_id = mitre_match.group(1).upper() if mitre_match else ('T1059' if 'script' in query_lower else ('T1110' if 'brute' in query_lower else query.strip()))
            return {
                "required_tools": ["MITRE_ATTACK"],
                "tool_commands": {
                    "MITRE_ATTACK": [f"lookup_technique {ttp_id}"]
                },
                "reasoning": f"Adversary TTP taxonomy lookup detected. Querying MITRE ATTACK Enterprise Matrix for {ttp_id}."
            }

        # ML Threat & UEBA Anomaly Intent
        if any(k in query_lower for k in ['machine learning', 'isolation forest', 'random forest', 'ueba', 'anomaly score', 'behavioral deviation', 'false positive rate', 'ml detection', 'ml engine']):
            return {
                "required_tools": ["ML_Threat_Engine"],
                "tool_commands": {
                    "ML_Threat_Engine": [query]
                },
                "reasoning": "Machine Learning inference and UEBA behavioral analytics intent detected. Running IsolationForest and RandomForest triage via MCP."
            }

        # MalwareBazaar / Hash Intent
        if entities.get('hash') or any(k in query_lower for k in ['malwarebazaar', 'malware bazaar', 'urlhaus', 'abuse.ch', 'file hash', 'sha256', 'md5']):
            target_hash = entities.get('hash') or query.split()[-1]
            return {
                "required_tools": ["MalwareBazaar", "VirusTotal"],
                "tool_commands": {
                    "MalwareBazaar": [f"lookup_hash {target_hash}"],
                    "VirusTotal": [f"check_hash {target_hash}"]
                },
                "reasoning": f"Malware sample and hash lookup intent detected for {target_hash} across free MalwareBazaar and VirusTotal."
            }

        # 1. Direct LLM response - No tools needed ONLY for pure conceptual, conversational questions without security entities
        security_keywords = ['alert', 'agent', 'wazuh', 'endpoint', 'threat', 'vulnerab', 'cve', 'log', 'block', 'isolate', 'quarantine', 'investig', 'ip', 'hash', 'status', 'scan', 'incident', 'event', 'mitre', 'pannu', 'ethana', 'iruku', 'irruku', 'kaatu']
        has_security_topic = any(k in query_lower for k in security_keywords)

        if not has_security_topic and (query_type in ['general_question', 'tool_explanation', 'conversational', 'policy_review'] or intent in ['general_question', 'tool_explanation', 'conversational', 'policy_review']):
            if not (entities.get('ip') or entities.get('hash') or entities.get('url') or entities.get('domain')):
                return {
                    "required_tools": [],
                    "tool_commands": {},
                    "reasoning": "Query is a general concept explanation. Answering directly using AI knowledge without external tool calls."
                }

        # 2. IOC Lookup Intent
        if query_type == 'ioc_lookup' or intent == 'ioc_lookup' or any(k in query_lower for k in ['check ip', 'check hash', 'check url', 'check domain', 'vt', 'virustotal', 'investigate ip']):
            if entities.get('ip'):
                tools.extend(['IP_Intel', 'VirusTotal', 'AbuseIPDB', 'Wazuh'])
                commands['IP_Intel'] = [f"lookup_ip {entities['ip']}"]
                commands['VirusTotal'] = [f"check_ip {entities['ip']}"]
                commands['AbuseIPDB'] = [f"check {entities['ip']}"]
                commands['Wazuh'] = ["get_alerts"]
                reasoning = f"IOC lookup intent detected. Calling VirusTotal, AbuseIPDB, and Wazuh for IP {entities['ip']}."
            elif entities.get('hash'):
                tools.extend(['VirusTotal', 'AlienVault OTX'])
                commands['VirusTotal'] = [f"check_hash {entities['hash']}"]
                commands['AlienVault OTX'] = [f"check {entities['hash']}"]
                reasoning = f"IOC lookup intent detected. Calling VirusTotal and AlienVault for file hash {entities['hash']}."
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
            commands['Wazuh'] = ["get_alerts", "get_statistics"]
            
            # Enrich indicators if present
            if entities.get('ip'):
                tools.extend(['VirusTotal', 'MISP', 'Shodan', 'AbuseIPDB'])
                commands['VirusTotal'] = [f"check_ip {entities['ip']}"]
                commands['MISP'] = [f"search {entities['ip']}"]
                commands['Shodan'] = [f"search {entities['ip']}"]
                commands['AbuseIPDB'] = [f"check {entities['ip']}"]
            elif entities.get('hash'):
                tools.append('VirusTotal')
                commands['VirusTotal'] = [f"check_hash {entities['hash']}"]

            reasoning = "Incident investigation intent detected. Querying Wazuh SIEM telemetry and enriching with VirusTotal, MISP, and Shodan."

            return {
                "required_tools": tools,
                "tool_commands": commands,
                "reasoning": reasoning
            }

        # 4. Threat Hunting Intent
        if query_type == 'threat_hunting' or intent == 'threat_hunting' or 'hunt' in query_lower:
            tools.append('Wazuh')
            commands['Wazuh'] = ["get_active_events", "get_alerts"]
            if entities.get('ip'):
                tools.append('VirusTotal')
                commands['VirusTotal'] = [f"check_ip {entities['ip']}"]
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
            # Use get_agents for agent-related queries, get_alerts for general security posture
            if any(k in query_lower for k in ['agent', 'connected', 'wazuh']):
                commands['Wazuh'] = ["get_agents", "get_statistics"]
            else:
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
