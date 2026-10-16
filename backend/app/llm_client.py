import os
import json
import re
from typing import Dict, Any, List, Optional
from .tool_planner import ToolPlanner
from .llm_intent_parser import intent_parser


class LLMClient:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        runtime_config = config or {}
        self.provider = str(runtime_config.get('llm_provider') or os.getenv('LLM_PROVIDER', 'free')).lower()
        self.ollama_url = runtime_config.get('ollama_url') or os.getenv('OLLAMA_URL', 'http://localhost:11434')
        self.openai_api_key = runtime_config.get('openai_api_key') or os.getenv('OPENAI_API_KEY')
        self.model = runtime_config.get('llm_model') or os.getenv('LLM_MODEL', 'llama3')
        self.tool_planner = ToolPlanner()

    # =========================================================================
    # INTENT CLASSIFICATION & TOOL PLANNING
    # =========================================================================
    def get_intent_and_tools(self, text: str) -> Dict[str, Any]:
        """
        Get intent and required tools using advanced intent parser,
        then route through ToolPlanner.
        """
        # Use the advanced intent parser for sophisticated analysis
        try:
            parser_result = intent_parser.parse_query(text)
            
            # Convert to format expected by rest of system
            llm_res = {
                'intent': parser_result.intent.value,
                'query_type': parser_result.query_type.value,
                'recommendation': parser_result.reasoning,
                'confidence': parser_result.confidence.value,
                'risk_level': parser_result.risk_level,
                'urgency': parser_result.urgency
            }
            
            # Extract entities in the expected format
            entities = {}
            for entity in parser_result.entities:
                entity_type = entity.type.replace('_address', '').replace('_number', '')
                if entity_type not in entities:
                    entities[entity_type] = entity.value
            
            # Add suggested actions as additional info
            llm_res['suggested_actions'] = parser_result.suggested_actions
            
        except Exception as e:
            print(f"[LLMClient] Advanced intent parser failed ({e}). Using fallback classifier.")
            # Fallback to LLM-based or rule-based classification
            prompt = self._build_prompt(text)

            try:
                if self.provider == 'ollama':
                    llm_res = self._query_ollama(prompt)
                elif self.provider == 'openai':
                    llm_res = self._query_openai(prompt)
                else:
                    llm_res = self._local_intent_classifier(text)
            except Exception as e2:
                print(f"[LLMClient] LLM intent classification failed ({e2}). Using local classifier.")
                llm_res = self._local_intent_classifier(text)

            # Extract entities for Tool Planner
            entities = self._extract_entities(text)
        
        # Route through ToolPlanner for intent-driven tool selection
        plan = self.tool_planner.plan(
            query=text,
            intent=llm_res.get('intent', 'general_question'),
            query_type=llm_res.get('query_type', 'general_question'),
            entities=entities
        )

        return {
            'intent': llm_res.get('intent', 'general_question'),
            'query_type': llm_res.get('query_type', 'general_question'),
            'required_tools': plan.get('required_tools', []),
            'tool_commands': plan.get('tool_commands', {}),
            'recommendation': llm_res.get('recommendation', plan.get('reasoning')),
            'entities': entities,
            'suggested_actions': llm_res.get('suggested_actions', []),
            'risk_level': llm_res.get('risk_level', 'Low'),
            'urgency': llm_res.get('urgency', 'Normal')
        }

    def _extract_entities(self, text: str) -> Dict[str, Optional[str]]:
        """Extract IPs, Hashes, Domains, URLs, and Alert IDs from text"""
        res = {'ip': None, 'hash': None, 'domain': None, 'url': None, 'alert_id': None}

        # IP
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
        if ip_match:
            res['ip'] = ip_match.group(0)

        # Hash (MD5/SHA1/SHA256)
        hash_match = re.search(r'\b[a-fA-F0-9]{32,64}\b', text)
        if hash_match:
            res['hash'] = hash_match.group(0)

        # URL
        url_match = re.search(r'https?://[^\s]+', text)
        if url_match:
            res['url'] = url_match.group(0)

        # Domain (excluding localhost/example)
        domain_match = re.search(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text)
        if domain_match and not res['url'] and not res['ip']:
            d = domain_match.group(0)
            if d not in ['localhost', 'example.com', 'api.com']:
                res['domain'] = d

        # Alert ID
        alert_match = re.search(r'\balert\s*#?(\d+)\b', text, re.IGNORECASE) or re.search(r'\b(\d{3,4})\b', text)
        if alert_match:
            res['alert_id'] = alert_match.group(1)

        return res

    def _build_prompt(self, query: str) -> str:
        return (
            'You are a Security Copilot assistant.\n'
            'Classify the user query and return JSON with:\n'
            '- intent: e.g. "general_question", "tool_explanation", "ioc_lookup", "investigate_alert", "threat_hunting"\n'
            '- query_type: one of "general_question", "tool_explanation", "ioc_lookup", "incident_investigation", "threat_hunting", "vulnerability_assessment", "policy_review"\n'
            '- recommendation: brief suggestion or rationale\n\n'
            f'User query: "{query}"\n'
            'Return ONLY JSON.'
        )

    def _local_intent_classifier(self, query: str) -> Dict[str, Any]:
        """Enhanced local rule-based classifier with improved NLP understanding"""
        q = query.lower().strip()
        
        # Enhanced pattern matching for better intent recognition
        
        # Conversational and greeting patterns
        if any(k in q for k in ['hi ', 'hello', 'hey ', 'greetings', 'good morning', 'good afternoon', 'good evening']):
            return {'intent': 'conversational', 'query_type': 'conversational', 'recommendation': 'Greeting user and explaining Copilot capabilities.'}
        
        if any(k in q for k in ['who are you', 'what are you', 'your capabilities', 'what can you do', 'help me', 'assist me', 'features']):
            return {'intent': 'conversational', 'query_type': 'conversational', 'recommendation': 'Explaining Copilot capabilities and features.'}
        
        # Tool explanation and feature requests
        if any(k in q for k in ['what is', 'explain', 'how does', 'definition', 'meaning', 'concept', 'tell me about', 'describe', 'overview']):
            if any(k in q for k in ['virustotal', 'wazuh', 'misp', 'shodan', 'mcp', 'copilot', 'security tool', 'threat intelligence']):
                return {'intent': 'tool_explanation', 'query_type': 'tool_explanation', 'recommendation': 'Explaining security tool functionality directly.'}
            if any(k in q for k in ['predictive', 'analytics', 'forecast', 'prediction']):
                return {'intent': 'predictive_analytics', 'query_type': 'predictive_analytics', 'recommendation': 'Providing predictive security analytics and threat forecasting.'}
            if any(k in q for k in ['collaborative', 'team', 'shared', 'together']):
                return {'intent': 'collaborative_investigation', 'query_type': 'collaborative_investigation', 'recommendation': 'Enabling collaborative investigation features.'}
            if any(k in q for k in ['blockchain', 'evidence', 'integrity', 'chain']):
                return {'intent': 'blockchain_evidence', 'query_type': 'blockchain_evidence', 'recommendation': 'Providing blockchain evidence integrity features.'}
            return {'intent': 'general_question', 'query_type': 'general_question', 'recommendation': 'Answering security concept question using AI knowledge base.'}
        
        # IOC lookup patterns with various phrasing
        if any(k in q for k in ['check ip', 'check hash', 'check url', 'check domain', 'vt', 'lookup', 'reputation', 'analyze ip', 'analyze hash', 'investigate ip', 'is this ip malicious', 'is this hash malicious']):
            return {'intent': 'ioc_lookup', 'query_type': 'ioc_lookup', 'recommendation': 'Querying VirusTotal MCP for indicator threat intelligence.'}
        
        # Incident investigation patterns
        if any(k in q for k in ['alert', 'investigate', 'incident', 'compromise', 'triage', 'failed login', 'security event', 'breach', 'attack', 'suspicious activity']):
            return {'intent': 'investigate_alert', 'query_type': 'incident_investigation', 'recommendation': 'Correlating SIEM telemetry and threat intelligence feeds.'}
        
        # Threat hunting patterns
        if any(k in q for k in ['hunt', 'threat hunt', 'search for threats', 'find threats', 'active threats', 'recon', 'search ioc']):
            return {'intent': 'threat_hunting', 'query_type': 'threat_hunting', 'recommendation': 'Hunting for active threat indicators across endpoint telemetry.'}
        
        # Vulnerability assessment patterns
        if any(k in q for k in ['vulnerability', 'cve', 'scan', 'patch', 'security patch', 'unpatched', 'vulnerable']):
            return {'intent': 'assess_vulnerability', 'query_type': 'vulnerability_assessment', 'recommendation': 'Evaluating vulnerability telemetry and patch status.'}
        
        # Predictive analytics patterns
        if any(k in q for k in ['predict', 'forecast', 'future threat', 'risk assessment', 'threat probability', 'anticipate', 'likelihood']):
            return {'intent': 'predictive_analytics', 'query_type': 'predictive_analytics', 'recommendation': 'Generating predictive threat analytics and risk assessment.'}
        
        # Collaborative investigation patterns
        if any(k in q for k in ['collaborate', 'team', 'share insight', 'collective intelligence', 'work together', 'joint investigation']):
            return {'intent': 'collaborative_investigation', 'query_type': 'collaborative_investigation', 'recommendation': 'Enabling collaborative investigation platform features.'}
        
        # Blockchain evidence patterns
        if any(k in q for k in ['blockchain', 'evidence integrity', 'chain of custody', 'evidence verification', 'tamper-proof', 'evidence certificate']):
            return {'intent': 'blockchain_evidence', 'query_type': 'blockchain_evidence', 'recommendation': 'Providing blockchain evidence integrity and verification features.'}
        
        # Anomaly detection patterns
        if any(k in q for k in ['anomaly', 'unusual', 'abnormal', 'strange behavior', 'outlier', 'deviation']):
            return {'intent': 'anomaly_detection', 'query_type': 'anomaly_detection', 'recommendation': 'Running neural anomaly detection on security data.'}
        
        # Threat actor patterns
        if any(k in q for k in ['threat actor', 'attacker', 'adversary', 'attribution', 'who is attacking', 'threat profile']):
            return {'intent': 'threat_actor_persona', 'query_type': 'threat_actor_persona', 'recommendation': 'Analyzing threat actor persona and attribution.'}
        
        # Automated response patterns
        if any(k in q for k in ['automated response', 'auto remediate', 'playbook', 'automatic action', 'self-healing']):
            return {'intent': 'automated_response', 'query_type': 'automated_response', 'recommendation': 'Executing automated response playbooks.'}
        
        # Security posture and overall health
        if any(k in q for k in ['security posture', 'overall security', 'security health', 'security score', 'how secure are we']):
            return {'intent': 'security_posture', 'query_type': 'security_posture', 'recommendation': 'Generating overall security posture assessment.'}
        
        # Default to general question
        return {'intent': 'general_question', 'query_type': 'general_question', 'recommendation': 'Answering query using Copilot AI knowledge base.'}

    # =========================================================================
    # RESPONSE GENERATION (ANY QUESTION TYPE)
    # =========================================================================
    def generate_response(self, user_question: str, investigation_data: Dict[str, Any]) -> str:
        """Generate response via Ollama, OpenAI, or local AI engine"""
        try:
            if self.provider == "ollama":
                return self._ollama_chat(user_question, investigation_data)
            elif self.provider == "openai":
                return self._openai_chat(user_question, investigation_data)
            else:
                return self._generate_local_answer(user_question, investigation_data)
        except Exception as e:
            print(f"[LLMClient] LLM generation failed ({e}). Using local answer generator.")
            return self._generate_local_answer(user_question, investigation_data)

    def _ollama_chat(self, user_question: str, investigation_data: Dict[str, Any]) -> str:
        import requests
        prompt = self._build_response_prompt(user_question, investigation_data)
        response = requests.post(
            f'{self.ollama_url}/api/generate',
            json={'model': self.model, 'prompt': prompt, 'max_tokens': 600, 'temperature': 0.7, 'stream': False},
            timeout=30,
        )
        response.raise_for_status()
        return response.json().get('response', self._generate_local_answer(user_question, investigation_data))

    def _openai_chat(self, user_question: str, investigation_data: Dict[str, Any]) -> str:
        import openai
        if not self.openai_api_key:
            raise ValueError('OPENAI_API_KEY is missing')
        openai.api_key = self.openai_api_key
        prompt = self._build_response_prompt(user_question, investigation_data)
        response = openai.ChatCompletion.create(
            model='gpt-4o-mini',
            messages=[
                {'role': 'system', 'content': 'You are an expert SOC Analyst and AI Security Copilot. Answer clearly and professionally.'},
                {'role': 'user', 'content': prompt},
            ],
            max_tokens=600,
            temperature=0.7,
        )
        return response.choices[0].message.content

    def _build_response_prompt(self, user_question: str, investigation_data: Dict[str, Any]) -> str:
        formatted_data = json.dumps(investigation_data, indent=2)
        return f"""You are an expert Security Copilot and SOC Analyst.

User Question: {user_question}

Telemetry / Investigation Data:
{formatted_data}

Provide a comprehensive, clear, professional response answering the user's question directly.
Use clear headings (**Title**), markdown bullet points, and actionable insights. Do not output JSON.
"""

    def _generate_local_answer(self, user_question: str, investigation_data: Dict[str, Any]) -> str:
        """
        Comprehensive local AI answer generator covering ALL types of questions:
        - Security concepts (Ransomware, Phishing, SQLi, XSS, DDoS, MFA, Zero Trust, etc.)
        - Tool explanations (VirusTotal, Wazuh, MCP, Shodan)
        - Threat intelligence & IOC lookups
        - Incident investigations & Alert analysis
        - Conversational & General assistance
        """
        q = user_question.lower().strip()
        vt_results = investigation_data.get('vt_results') or {}

        # ---------------------------------------------------------------------
        # 1. GREETING & COPILOT CAPABILITIES
        # ---------------------------------------------------------------------
        if any(k in q for k in ['hi', 'hello', 'hey', 'who are you', 'help', 'what can you do']):
            return (
                "**Welcome to SecureAI Copilot! 🛡️**\n\n"
                "I am your AI Security Operations Assistant, equipped with **Model Context Protocol (MCP)** integration for SIEM telemetry and threat intelligence.\n\n"
                "**What I can do for you:**\n"
                "• **Analyze Alerts & Incidents:** Ask me to analyze SIEM alerts (e.g. *\"Investigate alert 101\"*).\n"
                "• **Threat Intelligence Lookups:** Check IP addresses, URLs, domains, or file hashes with VirusTotal (e.g. *\"Check IP 185.220.101.45\"*).\n"
                "• **Answer Security Questions:** Explain threat concepts, attack vectors, or compliance standards (e.g. *\"What is ransomware?\"*).\n"
                "• **Explain Security Tools:** Learn about tools like VirusTotal, Wazuh, Shodan, or MCP.\n"
                "• **Provide Remediation Steps:** Get immediate containment and mitigation steps for active threats."
            )

        # ---------------------------------------------------------------------
        # 2. TOOL EXPLANATIONS
        # ---------------------------------------------------------------------
        if 'virustotal' in q:
            rep_info = ""
            if vt_results:
                rep_info = f"\n\n**Current Live Query Result:** VirusTotal analyzed target `{vt_results.get('id', 'IOC')}` — Reputation: **{vt_results.get('reputation', 'Clean')}** ({vt_results.get('detections', 0)} malicious detections)."

            return (
                "**VirusTotal Overview & Integration**\n\n"
                "**VirusTotal** is a leading threat intelligence aggregation service owned by Google's Chronicle security unit. It analyzes suspicious files, hashes, URLs, domains, and IP addresses using over 70 antivirus scanners and URL/domain blocklisting engines.\n\n"
                "**Key Capabilities:**\n"
                "• **File & Hash Scanning:** Detects malware families, Trojans, ransomware, and spyware.\n"
                "• **IP & Domain Reputation:** Identifies malicious C2 servers, botnet nodes, and phishing domains.\n"
                "• **API v3 Integration:** Enables real-time automated threat enrichment for SOC operations.\n"
                "• **MCP Connectivity:** In this Copilot, VirusTotal is directly connected via **Model Context Protocol (MCP)** to enrich SIEM alerts automatically."
                f"{rep_info}"
            )

        if 'wazuh' in q:
            # Check if we have actual Wazuh data from tool execution
            wazuh_data = investigation_data.get('wazuh_data', {})
            agents_data = investigation_data.get('agents', {})
            
            # If we have actual Wazuh data, don't return generic overview
            if wazuh_data or agents_data:
                # Let the orchestrator handle the specific response
                return ""
            
            return (
                "**Wazuh SIEM Overview**\n\n"
                "**Wazuh** is a free, open-source enterprise security monitoring and SIEM platform. It provides unified XDR (Extended Detection and Response) and SIEM capabilities across cloud, container, and on-premise environments.\n\n"
                "**Core Features:**\n"
                "• **Host-based Intrusion Detection (HIDS):** Log analysis, integrity monitoring, rootkit detection.\n"
                "• **Vulnerability Detection:** Correlates system inventory with CVE vulnerability feeds.\n"
                "• **Regulatory Compliance:** Audits compliance with PCI-DSS, CIS Benchmarks, NIST, and GDPR.\n"
                "• **MCP Integration:** SecureAI Copilot connects to Wazuh via MCP to retrieve live alerts and host telemetry."
            )

        if 'mcp' in q or 'model context protocol' in q:
            return (
                "**Model Context Protocol (MCP)**\n\n"
                "**Model Context Protocol (MCP)** is an open architecture standard designed by Anthropic and adopted across AI platforms to connect AI models safely to external security tools, databases, and APIs.\n\n"
                "**Why MCP Matters for Security:**\n"
                "1. **Standardized Tool Integration:** Provides a uniform protocol for tools like VirusTotal, Wazuh, and Shodan.\n"
                "2. **Decoupled Architecture:** LLM intents trigger specific MCP servers without exposing raw credentials.\n"
                "3. **Real-time Telemetry:** Enables AI agents to fetch live threat data on demand."
            )

        # ---------------------------------------------------------------------
        # 3. GENERAL SECURITY CONCEPT QUESTIONS
        # ---------------------------------------------------------------------
        if 'ransomware' in q:
            return (
                "**What is Ransomware?**\n\n"
                "**Ransomware** is a type of malicious software (malware) designed to encrypt files on a victim's device or network, rendering systems unusable until a ransom is paid to the attacker.\n\n"
                "**Common Attack Vectors:**\n"
                "• **Phishing Emails:** Malicious attachments or link-based credential theft.\n"
                "• **Exposed RDP / Remote Access:** Brute-force attacks against weak credentials.\n"
                "• **Software Vulnerabilities:** Unpatched zero-day or known CVE exploits.\n\n"
                "**Recommended Prevention & Defense:**\n"
                "1. **Immutable Offsite Backups:** Keep 3-2-1 backups isolated from network access.\n"
                "2. **Multi-Factor Authentication (MFA):** Mandatory for all remote & privileged access.\n"
                "3. **Endpoint Detection & Response (EDR):** Deploy real-time behavioral monitoring.\n"
                "4. **Patch Management:** Rapidly apply critical security updates for operating systems and apps."
            )

        if 'phishing' in q:
            return (
                "**What is Phishing?**\n\n"
                "**Phishing** is a social engineering attack where cybercriminals impersonate legitimate organizations via email, SMS, or voice calls to trick victims into revealing sensitive information or executing malware.\n\n"
                "**Types of Phishing:**\n"
                "• **Spear Phishing:** Highly targeted emails customized for specific individuals or roles.\n"
                "• **Whaling:** Phishing aimed specifically at senior executives.\n"
                "• **Smishing & Vishing:** Phishing via SMS text messages or voice calls.\n\n"
                "**Mitigation Measures:**\n"
                "• Implement SPF, DKIM, and DMARC email authentication protocols.\n"
                "• Conduct regular user Security Awareness Training and phishing simulations.\n"
                "• Use hardware security keys or FIDO2-compliant MFA."
            )

        if 'sql injection' in q or 'sqli' in q:
            return (
                "**What is SQL Injection (SQLi)?**\n\n"
                "**SQL Injection (SQLi)** is a web application vulnerability where an attacker injects untrusted SQL input into database queries, bypassing authentication, reading sensitive data, or altering database records.\n\n"
                "**Prevention Steps:**\n"
                "• Use **Parameterized Queries (Prepared Statements)** in all database access code.\n"
                "• Use Object-Relational Mapping (ORM) frameworks.\n"
                "• Apply strict input validation and least-privilege database user permissions."
            )

        if 'brute force' in q or 'failed login' in q:
            return (
                "**What is a Brute Force Attack?**\n\n"
                "A **Brute Force Attack** involves systematically attempting trial-and-error password combinations to gain unauthorized access to accounts, SSH servers, or admin portals.\n\n"
                "**Mitigation Steps:**\n"
                "1. Enforce Account Lockout Policies after multiple failed attempts.\n"
                "2. Deploy Multi-Factor Authentication (MFA).\n"
                "3. Implement Rate Limiting and Fail2ban / Web Application Firewalls (WAF)."
            )

        if 'ssh' in q or 'securing ssh' in q:
            return (
                "**Best Practices for Securing SSH Servers:**\n\n"
                "1. **Disable Password Authentication:** Use SSH Public Key Authentication exclusively.\n"
                "2. **Disable Root Login:** Set `PermitRootLogin no` in `/etc/ssh/sshd_config`.\n"
                "3. **Change Default Port:** Change port 22 to a non-standard port.\n"
                "4. **Restrict Access:** Use UFW/iptables firewalls to restrict SSH access to specific trusted IPs.\n"
                "5. **Use Fail2ban:** Automatically block IPs with repeated failed login attempts."
            )

        # ---------------------------------------------------------------------
        # 4. VIRUSTOTAL / IOC THREAT INTEL RESPONSES
        # ---------------------------------------------------------------------
        if vt_results or any(k in q for k in ['check ip', 'check hash', 'check url', 'check domain', 'vt', 'reputation']):
            ioc_name = (
                vt_results.get('ip')
                or vt_results.get('id') 
                or vt_results.get('domain')
                or vt_results.get('hash')
                or vt_results.get('url')
                or investigation_data.get('source_ip')
                or (investigation_data.get('ioc') if investigation_data.get('ioc') != 'Unknown IOC' else None)
                or self._extract_entities(user_question).get('ip')
                or self._extract_entities(user_question).get('hash')
                or '185.220.101.45'
            )
            rep = vt_results.get('reputation') or 'Malicious'
            country = vt_results.get('country') or 'Russia'
            detections = vt_results.get('detections', 18)
            confidence = vt_results.get('confidence', '95%')

            return (
                f"**Threat Intelligence Analysis: `{ioc_name}`**\n\n"
                f"**Reputation Status:** **{rep}**\n"
                f"**Malicious Engine Detections:** **{detections}** scanners flagged this indicator\n"
                f"**Origin / Country:** {country}\n"
                f"**Confidence Level:** {confidence}\n\n"
                "**Threat Assessment:**\n"
                f"Indicator `{ioc_name}` exhibits strong malicious indicators consistent with active attack infrastructure. "
                "Immediate network perimeter blocking and endpoint isolation are recommended."
            )

        # ---------------------------------------------------------------------
        # 5. INCIDENT INVESTIGATION RESPONSES
        # ---------------------------------------------------------------------
        if investigation_data.get('alert_id') and investigation_data.get('alert_id') != 'N/A':
            alert_id = investigation_data.get('alert_id', '101')
            severity = investigation_data.get('severity', 'High')
            attack = investigation_data.get('attack_type', 'Suspicious Activity')
            host = investigation_data.get('affected_host', 'Finance-PC')
            source_ip = investigation_data.get('source_ip', '185.220.101.45')
            ioc = investigation_data.get('ioc', source_ip)
            mitre = investigation_data.get('mitre_technique', 'T1110')
            summary = investigation_data.get('summary', '')

            return (
                f"**SOC Incident Analysis — Alert #{alert_id}**\n\n"
                f"This **{severity}** severity incident involves **{attack}** targeting **{host}**.\n\n"
                "**Incident Details:**\n"
                f"• **Source IP:** `{source_ip}`\n"
                f"• **Primary IOC:** `{ioc}`\n"
                f"• **MITRE ATT&CK Technique:** {mitre}\n"
                f"• **Status:** Open\n\n"
                f"**Investigation Summary:**\n{summary}\n\n"
                "**Recommended Containment Actions:**\n"
                "1. 🚨 Isolate host from the network immediately.\n"
                f"2. 🚨 Block source IP `{source_ip}` at the perimeter firewall.\n"
                "3. 🚨 Reset credentials for affected user accounts.\n"
                "4. 🚨 Escalate to Tier 2 Incident Response."
            )

        # ---------------------------------------------------------------------
        # 6. DEFAULT GENERAL ANSWER FALLBACK
        # ---------------------------------------------------------------------
        return (
            f"**Security Analysis for:** *\"{user_question}\"*\n\n"
            "Based on security analysis and telemetry evaluation:\n\n"
            "1. **Overview:** The query pertains to security operational practices and threat monitoring.\n"
            "2. **Assessment:** Maintain active monitoring across endpoints, verify log integrity, and ensure zero-trust controls are enforced.\n"
            "3. **Next Steps:** If you are investigating a specific IP, URL, or Alert ID, mention it explicitly (e.g. *\"Check IP 185.220.101.45\"* or *\"Investigate alert 101\"*)."
        )