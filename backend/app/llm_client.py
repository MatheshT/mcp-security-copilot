import os
import json
import re
from typing import Dict, Any, List, Optional


class LLMClient:
    def __init__(self):
        self.provider = os.getenv('LLM_PROVIDER', 'free').lower()
        self.ollama_url = os.getenv('OLLAMA_URL', 'http://localhost:11434')
        self.openai_api_key = os.getenv('OPENAI_API_KEY')
        self.model = os.getenv('LLM_MODEL', 'llama3')

    def get_intent_and_tools(self, text: str) -> Dict[str, Any]:
        """
        Get intent and required tools from the LLM based on user query.
        Falls back to local logic if LLM is unavailable.
        """
        prompt = self._build_prompt(text)

        try:
            if self.provider == 'ollama':
                return self._query_ollama(prompt)
            elif self.provider == 'openai':
                return self._query_openai(prompt)
            else:
                # Default to local fallback
                return self._local_fallback(text)
        except Exception as e:
            print(f"LLM query failed: {e}")
            return self._local_fallback(text)

    def _build_prompt(self, query: str) -> str:
        """Build the prompt for the LLM"""
        return (
            'You are a security copilot assistant.\n'
            'Analyze the user investigation query and return a JSON object with these fields:\n'
            '- intent: a short user intent label (e.g., "investigate_alert", "threat_hunting", "assess_vulnerability", "policy_review", "general_security_question")\n'
            '- query_type: one of incident_investigation, threat_hunting, vulnerability_assessment, policy_review, other\n'
            '- required_tools: an array of security tools needed to investigate or enrich the query\n'
            '- recommendation: a brief next step recommendation\n'
            '\n'
            f'User query: "{query}"\n'
            '\n'
            'Return only valid JSON without extra text.'
        )

    def _local_fallback(self, query: str) -> Dict[str, Any]:
        """Local fallback logic when LLM is unavailable"""
        lower = query.lower()
        tools: List[str] = []
        intent = 'unknown'
        query_type = 'other'
        recommendation = 'Review the query and collect more context from incident telemetry.'

        if any(keyword in lower for keyword in ['alert', 'investigate', 'incident', 'triage', 'compromise']):
            intent = 'investigate_alert'
            query_type = 'incident_investigation'
            tools = ['Wazuh', 'VirusTotal']
            recommendation = 'Check alert details, endpoint telemetry, and threat intelligence feeds.'
        elif any(keyword in lower for keyword in ['hunt', 'ioc', 'recon', 'search']):
            intent = 'threat_hunting'
            query_type = 'threat_hunting'
            tools = ['Wazuh', 'VirusTotal']
            recommendation = 'Correlate telemetry across endpoints and enrich indicators.'
        elif any(keyword in lower for keyword in ['vulnerability', 'scan', 'patch', 'cve']):
            intent = 'assess_vulnerability'
            query_type = 'vulnerability_assessment'
            tools = ['Wazuh', 'VirusTotal']
            recommendation = 'Review affected hosts and schedule remediation for exposed services.'
        elif any(keyword in lower for keyword in ['policy', 'compliance', 'audit', 'control']):
            intent = 'policy_review'
            query_type = 'policy_review'
            tools = ['Wazuh']
            recommendation = 'Validate the control framework and escalate gaps to compliance owners.'
        else:
            tools = ['Wazuh']
            intent = 'general_security_question'
            recommendation = 'Gather more context and expand the query for a clearer response.'

        return {
            'intent': intent,
            'query_type': query_type,
            'required_tools': tools,
            'recommendation': recommendation,
        }

    def _query_ollama(self, prompt: str) -> Dict[str, Any]:
        """Query Ollama API"""
        import requests

        response = requests.post(
            f'{self.ollama_url}/api/generate',
            json={
                'model': self.model,
                'prompt': prompt,
                'max_tokens': 300,
                'temperature': 0.2,
                'stream': False,
            },
            timeout=30,
        )
        response.raise_for_status()
        output = response.json()
        text = output.get('response', '')
        return self._parse_json_from_text(text)

    def _query_openai(self, prompt: str) -> Dict[str, Any]:
        """Query OpenAI API"""
        import openai

        if not self.openai_api_key:
            raise ValueError('OPENAI_API_KEY is required for OpenAI provider')

        openai.api_key = self.openai_api_key
        response = openai.ChatCompletion.create(
            model='gpt-4o-mini',
            messages=[
                {'role': 'system', 'content': 'You are a security copilot assistant.'},
                {'role': 'user', 'content': prompt},
            ],
            max_tokens=300,
            temperature=0.2,
        )
        text = response.choices[0].message.content
        return self._parse_json_from_text(text)

    def _parse_json_from_text(self, text: str) -> Dict[str, Any]:
        """Parse JSON from LLM response text"""
        # Try to find JSON in the response
        match = re.search(r'({.*})', text, re.DOTALL)
        if not match:
            raise ValueError('LLM response did not contain JSON')
        
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError as e:
            # Try to fix common JSON issues
            cleaned = match.group(1)
            # Fix unquoted keys
            cleaned = re.sub(r'(\w+):', r'"\1":', cleaned)
            # Fix single quotes
            cleaned = cleaned.replace("'", '"')
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                raise ValueError(f'Failed to parse JSON from LLM response: {e}')

    def generate_response(
        self,
        user_question: str,
        investigation_data: Dict[str, Any]
    ) -> str:
        """
        Generate a natural language response based on the investigation data.
        """
        try:
            if self.provider == "ollama":
                return self._ollama_chat(user_question, investigation_data)
            elif self.provider == "openai":
                return self._openai_chat(user_question, investigation_data)
            else:
                return self._generate_local_answer(user_question, investigation_data)
        except Exception as e:
            print(f"Response generation failed: {e}")
            return self._generate_local_answer(user_question, investigation_data)

    def _ollama_chat(self, user_question: str, investigation_data: Dict[str, Any]) -> str:
        """Generate response using Ollama"""
        import requests
        
        prompt = self._build_response_prompt(user_question, investigation_data)
        
        response = requests.post(
            f'{self.ollama_url}/api/generate',
            json={
                'model': self.model,
                'prompt': prompt,
                'max_tokens': 500,
                'temperature': 0.7,
                'stream': False,
            },
            timeout=30,
        )
        response.raise_for_status()
        output = response.json()
        return output.get('response', self._generate_local_answer(user_question, investigation_data))

    def _openai_chat(self, user_question: str, investigation_data: Dict[str, Any]) -> str:
        """Generate response using OpenAI"""
        import openai

        if not self.openai_api_key:
            raise ValueError('OPENAI_API_KEY is required for OpenAI provider')

        prompt = self._build_response_prompt(user_question, investigation_data)
        
        openai.api_key = self.openai_api_key
        response = openai.ChatCompletion.create(
            model='gpt-4o-mini',
            messages=[
                {'role': 'system', 'content': 'You are an expert SOC Analyst. Provide clear, actionable security insights.'},
                {'role': 'user', 'content': prompt},
            ],
            max_tokens=500,
            temperature=0.7,
        )
        return response.choices[0].message.content

    def _build_response_prompt(self, user_question: str, investigation_data: Dict[str, Any]) -> str:
        """Build the prompt for generating a natural language response"""
        # Format investigation data for the prompt
        formatted_data = json.dumps(investigation_data, indent=2)
        
        return f"""
You are an expert SOC Analyst.

The user asked:
{user_question}

Investigation Data:
{formatted_data}

Please provide a natural, professional response that:
1. Explains what happened in clear terms
2. Answers the user's specific question
3. Provides actionable recommendations if appropriate
4. Explains the severity and impact
5. Is concise but comprehensive

Write like a professional security analyst explaining the situation to a fellow security professional.

Never output JSON. Write in plain English with proper formatting.
"""

    def _generate_local_answer(self, user_question: str, investigation_data: Dict[str, Any]) -> str:
        """
        Generate a local fallback response without using an LLM.
        This ensures the system always has a response even without API keys.
        """
        # Extract key information from investigation data
        attack = investigation_data.get("attack_type", "Unknown")
        host = investigation_data.get("affected_host", "Unknown")
        severity = investigation_data.get("severity", "Unknown")
        ioc = investigation_data.get("ioc", "Unknown")
        source_ip = investigation_data.get("source_ip", "N/A")
        destination_ip = investigation_data.get("destination_ip", "N/A")
        mitre = investigation_data.get("mitre_technique", "N/A")
        status = investigation_data.get("status", "Open")
        summary = investigation_data.get("summary", "")
        
        # Get user question in lowercase for matching
        q = user_question.lower()
        
        # Check for specific question types
        if any(phrase in q for phrase in ["what happened", "summary", "describe", "tell me about"]):
            return self._generate_summary_response(attack, host, severity, ioc, source_ip, summary)
        
        if any(phrase in q for phrase in ["why", "critical", "high", "severity"]):
            return self._generate_severity_explanation(attack, host, severity, ioc, mitre)
        
        if any(phrase in q for phrase in ["recommend", "contain", "remediate", "fix", "response"]):
            return self._generate_recommendations(attack, severity, ioc)
        
        if any(phrase in q for phrase in ["ioc", "indicator", "malicious"]):
            return self._generate_ioc_response(ioc, source_ip, destination_ip)
        
        if "status" in q:
            return f"The current status of this investigation is: {status}. The alert is actively being monitored for additional activity."
        
        # Default response with all key information
        return self._generate_default_response(attack, host, severity, ioc, source_ip, destination_ip, mitre, status)

    def _generate_summary_response(self, attack: str, host: str, severity: str, ioc: str, source_ip: str, summary: str) -> str:
        """Generate a summary response"""
        response = f"**Incident Summary**\n\n"
        response += f"This investigation identified a **{severity}** severity incident involving **{attack}** "
        response += f"targeting **{host}**.\n\n"
        
        if source_ip and source_ip != "N/A":
            response += f"The attack originated from IP address **{source_ip}**. "
        
        if summary:
            response += f"\n{summary}\n\n"
        
        response += f"The primary indicator of compromise is **{ioc}**. "
        response += "Immediate investigation and containment actions are recommended."
        
        return response

    def _generate_severity_explanation(self, attack: str, host: str, severity: str, ioc: str, mitre: str) -> str:
        """Generate a severity explanation response"""
        response = f"**Severity Analysis**\n\n"
        response += f"This incident has been classified as **{severity}** because:\n\n"
        
        if severity in ["Critical", "High"]:
            response += "• The attack involves active malicious activity confirmed by threat intelligence\n"
            response += f"• The IOC **{ioc}** has a known malicious reputation\n"
            if mitre and mitre != "N/A":
                response += f"• The attack maps to MITRE ATT&CK technique **{mitre}**\n"
            response += "• There is potential for data breach or system compromise\n"
            response += "• Immediate response is required to prevent escalation\n"
        elif severity == "Medium":
            response += "• Suspicious activity was detected but may not be confirmed malicious\n"
            response += "• Additional investigation is needed to determine impact\n"
        else:
            response += "• The activity appears low-risk but warrants monitoring\n"
        
        response += f"\nThe attack type is **{attack}** targeting **{host}**."
        
        return response

    def _generate_recommendations(self, attack: str, severity: str, ioc: str) -> str:
        """Generate recommendations response"""
        response = "**Recommended Actions**\n\n"
        
        if severity in ["Critical", "High"]:
            response += "**Immediate Actions:**\n"
            response += "1. 🚨 Isolate affected systems from the network immediately\n"
            response += "2. 🚨 Escalate to the incident response team\n"
            response += "3. 🚨 Preserve forensic evidence for analysis\n"
            response += f"4. 🚨 Block IOC **{ioc}** at the network perimeter\n\n"
        else:
            response += "**Recommended Actions:**\n"
        
        # Attack-specific recommendations
        if "login" in attack.lower() or "brute" in attack.lower():
            response += "• Reset affected user passwords immediately\n"
            response += "• Enable Multi-Factor Authentication (MFA) for all accounts\n"
            response += "• Review failed login patterns and adjust lockout policies\n"
        
        if "malware" in attack.lower() or "ransom" in attack.lower():
            response += "• Run full antivirus scans on all affected systems\n"
            response += "• Check for persistence mechanisms\n"
            response += "• Review backup integrity and restore procedures\n"
        
        if "phishing" in attack.lower():
            response += "• Notify all potentially affected users\n"
            response += "• Review and update email filtering rules\n"
            response += "• Conduct security awareness training\n"
        
        # General recommendations
        response += "\n**General Recommendations:**\n"
        response += "• Monitor for additional alerts and suspicious activity\n"
        response += "• Review logs for signs of lateral movement\n"
        response += "• Update security monitoring rules to detect similar patterns\n"
        response += "• Document findings for future reference\n"
        
        return response

    def _generate_ioc_response(self, ioc: str, source_ip: str, destination_ip: str) -> str:
        """Generate an IOC-specific response"""
        response = f"**Indicators of Compromise (IOCs)**\n\n"
        response += f"The primary IOC identified is: **{ioc}**\n\n"
        
        if source_ip and source_ip != "N/A":
            response += f"**Source IP:** {source_ip}\n"
        if destination_ip and destination_ip != "N/A":
            response += f"**Destination IP:** {destination_ip}\n"
        
        response += "\n**What to do with this IOC:**\n"
        response += "• Block at firewall and endpoint detection tools\n"
        response += "• Search for additional instances in your environment\n"
        response += "• Enrich with threat intelligence feeds\n"
        response += "• Monitor for ongoing activity related to this IOC\n"
        
        return response

    def _generate_default_response(self, attack: str, host: str, severity: str, ioc: str, 
                                   source_ip: str, destination_ip: str, mitre: str, status: str) -> str:
        """Generate a default comprehensive response"""
        response = "**Security Investigation Report**\n\n"
        response += f"**Incident Details:**\n"
        response += f"• Attack Type: {attack}\n"
        response += f"• Affected Host: {host}\n"
        response += f"• Severity: {severity}\n"
        response += f"• Status: {status}\n"
        
        if source_ip and source_ip != "N/A":
            response += f"• Source IP: {source_ip}\n"
        if destination_ip and destination_ip != "N/A":
            response += f"• Destination IP: {destination_ip}\n"
        if mitre and mitre != "N/A":
            response += f"• MITRE Technique: {mitre}\n"
        
        response += f"\n**Primary IOC:** {ioc}\n\n"
        response += "**Recommended Actions:**\n"
        response += "1. Investigate the compromised host\n"
        response += "2. Block the identified IOC\n"
        response += "3. Review access logs for suspicious activity\n"
        response += "4. Monitor for additional alerts\n\n"
        response += "**Next Steps:**\n"
        response += "• Escalate to incident response team if critical\n"
        response += "• Document findings and actions taken\n"
        response += "• Review and update security controls\n"
        
        return response