from typing import Optional
from .orchestrator import SecurityCopilotOrchestrator
from .schemas import InvestigationResponse


class InvestigationService:
    def __init__(self, orchestrator: Optional[SecurityCopilotOrchestrator] = None):
        """
        Initialize the Investigation Service.
        
        Args:
            orchestrator: Optional orchestrator instance. If not provided, creates a new one.
        """
        self.orchestrator = orchestrator or SecurityCopilotOrchestrator()

    def analyze_file_upload(self, filename: str, content_bytes: bytes) -> InvestigationResponse:
        """Process an uploaded file/image through orchestrator file analysis"""
        result = self.orchestrator.analyze_file_upload(filename, content_bytes)
        llm_result = result.get('llm', {})
        ai_answer = result.get('ai_answer') or self._generate_fallback_answer(result.get('report_json', {}), filename)
        
        return InvestigationResponse(
            required_tools=llm_result.get("required_tools", []),
            query_type=llm_result.get("query_type", "other"),
            intent=llm_result.get("intent", "unknown"),
            recommendation=llm_result.get("recommendation"),
            tool_responses=result.get("tool_responses"),
            unified_investigation=result.get("unified_investigation"),
            report_json=result.get("report_json"),
            report_html=result.get("report_html"),
            ai_answer=ai_answer,
        )

    def analyze_query(self, query: str) -> InvestigationResponse:
        """
        Process a user query through the orchestrator and return structured results.
        
        Args:
            query: The user's investigation query (e.g., "Investigate alert 101", 
                   "Check IP 185.220.101.45", "What happened with this alert?")
            
        Returns:
            InvestigationResponse with all investigation data including:
            - required_tools: List of security tools used
            - query_type: Type of query (incident_investigation, threat_hunting, etc.)
            - intent: User intent label
            - recommendation: Next step recommendation
            - tool_responses: Raw responses from security tools
            - unified_investigation: Correlated investigation data
            - report_json: Structured report JSON
            - report_html: HTML version of the report
            - ai_answer: Natural language AI analysis response
        """
        # Step 1: Run the orchestrator to process the query
        result = self.orchestrator.analyze_query(query)
        
        # Debug output
        print(f"[InvestigationService] Analysis complete for query: {query}")
        
        # Step 2: Extract LLM results
        llm_result = result.get('llm', {})
        
        # Step 3: Get AI answer (with fallback if not available)
        ai_answer = result.get('ai_answer')
        if not ai_answer:
            ai_answer = self._generate_fallback_answer(
                result.get('report_json', {}), 
                query
            )
        
        # Step 4: Return structured response
        return InvestigationResponse(
            required_tools=llm_result.get("required_tools", []),
            query_type=llm_result.get("query_type", "other"),
            intent=llm_result.get("intent", "unknown"),
            recommendation=llm_result.get("recommendation"),
            tool_responses=result.get("tool_responses"),
            unified_investigation=result.get("unified_investigation"),
            report_json=result.get("report_json"),
            report_html=result.get("report_html"),
            ai_answer=ai_answer,
        )

    def _generate_fallback_answer(self, report_json: dict, query: str) -> str:
        """
        Generate a fallback answer if the LLM didn't provide one.
        This ensures we always have something to show the user.
        
        Args:
            report_json: The structured investigation report
            query: The original user query
            
        Returns:
            A formatted natural language response
        """
        # If no report data is available
        if not report_json:
            return (
                "I've analyzed your query but no investigation data was available. "
                "Please try rephrasing your question or check if the alert ID is correct."
            )
        
        # Extract key information from the report
        alert_id = report_json.get('alert_id', 'Unknown')
        attack = report_json.get('attack_type', 'Unknown')
        host = report_json.get('affected_host', 'Unknown')
        severity = report_json.get('severity', 'Unknown')
        ioc = report_json.get('ioc', 'Unknown')
        source_ip = report_json.get('source_ip', 'N/A')
        destination_ip = report_json.get('destination_ip', 'N/A')
        mitre = report_json.get('mitre_technique', 'N/A')
        status = report_json.get('status', 'Open')
        summary = report_json.get('investigation_summary', '')
        confidence = report_json.get('confidence', 'Unknown')
        
        # Build a comprehensive fallback answer
        answer_parts = []
        
        # 1. Header
        answer_parts.append("**Investigation Summary**")
        answer_parts.append("")
        
        # 2. Overview
        overview = f"This investigation (Alert ID: {alert_id}) identified a **{severity}** severity incident"
        if attack != 'Unknown':
            overview += f" involving **{attack}**"
        if host != 'Unknown':
            overview += f" targeting **{host}**"
        answer_parts.append(overview + ".")
        answer_parts.append("")
        
        # 3. Technical details
        details = []
        if source_ip and source_ip != 'N/A':
            details.append(f"**Source IP:** {source_ip}")
        if destination_ip and destination_ip != 'N/A':
            details.append(f"**Destination IP:** {destination_ip}")
        if mitre and mitre != 'N/A':
            details.append(f"**MITRE Technique:** {mitre}")
        if status:
            details.append(f"**Status:** {status}")
        if confidence and confidence != 'Unknown':
            details.append(f"**Confidence:** {confidence}")
        
        if details:
            answer_parts.append("**Technical Details:**")
            answer_parts.extend(details)
            answer_parts.append("")
        
        # 4. IOC Information
        if ioc and ioc != 'Unknown IOC':
            answer_parts.append(f"**Primary Indicator of Compromise:** `{ioc}`")
            answer_parts.append("")
        
        # 5. Summary
        if summary:
            answer_parts.append(f"**Summary:** {summary}")
            answer_parts.append("")
        
        # 6. Threat Intelligence
        threat_intel = report_json.get('threat_intelligence', [])
        if threat_intel:
            answer_parts.append("**Threat Intelligence Findings:**")
            for intel in threat_intel[:5]:
                answer_parts.append(f"• {intel}")
            answer_parts.append("")
        
        # 7. Recommendations
        recommendations = report_json.get('recommendations', [])
        if recommendations:
            answer_parts.append("**Recommended Actions:**")
            for rec in recommendations[:7]:
                answer_parts.append(f"• {rec}")
            answer_parts.append("")
        
        # 8. Next Steps
        answer_parts.append("**Next Steps:**")
        if severity in ['Critical', 'High']:
            answer_parts.append("• 🚨 IMMEDIATE: Escalate to incident response team")
            answer_parts.append("• 🚨 IMMEDIATE: Isolate affected systems from the network")
        answer_parts.append("• Continue monitoring for additional alerts")
        answer_parts.append("• Document all findings and actions taken")
        answer_parts.append("• Review and update security controls if needed")
        
        # Join all parts with newlines
        return "\n".join(answer_parts)

    def get_status(self) -> dict:
        """
        Get the current status of the investigation service.
        Useful for health checks and monitoring.
        
        Returns:
            Dictionary with service status information
        """
        return {
            "service": "InvestigationService",
            "status": "healthy",
            "orchestrator": {
                "default_tools": self.orchestrator.default_tools,
                "llm_provider": self.orchestrator.llm_client.provider,
            }
        }