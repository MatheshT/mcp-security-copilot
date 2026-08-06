"""
Autonomous SOC Analyst Module
Acts as an autonomous SOC analyst for security investigation
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum
from ..log_collector.windows_log_collector import WindowsLogCollector
from ..log_collector.ioc_extractor import IOCExtractor, IOCPrioritizer
from ..threat_intel.orchestrator import ThreatIntelOrchestrator
from ..llm_client import LLMClient
from ..utils.logger import get_logger

logger = get_logger(__name__)


class InvestigationPhase(str, Enum):
    """Phases of investigation"""
    PLANNING = "planning"
    EVIDENCE_COLLECTION = "evidence_collection"
    IOC_EXTRACTION = "ioc_extraction"
    THREAT_INTEL = "threat_intel_analysis"
    CORRELATION = "correlation_analysis"
    RISK_ASSESSMENT = "risk_assessment"
    REPORTING = "reporting"
    ACTION_RECOMMENDATION = "action_recommendation"


class AutonomousSOCAnalyst:
    """Autonomous SOC Analyst for security investigations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.log_collector = WindowsLogCollector()
        self.ioc_extractor = IOCExtractor()
        self.ioc_prioritizer = IOCPrioritizer()
        self.threat_intel_orchestrator = ThreatIntelOrchestrator(config)
        self.llm_client = LLMClient(config)
        
        self.investigation_state = {
            "current_phase": InvestigationPhase.PLANNING,
            "phases_completed": [],
            "findings": {},
            "evidence": {},
            "risk_score": 0,
            "decisions": []
        }
    
    async def conduct_investigation(self, investigation_params: Dict[str, Any]) -> Dict[str, Any]:
        """Conduct a complete autonomous investigation"""
        investigation_id = f"investigation_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        logger.info(f"Starting investigation {investigation_id}")
        
        investigation_result = {
            "investigation_id": investigation_id,
            "start_time": datetime.now().isoformat(),
            "parameters": investigation_params,
            "phases": [],
            "final_report": None,
            "status": "in_progress"
        }
        
        try:
            # Phase 1: Planning
            planning_result = await self._plan_investigation(investigation_params)
            investigation_result["phases"].append(planning_result)
            self.investigation_state["phases_completed"].append(InvestigationPhase.PLANNING)
            
            # Phase 2: Evidence Collection
            evidence_result = await self._collect_evidence(planning_result)
            investigation_result["phases"].append(evidence_result)
            self.investigation_state["phases_completed"].append(InvestigationPhase.EVIDENCE_COLLECTION)
            
            # Phase 3: IOC Extraction
            ioc_result = await self._extract_iocs(evidence_result)
            investigation_result["phases"].append(ioc_result)
            self.investigation_state["phases_completed"].append(InvestigationPhase.IOC_EXTRACTION)
            
            # Phase 4: Threat Intelligence Analysis
            threat_intel_result = await self._analyze_threat_intel(ioc_result)
            investigation_result["phases"].append(threat_intel_result)
            self.investigation_state["phases_completed"].append(InvestigationPhase.THREAT_INTEL)
            
            # Phase 5: Correlation Analysis
            correlation_result = await self._perform_correlation(threat_intel_result)
            investigation_result["phases"].append(correlation_result)
            self.investigation_state["phases_completed"].append(InvestigationPhase.CORRELATION)
            
            # Phase 6: Risk Assessment
            risk_result = await self._assess_risk(correlation_result)
            investigation_result["phases"].append(risk_result)
            self.investigation_state["phases_completed"].append(InvestigationPhase.RISK_ASSESSMENT)
            
            # Phase 7: Report Generation
            report_result = await self._generate_report(risk_result)
            investigation_result["phases"].append(report_result)
            self.investigation_state["phases_completed"].append(InvestigationPhase.REPORTING)
            
            # Phase 8: Action Recommendations
            action_result = await self._recommend_actions(report_result)
            investigation_result["phases"].append(action_result)
            self.investigation_state["phases_completed"].append(InvestigationPhase.ACTION_RECOMMENDATION)
            
            # Final report
            investigation_result["final_report"] = report_result.get("report", {})
            investigation_result["status"] = "completed"
            investigation_result["end_time"] = datetime.now().isoformat()
            
            logger.info(f"Investigation {investigation_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Investigation {investigation_id} failed: {e}")
            investigation_result["status"] = "failed"
            investigation_result["error"] = str(e)
            investigation_result["end_time"] = datetime.now().isoformat()
        
        return investigation_result
    
    async def _plan_investigation(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Plan the investigation approach"""
        logger.info("Phase 1: Planning investigation")
        
        self.investigation_state["current_phase"] = InvestigationPhase.PLANNING
        
        # Use LLM to generate investigation plan
        planning_prompt = f"""
        Based on the following investigation parameters, create a detailed investigation plan:
        
        Parameters: {params}
        
        The plan should include:
        1. What log sources to collect
        2. Time range for analysis
        3. Priority areas to investigate
        4. Specific IOC types to focus on
        5. Hypotheses to test
        """
        
        try:
            llm_plan = await self.llm_client.analyze(planning_prompt)
        except:
            llm_plan = {"analysis": "Default investigation plan will be used"}
        
        # Create structured plan
        plan = {
            "phase": InvestigationPhase.PLANNING,
            "timestamp": datetime.now().isoformat(),
            "log_sources": params.get("log_sources", ["windows_event", "sysmon", "defender"]),
            "time_range_hours": params.get("time_range_hours", 24),
            "priority_areas": self._determine_priority_areas(params),
            "ioc_focus": self._determine_ioc_focus(params),
            "hypotheses": self._generate_hypotheses(params),
            "llm_guidance": llm_plan
        }
        
        self.investigation_state["findings"]["plan"] = plan
        
        return plan
    
    def _determine_priority_areas(self, params: Dict[str, Any]) -> List[str]:
        """Determine priority investigation areas"""
        priority_areas = []
        
        if params.get("investigation_type") == "malware":
            priority_areas.extend(["process_creation", "file_modification", "network_connections"])
        elif params.get("investigation_type") == "insider_threat":
            priority_areas.extend(["user_activity", "data_access", "privilege_escalation"])
        elif params.get("investigation_type") == "lateral_movement":
            priority_areas.extend(["network_connections", "authentication", "remote_execution"])
        else:
            priority_areas.extend(["all_security_events", "high_risk_activities"])
        
        return priority_areas
    
    def _determine_ioc_focus(self, params: Dict[str, Any]) -> List[str]:
        """Determine IOC focus areas"""
        return ["ip_addresses", "domains", "file_hashes", "processes", "users"]
    
    def _generate_hypotheses(self, params: Dict[str, Any]) -> List[str]:
        """Generate investigation hypotheses"""
        return [
            "Potential malware infection based on suspicious activity",
            "Possible unauthorized access attempt",
            "Normal baseline deviation detected"
        ]
    
    async def _collect_evidence(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Collect evidence based on plan"""
        logger.info("Phase 2: Collecting evidence")
        
        self.investigation_state["current_phase"] = InvestigationPhase.EVIDENCE_COLLECTION
        
        evidence = {
            "phase": InvestigationPhase.EVIDENCE_COLLECTION,
            "timestamp": datetime.now().isoformat(),
            "collection_summary": {},
            "evidence_data": {}
        }
        
        # Collect logs from planned sources
        for source in plan["log_sources"]:
            try:
                log_data = await self.log_collector.collect_specific_source(
                    source,
                    plan["time_range_hours"]
                )
                evidence["evidence_data"][source] = log_data
                evidence["collection_summary"][source] = {
                    "status": "success",
                    "log_count": log_data.get("total_logs", 0)
                }
            except Exception as e:
                logger.error(f"Error collecting {source}: {e}")
                evidence["collection_summary"][source] = {
                    "status": "failed",
                    "error": str(e)
                }
        
        self.investigation_state["evidence"] = evidence["evidence_data"]
        
        return evidence
    
    async def _extract_iocs(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Extract IOCs from collected evidence"""
        logger.info("Phase 3: Extracting IOCs")
        
        self.investigation_state["current_phase"] = InvestigationPhase.IOC_EXTRACTION
        
        # Flatten all logs from different sources
        all_logs = []
        for source, data in evidence["evidence_data"].items():
            if "logs" in data:
                all_logs.extend(data["logs"])
        
        # Extract IOCs
        iocs = self.ioc_extractor.extract_iocs(all_logs)
        
        # Prioritize IOCs
        prioritized_iocs = self.ioc_prioritizer.prioritize_iocs(iocs)
        
        result = {
            "phase": InvestigationPhase.IOC_EXTRACTION,
            "timestamp": datetime.now().isoformat(),
            "total_logs_processed": len(all_logs),
            "extracted_iocs": iocs,
            "prioritized_iocs": prioritized_iocs,
            "ioc_summary": iocs.get("summary", {})
        }
        
        self.investigation_state["findings"]["iocs"] = iocs
        
        return result
    
    async def _analyze_threat_intel(self, ioc_result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze IOCs against threat intelligence sources"""
        logger.info("Phase 4: Analyzing threat intelligence")
        
        self.investigation_state["current_phase"] = InvestigationPhase.THREAT_INTEL
        
        # Use threat intelligence orchestrator
        threat_intel_results = await self.threat_intel_orchestrator.analyze_iocs(
            ioc_result["extracted_iocs"]
        )
        
        result = {
            "phase": InvestigationPhase.THREAT_INTEL,
            "timestamp": datetime.now().isoformat(),
            "threat_intel_analysis": threat_intel_results,
            "high_risk_iocs": self._identify_high_risk_iocs(threat_intel_results)
        }
        
        self.investigation_state["findings"]["threat_intel"] = threat_intel_results
        
        return result
    
    def _identify_high_risk_iocs(self, threat_intel_results: Dict[str, Any]) -> List[Dict]:
        """Identify high-risk IOCs from threat intelligence results"""
        high_risk_iocs = []
        
        for source, results in threat_intel_results.items():
            if isinstance(results, dict) and "analyses" in results:
                for ioc_key, analysis in results["analyses"].items():
                    if (isinstance(analysis, dict) and 
                        analysis.get("risk_level") in ["critical", "high"]):
                        high_risk_iocs.append({
                            "ioc": ioc_key,
                            "source": source,
                            "risk_level": analysis.get("risk_level"),
                            "details": analysis
                        })
        
        return high_risk_iocs
    
    async def _perform_correlation(self, threat_intel_result: Dict[str, Any]) -> Dict[str, Any]:
        """Perform correlation analysis"""
        logger.info("Phase 5: Performing correlation analysis")
        
        self.investigation_state["current_phase"] = InvestigationPhase.CORRELATION
        
        correlation_analysis = threat_intel_result["threat_intel_analysis"].get(
            "correlation_analysis", {}
        )
        
        # Use LLM for advanced correlation insights
        correlation_prompt = f"""
        Analyze the following correlation data and provide insights:
        
        Correlation Analysis: {correlation_analysis}
        IOC Summary: {self.investigation_state["findings"].get("iocs", {}).get("summary", {})}
        
        Provide:
        1. Patterns identified
        2. Potential threat actor attribution
        3. Attack timeline reconstruction
        4. Gaps in evidence
        """
        
        try:
            llm_correlation = await self.llm_client.analyze(correlation_prompt)
        except:
            llm_correlation = {"analysis": "Basic correlation analysis completed"}
        
        result = {
            "phase": InvestigationPhase.CORRELATION,
            "timestamp": datetime.now().isoformat(),
            "correlation_analysis": correlation_analysis,
            "llm_insights": llm_correlation,
            "identified_patterns": self._identify_patterns(correlation_analysis)
        }
        
        return result
    
    def _identify_patterns(self, correlation_analysis: Dict[str, Any]) -> List[str]:
        """Identify patterns from correlation analysis"""
        patterns = []
        
        if correlation_analysis.get("cross_source_matches"):
            patterns.append("Multiple threat intelligence sources flagged same IOCs")
        
        if correlation_analysis.get("threat_actor_indicators"):
            patterns.append("Potential threat actor TTPs detected")
        
        if correlation_analysis.get("high_confidence_findings"):
            patterns.append(f"{len(correlation_analysis['high_confidence_findings'])} high-confidence findings")
        
        return patterns
    
    async def _assess_risk(self, correlation_result: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall risk"""
        logger.info("Phase 6: Assessing risk")
        
        self.investigation_state["current_phase"] = InvestigationPhase.RISK_ASSESSMENT
        
        threat_intel_results = correlation_result["threat_intel_analysis"]
        risk_assessment = threat_intel_results.get("risk_assessment", {})
        
        # Use LLM for risk assessment validation
        risk_prompt = f"""
        Review and validate the following risk assessment:
        
        Risk Assessment: {risk_assessment}
        Correlation Results: {correlation_result}
        
        Provide:
        1. Validation of risk score
        2. Additional risk factors to consider
        3. Potential impact assessment
        """
        
        try:
            llm_risk = await self.llm_client.analyze(risk_prompt)
        except:
            llm_risk = {"analysis": "Risk assessment completed"}
        
        result = {
            "phase": InvestigationPhase.RISK_ASSESSMENT,
            "timestamp": datetime.now().isoformat(),
            "risk_assessment": risk_assessment,
            "llm_validation": llm_risk,
            "overall_risk_score": risk_assessment.get("overall_risk_score", 0),
            "risk_level": risk_assessment.get("risk_level", "unknown")
        }
        
        self.investigation_state["risk_score"] = risk_assessment.get("overall_risk_score", 0)
        
        return result
    
    async def _generate_report(self, risk_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate investigation report"""
        logger.info("Phase 7: Generating report")
        
        self.investigation_state["current_phase"] = InvestigationPhase.REPORTING
        
        # Generate comprehensive report
        report = {
            "investigation_id": f"investigation_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "report_timestamp": datetime.now().isoformat(),
            "executive_summary": self._generate_executive_summary(),
            "investigation_phases": self.investigation_state["phases_completed"],
            "key_findings": self._generate_key_findings(),
            "risk_assessment": risk_result["risk_assessment"],
            "evidence_summary": self._generate_evidence_summary(),
            "threat_intelligence_summary": self._generate_threat_intel_summary(),
            "correlation_findings": self._generate_correlation_summary(),
            "recommendations": []
        }
        
        # Use LLM to enhance report
        report_prompt = f"""
        Enhance the following investigation report with detailed analysis and recommendations:
        
        Report Data: {report}
        Investigation State: {self.investigation_state}
        
        Provide:
        1. Detailed executive summary
        2. Attack narrative
        3. Impact assessment
        4. Strategic recommendations
        """
        
        try:
            llm_report = await self.llm_client.analyze(report_prompt)
            report["llm_enhancement"] = llm_report
        except:
            report["llm_enhancement"] = {"analysis": "Report generation completed"}
        
        result = {
            "phase": InvestigationPhase.REPORTING,
            "timestamp": datetime.now().isoformat(),
            "report": report
        }
        
        return result
    
    def _generate_executive_summary(self) -> str:
        """Generate executive summary"""
        risk_score = self.investigation_state["risk_score"]
        
        if risk_score >= 75:
            severity = "critical"
            summary = "Critical security incident detected requiring immediate action"
        elif risk_score >= 50:
            severity = "high"
            summary = "High-risk security incident detected requiring urgent investigation"
        elif risk_score >= 25:
            severity = "medium"
            summary = "Medium-risk security activity detected requiring investigation"
        else:
            severity = "low"
            summary = "Low-risk security activity detected for monitoring"
        
        return f"""
        Security Investigation Executive Summary
        
        Risk Level: {severity.upper()}
        Risk Score: {risk_score}/100
        
        {summary}
        
        This investigation analyzed Windows Event Logs, Sysmon logs, and Windows Defender logs
        to identify potential security threats. The analysis included IOC extraction, threat
        intelligence correlation, and risk assessment.
        """
    
    def _generate_key_findings(self) -> List[str]:
        """Generate key findings"""
        findings = []
        
        iocs = self.investigation_state["findings"].get("iocs", {})
        if iocs.get("summary"):
            findings.append(f"Extracted {iocs['summary'].get('unique_ip_addresses', 0)} unique IP addresses")
            findings.append(f"Extracted {iocs['summary'].get('unique_domains', 0)} unique domains")
            findings.append(f"Extracted {iocs['summary'].get('total_file_hashes', 0)} file hashes")
        
        threat_intel = self.investigation_state["findings"].get("threat_intel", {})
        if threat_intel.get("risk_assessment"):
            risk_level = threat_intel["risk_assessment"].get("risk_level", "unknown")
            findings.append(f"Overall risk level assessed as: {risk_level}")
        
        return findings
    
    def _generate_evidence_summary(self) -> Dict[str, Any]:
        """Generate evidence summary"""
        evidence = self.investigation_state.get("evidence", {})
        
        summary = {
            "total_sources": len(evidence),
            "sources": []
        }
        
        for source, data in evidence.items():
            summary["sources"].append({
                "name": source,
                "log_count": data.get("total_logs", 0),
                "collection_time": data.get("collected_at", "")
            })
        
        return summary
    
    def _generate_threat_intel_summary(self) -> Dict[str, Any]:
        """Generate threat intelligence summary"""
        threat_intel = self.investigation_state["findings"].get("threat_intel", {})
        
        return {
            "sources_queried": list(threat_intel.keys()),
            "successful_analyses": threat_intel.get("successful", 0),
            "correlation_findings": len(threat_intel.get("correlation_analysis", {}).get("cross_source_matches", []))
        }
    
    def _generate_correlation_summary(self) -> Dict[str, Any]:
        """Generate correlation summary"""
        threat_intel = self.investigation_state["findings"].get("threat_intel", {})
        correlation = threat_intel.get("correlation_analysis", {})
        
        return {
            "cross_source_matches": len(correlation.get("cross_source_matches", [])),
            "high_confidence_findings": len(correlation.get("high_confidence_findings", [])),
            "threat_actor_indicators": len(correlation.get("threat_actor_indicators", []))
        }
    
    async def _recommend_actions(self, report_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate action recommendations"""
        logger.info("Phase 8: Recommending actions")
        
        self.investigation_state["current_phase"] = InvestigationPhase.ACTION_RECOMMENDATION
        
        risk_assessment = report_result["report"]["risk_assessment"]
        threat_intel_results = self.investigation_state["findings"].get("threat_intel", {})
        
        # Generate recommendations based on risk
        recommendations = self._generate_action_recommendations(risk_assessment, threat_intel_results)
        
        result = {
            "phase": InvestigationPhase.ACTION_RECOMMENDATION,
            "timestamp": datetime.now().isoformat(),
            "recommendations": recommendations,
            "priority": self._determine_action_priority(risk_assessment)
        }
        
        return result
    
    def _generate_action_recommendations(self, risk_assessment: Dict[str, Any],
                                         threat_intel_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate action recommendations"""
        recommendations = []
        risk_level = risk_assessment.get("risk_level", "low")
        
        if risk_level in ["critical", "high"]:
            recommendations.extend([
                {
                    "action": "Isolate affected systems",
                    "priority": "immediate",
                    "category": "containment"
                },
                {
                    "action": "Block malicious IOCs",
                    "priority": "immediate",
                    "category": "containment"
                },
                {
                    "action": "Initiate incident response",
                    "priority": "immediate",
                    "category": "response"
                }
            ])
        
        if risk_level in ["medium", "high", "critical"]:
            recommendations.extend([
                {
                    "action": "Conduct forensic analysis",
                    "priority": "high",
                    "category": "investigation"
                },
                {
                    "action": "Review user activity",
                    "priority": "high",
                    "category": "investigation"
                }
            ])
        
        recommendations.extend([
            {
                "action": "Update security signatures",
                "priority": "medium",
                "category": "prevention"
            },
            {
                "action": "Monitor for continued activity",
                "priority": "medium",
                "category": "monitoring"
            }
        ])
        
        return recommendations
    
    def _determine_action_priority(self, risk_assessment: Dict[str, Any]) -> str:
        """Determine overall action priority"""
        risk_level = risk_assessment.get("risk_level", "low")
        
        if risk_level == "critical":
            return "immediate"
        elif risk_level == "high":
            return "urgent"
        elif risk_level == "medium":
            return "standard"
        else:
            return "low"
    
    async def close(self):
        """Close all connections"""
        await self.threat_intel_orchestrator.close()
        await self.llm_client.close()