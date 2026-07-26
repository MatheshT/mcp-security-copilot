"""
Collaborative Investigation Module
Enables real-time collaboration, knowledge sharing, and team-based investigation
with features that don't exist in traditional security tools.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime
import json
import hashlib
import uuid


class CollaborativeInvestigationPlatform:
    """
    Revolutionary collaborative platform that enables security teams to work together
    in real-time with shared insights, live updates, and collective intelligence.
    """
    
    def __init__(self):
        self.active_sessions = {}
        self.investigation_threads = {}
        self.team_insights = {}
        self.knowledge_graph = {}
        
    def create_investigation_session(self, user_id: str, investigation_data: Dict) -> Dict[str, Any]:
        """
        Create a collaborative investigation session with real-time collaboration features.
        Generates unique session ID and enables team participation.
        """
        session_id = str(uuid.uuid4())
        
        session = {
            "session_id": session_id,
            "created_by": user_id,
            "created_at": datetime.utcnow().isoformat(),
            "participants": [user_id],
            "status": "active",
            "investigation_data": investigation_data,
            "live_updates": [],
            "shared_insights": [],
            "decision_log": [],
            "collaboration_score": 0
        }
        
        self.active_sessions[session_id] = session
        
        return {
            "session_id": session_id,
            "invitation_link": f"/collaborate/{session_id}",
            "qr_code": self._generate_qr_code(session_id),
            "participant_count": 1,
            "features": [
                "Real-time synchronization",
                "Shared annotation",
                "Live decision tracking",
                "Collective intelligence"
            ]
        }
    
    def add_participant(self, session_id: str, user_id: str, role: str = "analyst") -> Dict[str, Any]:
        """Add a participant to an ongoing investigation session"""
        if session_id not in self.active_sessions:
            return {"error": "Session not found"}
        
        session = self.active_sessions[session_id]
        
        if user_id not in session["participants"]:
            session["participants"].append(user_id)
            session["live_updates"].append({
                "type": "participant_joined",
                "user_id": user_id,
                "role": role,
                "timestamp": datetime.utcnow().isoformat()
            })
        
        return {
            "session_id": session_id,
            "participant_count": len(session["participants"]),
            "role": role,
            "current_state": self._get_session_state(session)
        }
    
    def share_insight(self, session_id: str, user_id: str, insight: Dict) -> Dict[str, Any]:
        """
        Share a security insight with the investigation team.
        Insights are automatically analyzed for relevance and added to the collective intelligence.
        """
        if session_id not in self.active_sessions:
            return {"error": "Session not found"}
        
        session = self.active_sessions[session_id]
        
        # Analyze insight relevance
        relevance_score = self._calculate_insight_relevance(insight, session["investigation_data"])
        
        shared_insight = {
            "insight_id": str(uuid.uuid4()),
            "user_id": user_id,
            "insight": insight,
            "relevance_score": relevance_score,
            "timestamp": datetime.utcnow().isoformat(),
            "endorsements": [],
            "comments": []
        }
        
        session["shared_insights"].append(shared_insight)
        session["collaboration_score"] += relevance_score
        
        # Update knowledge graph
        self._update_knowledge_graph(insight, session_id)
        
        return {
            "insight_id": shared_insight["insight_id"],
            "relevance_score": relevance_score,
            "contribution_impact": self._calculate_contribution_impact(relevance_score),
            "team_notification": self._generate_team_notification(shared_insight)
        }
    
    def record_decision(self, session_id: str, user_id: str, decision: Dict) -> Dict[str, Any]:
        """
        Record a security decision in the investigation decision log.
        Creates an audit trail with reasoning and expected outcomes.
        """
        if session_id not in self.active_sessions:
            return {"error": "Session not found"}
        
        session = self.active_sessions[session_id]
        
        decision_record = {
            "decision_id": str(uuid.uuid4()),
            "user_id": user_id,
            "decision": decision,
            "timestamp": datetime.utcnow().isoformat(),
            "rationale": decision.get("rationale", ""),
            "expected_outcome": decision.get("expected_outcome", ""),
            "impact_assessment": self._assess_decision_impact(decision, session)
        }
        
        session["decision_log"].append(decision_record)
        
        return {
            "decision_id": decision_record["decision_id"],
            "impact_assessment": decision_record["impact_assessment"],
            "confidence_level": self._calculate_decision_confidence(decision),
            "follow_up_actions": self._suggest_follow_up_actions(decision)
        }
    
    def generate_collective_intelligence(self, session_id: str) -> Dict[str, Any]:
        """
        Generate collective intelligence from all team insights and decisions.
        Uses AI to synthesize team knowledge into actionable intelligence.
        """
        if session_id not in self.active_sessions:
            return {"error": "Session not found"}
        
        session = self.active_sessions[session_id]
        
        # Analyze team insights
        insight_patterns = self._analyze_insight_patterns(session["shared_insights"])
        
        # Analyze decision patterns
        decision_patterns = self._analyze_decision_patterns(session["decision_log"])
        
        # Generate team expertise profile
        team_expertise = self._generate_team_expertise_profile(session)
        
        # Calculate collaboration effectiveness
        collaboration_metrics = self._calculate_collaboration_metrics(session)
        
        return {
            "session_id": session_id,
            "collective_intelligence_score": self._calculate_collective_intelligence_score(session),
            "insight_patterns": insight_patterns,
            "decision_patterns": decision_patterns,
            "team_expertise": team_expertise,
            "collaboration_metrics": collaboration_metrics,
            "actionable_intelligence": self._generate_actionable_intelligence(insight_patterns, decision_patterns),
            "knowledge_gaps": self._identify_knowledge_gaps(session),
            "recommendations": self._generate_team_recommendations(collaboration_metrics)
        }
    
    def _generate_qr_code(self, session_id: str) -> str:
        """Generate a QR code for quick session joining"""
        # In a real implementation, this would generate an actual QR code
        return f"QR_CODE_DATA:{session_id}"
    
    def _get_session_state(self, session: Dict) -> Dict[str, Any]:
        """Get current state of the investigation session"""
        return {
            "participant_count": len(session["participants"]),
            "insight_count": len(session["shared_insights"]),
            "decision_count": len(session["decision_log"]),
            "collaboration_score": session["collaboration_score"],
            "duration_minutes": self._calculate_session_duration(session)
        }
    
    def _calculate_insight_relevance(self, insight: Dict, investigation_data: Dict) -> float:
        """Calculate how relevant an insight is to the current investigation"""
        base_relevance = 0.5
        
        # Check for IOC overlap
        insight_iocs = set(insight.get("iocs", []))
        investigation_iocs = set(investigation_data.get("iocs", []))
        
        if insight_iocs and investigation_iocs:
            overlap = len(insight_iocs & investigation_iocs)
            base_relevance += (overlap / max(len(investigation_iocs), 1)) * 0.3
        
        # Check for attack pattern match
        if insight.get("attack_pattern") == investigation_data.get("attack_pattern"):
            base_relevance += 0.2
        
        return round(min(base_relevance, 1.0), 2)
    
    def _calculate_contribution_impact(self, relevance_score: float) -> str:
        """Calculate the impact of a contribution based on relevance"""
        if relevance_score > 0.8:
            return "High Impact"
        elif relevance_score > 0.5:
            return "Medium Impact"
        else:
            return "Low Impact"
    
    def _generate_team_notification(self, insight: Dict) -> Dict[str, Any]:
        """Generate a notification for the team about new insight"""
        return {
            "type": "new_insight",
            "message": f"New insight shared with {insight['relevance_score']:.0%} relevance",
            "priority": "high" if insight["relevance_score"] > 0.7 else "medium",
            "timestamp": insight["timestamp"]
        }
    
    def _update_knowledge_graph(self, insight: Dict, session_id: str):
        """Update the knowledge graph with new insight connections"""
        insight_id = insight.get("insight_id", str(uuid.uuid4()))
        
        if session_id not in self.knowledge_graph:
            self.knowledge_graph[session_id] = {
                "nodes": [],
                "edges": []
            }
        
        graph = self.knowledge_graph[session_id]
        
        # Add insight as a node
        graph["nodes"].append({
            "id": insight_id,
            "type": "insight",
            "data": insight
        })
        
        # Create connections to related insights
        for existing_node in graph["nodes"]:
            if existing_node["type"] == "insight":
                similarity = self._calculate_insight_similarity(insight, existing_node["data"])
                if similarity > 0.5:
                    graph["edges"].append({
                        "source": insight_id,
                        "target": existing_node["id"],
                        "weight": similarity
                    })
    
    def _calculate_insight_similarity(self, insight1: Dict, insight2: Dict) -> float:
        """Calculate similarity between two insights"""
        # Simple similarity based on IOC overlap
        iocs1 = set(insight1.get("iocs", []))
        iocs2 = set(insight2.get("iocs", []))
        
        if not iocs1 or not iocs2:
            return 0.0
        
        intersection = len(iocs1 & iocs2)
        union = len(iocs1 | iocs2)
        
        return intersection / union if union > 0 else 0.0
    
    def _assess_decision_impact(self, decision: Dict, session: Dict) -> Dict[str, Any]:
        """Assess the potential impact of a security decision"""
        impact_level = decision.get("impact_level", "medium")
        
        return {
            "severity": impact_level,
            "affected_systems": decision.get("affected_systems", []),
            "duration_minutes": decision.get("estimated_duration", 30),
            "risk_increase": decision.get("risk_increase", 0),
            "business_impact": decision.get("business_impact", "low")
        }
    
    def _calculate_decision_confidence(self, decision: Dict) -> str:
        """Calculate confidence level in a decision"""
        confidence_factors = [
            decision.get("data_support", 0),
            decision.get("team_consensus", 0),
            decision.get("historical_success", 0)
        ]
        
        avg_confidence = sum(confidence_factors) / len(confidence_factors)
        
        if avg_confidence > 0.8:
            return "High"
        elif avg_confidence > 0.5:
            return "Medium"
        else:
            return "Low"
    
    def _suggest_follow_up_actions(self, decision: Dict) -> List[str]:
        """Suggest follow-up actions based on the decision"""
        actions = []
        
        if decision.get("action_type") == "isolate":
            actions.extend([
                "Monitor isolated systems for containment effectiveness",
                "Prepare remediation plans",
                "Document isolation procedures"
            ])
        elif decision.get("action_type") == "block":
            actions.extend([
                "Monitor for blocking bypass attempts",
                "Update firewall rules permanently",
                "Review false positive rates"
            ])
        else:
            actions.extend([
                "Monitor for decision effectiveness",
                "Prepare contingency plans",
                "Document decision rationale"
            ])
        
        return actions
    
    def _analyze_insight_patterns(self, insights: List[Dict]) -> Dict[str, Any]:
        """Analyze patterns in team insights"""
        if not insights:
            return {"patterns": [], "trending_topics": [], "expertise_areas": []}
        
        # Extract patterns
        ioc_types = {}
        attack_patterns = {}
        expertise_areas = {}
        
        for insight in insights:
            # Count IOC types
            for ioc in insight.get("iocs", []):
                ioc_type = ioc.split(":")[0] if ":" in ioc else "unknown"
                ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
            
            # Count attack patterns
            pattern = insight.get("attack_pattern", "unknown")
            attack_patterns[pattern] = attack_patterns.get(pattern, 0) + 1
            
            # Count expertise areas
            for area in insight.get("expertise_areas", []):
                expertise_areas[area] = expertise_areas.get(area, 0) + 1
        
        return {
            "patterns": [
                {"type": "ioc_distribution", "data": ioc_types},
                {"type": "attack_patterns", "data": attack_patterns},
                {"type": "expertise_distribution", "data": expertise_areas}
            ],
            "trending_topics": sorted(attack_patterns.items(), key=lambda x: x[1], reverse=True)[:5],
            "expertise_areas": sorted(expertise_areas.items(), key=lambda x: x[1], reverse=True)
        }
    
    def _analyze_decision_patterns(self, decisions: List[Dict]) -> Dict[str, Any]:
        """Analyze patterns in team decisions"""
        if not decisions:
            return {"decision_types": [], "success_rate": 0, "average_confidence": 0}
        
        decision_types = {}
        successful_decisions = 0
        total_confidence = 0
        
        for decision in decisions:
            dec_type = decision.get("decision", {}).get("action_type", "unknown")
            decision_types[dec_type] = decision_types.get(dec_type, 0) + 1
            
            if decision.get("impact_assessment", {}).get("success", False):
                successful_decisions += 1
            
            total_confidence += self._get_confidence_value(decision.get("confidence_level", "Medium"))
        
        return {
            "decision_types": decision_types,
            "success_rate": successful_decisions / len(decisions) if decisions else 0,
            "average_confidence": total_confidence / len(decisions) if decisions else 0
        }
    
    def _get_confidence_value(self, confidence: str) -> float:
        """Convert confidence string to numeric value"""
        confidence_map = {"High": 0.9, "Medium": 0.6, "Low": 0.3}
        return confidence_map.get(confidence, 0.5)
    
    def _generate_team_expertise_profile(self, session: Dict) -> Dict[str, Any]:
        """Generate expertise profile for the team"""
        user_expertise = {}
        
        for insight in session["shared_insights"]:
            user_id = insight["user_id"]
            if user_id not in user_expertise:
                user_expertise[user_id] = {
                    "insights_shared": 0,
                    "total_relevance": 0,
                    "expertise_areas": []
                }
            
            user_expertise[user_id]["insights_shared"] += 1
            user_expertise[user_id]["total_relevance"] += insight["relevance_score"]
            user_expertise[user_id]["expertise_areas"].extend(
                insight.get("insight", {}).get("expertise_areas", [])
            )
        
        # Calculate expertise scores
        for user_id, data in user_expertise.items():
            data["expertise_score"] = data["total_relevance"] / max(data["insights_shared"], 1)
            data["top_areas"] = self._get_top_areas(data["expertise_areas"])
        
        return user_expertise
    
    def _get_top_areas(self, areas: List[str]) -> List[str]:
        """Get top expertise areas"""
        from collections import Counter
        if not areas:
            return []
        
        counter = Counter(areas)
        return [area for area, count in counter.most_common(3)]
    
    def _calculate_collaboration_metrics(self, session: Dict) -> Dict[str, Any]:
        """Calculate collaboration effectiveness metrics"""
        participant_count = len(session["participants"])
        insight_count = len(session["shared_insights"])
        decision_count = len(session["decision_log"])
        
        return {
            "participant_count": participant_count,
            "insight_count": insight_count,
            "decision_count": decision_count,
            "collaboration_score": session["collaboration_score"],
            "insights_per_participant": insight_count / max(participant_count, 1),
            "decision_frequency": decision_count / max(self._calculate_session_duration(session) / 60, 1),
            "team_engagement_level": self._calculate_engagement_level(session)
        }
    
    def _calculate_session_duration(self, session: Dict) -> int:
        """Calculate session duration in minutes"""
        created_at = datetime.fromisoformat(session["created_at"])
        now = datetime.utcnow()
        return int((now - created_at).total_seconds() / 60)
    
    def _calculate_engagement_level(self, session: Dict) -> str:
        """Calculate overall team engagement level"""
        duration = self._calculate_session_duration(session)
        participant_count = len(session["participants"])
        activity_count = len(session["shared_insights"]) + len(session["decision_log"])
        
        if duration == 0:
            return "Low"
        
        activity_rate = activity_count / (participant_count * duration)
        
        if activity_rate > 0.5:
            return "High"
        elif activity_rate > 0.2:
            return "Medium"
        else:
            return "Low"
    
    def _calculate_collective_intelligence_score(self, session: Dict) -> float:
        """Calculate the collective intelligence score of the team"""
        base_score = 50.0
        
        # Factor in collaboration score
        base_score += session["collaboration_score"] * 20
        
        # Factor in insight quality
        if session["shared_insights"]:
            avg_relevance = sum(i["relevance_score"] for i in session["shared_insights"]) / len(session["shared_insights"])
            base_score += avg_relevance * 15
        
        # Factor in decision effectiveness
        if session["decision_log"]:
            decision_success = sum(1 for d in session["decision_log"] if d.get("impact_assessment", {}).get("success", False))
            base_score += (decision_success / len(session["decision_log"])) * 15
        
        return round(min(base_score, 100.0), 1)
    
    def _generate_actionable_intelligence(self, insight_patterns: Dict, decision_patterns: Dict) -> List[Dict]:
        """Generate actionable intelligence from patterns"""
        actionable_items = []
        
        # Generate recommendations based on insight patterns
        for pattern in insight_patterns.get("patterns", []):
            if pattern["type"] == "attack_patterns":
                for attack_pattern, count in pattern["data"].items():
                    if count > 2:
                        actionable_items.append({
                            "type": "pattern_alert",
                            "pattern": attack_pattern,
                            "severity": "high" if count > 5 else "medium",
                            "recommendation": f"Investigate recurring {attack_pattern} pattern"
                        })
        
        # Generate recommendations based on decision patterns
        if decision_patterns.get("success_rate", 0) < 0.7:
            actionable_items.append({
                "type": "process_improvement",
                "recommendation": "Review decision-making process to improve success rate"
            })
        
        return actionable_items
    
    def _identify_knowledge_gaps(self, session: Dict) -> List[str]:
        """Identify gaps in team knowledge"""
        gaps = []
        
        # Check for missing expertise areas
        known_areas = set()
        for insight in session["shared_insights"]:
            known_areas.update(insight.get("insight", {}).get("expertise_areas", []))
        
        required_areas = {"network_security", "malware_analysis", "threat_intelligence", "incident_response"}
        missing_areas = required_areas - known_areas
        
        if missing_areas:
            gaps.extend([f"Consider adding expertise in: {area}" for area in missing_areas])
        
        # Check for low collaboration
        if session["collaboration_score"] < 30:
            gaps.append("Low collaboration detected - encourage team participation")
        
        return gaps
    
    def _generate_team_recommendations(self, metrics: Dict) -> List[str]:
        """Generate recommendations to improve team effectiveness"""
        recommendations = []
        
        if metrics["team_engagement_level"] == "Low":
            recommendations.append("Increase team engagement through more frequent insights sharing")
        
        if metrics["insights_per_participant"] < 2:
            recommendations.append("Encourage each team member to share more insights")
        
        if metrics["decision_frequency"] < 0.1:
            recommendations.append("Improve decision-making frequency and documentation")
        
        if not recommendations:
            recommendations.append("Team collaboration is effective - maintain current practices")
        
        return recommendations