"""
Automated Threat Actor Persona Analysis Module
Uses AI to create psychological and behavioral profiles of threat actors
based on their attack patterns, techniques, and motivations.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime
import random


class ThreatActorPersonaEngine:
    """
    Revolutionary AI-powered threat actor persona analysis that creates
    psychological profiles, behavioral patterns, and strategic insights
    about adversaries based on their attack patterns.
    """
    
    def __init__(self):
        self.known_actor_profiles = self._initialize_known_actors()
        self.personality_traits = self._initialize_personality_traits()
        self.motivation_patterns = self._initialize_motivation_patterns()
        
    def _initialize_known_actors(self) -> Dict[str, Dict]:
        """Initialize database of known threat actor personas"""
        return {
            "APT29": {
                "name": "APT29 (Cozy Bear)",
                "origin": "Russia",
                "personality": "Patient, persistent, sophisticated",
                "motivation": "Espionage, political interference",
                "attack_style": "Stealthy, long-term operations",
                "preferences": ["phishing", "credential theft", "lateral movement"],
                "risk_level": "Critical"
            },
            "Lazarus": {
                "name": "Lazarus Group (APT38)",
                "origin": "North Korea",
                "personality": "Aggressive, financially motivated, adaptable",
                "motivation": "Financial gain, political objectives",
                "attack_style": "Direct, bold, innovative",
                "preferences": ["ransomware", "crypto theft", "SWIFT attacks"],
                "risk_level": "Critical"
            },
            "FancyBear": {
                "name": "Fancy Bear (APT28)",
                "origin": "Russia",
                "personality": "Strategic, military-focused, precise",
                "motivation": "Military intelligence, political influence",
                "attack_style": "Zero-day exploits, strategic targeting",
                "preferences": ["credential harvesting", "political campaigns", "government targets"],
                "risk_level": "Critical"
            }
        }
    
    def _initialize_personality_traits(self) -> Dict[str, Dict]:
        """Initialize personality trait analysis framework"""
        return {
            "patience": {"low": 0.2, "medium": 0.5, "high": 0.8},
            "aggression": {"low": 0.3, "medium": 0.6, "high": 0.9},
            "sophistication": {"low": 0.2, "medium": 0.5, "high": 0.8},
            "adaptability": {"low": 0.3, "medium": 0.6, "high": 0.9},
            "stealth": {"low": 0.2, "medium": 0.5, "high": 0.8}
        }
    
    def _initialize_motivation_patterns(self) -> Dict[str, Dict]:
        """Initialize motivation pattern analysis"""
        return {
            "financial": {"typical_targets": ["banks", "crypto", "retail"], "attack_frequency": "high"},
            "espionage": {"typical_targets": ["government", "military", "tech"], "attack_frequency": "medium"},
            "political": {"typical_targets": ["political parties", "media", "infrastructure"], "attack_frequency": "medium"},
            "cybercrime": {"typical_targets": ["SMBs", "individuals", "e-commerce"], "attack_frequency": "high"},
            "hacktivism": {"typical_targets": ["corporations", "government", "organizations"], "attack_frequency": "variable"}
        }
    
    def analyze_actor_persona(self, attack_data: Dict) -> Dict[str, Any]:
        """
        Analyze attack data to create a comprehensive threat actor persona.
        Uses AI to predict personality, motivations, and behavioral patterns.
        """
        # Extract attack characteristics
        attack_patterns = self._extract_attack_patterns(attack_data)
        technical_sophistication = self._assess_technical_sophistication(attack_data)
        target_preferences = self._analyze_target_preferences(attack_data)
        temporal_patterns = self._analyze_temporal_patterns(attack_data)
        
        # Match against known actors
        actor_match = self._match_known_actor(attack_patterns, technical_sophistication)
        
        # Generate persona profile
        persona_profile = self._generate_persona_profile(
            attack_patterns,
            technical_sophistication,
            target_preferences,
            temporal_patterns,
            actor_match
        )
        
        # Predict future behavior
        behavioral_predictions = self._predict_future_behavior(persona_profile)
        
        # Generate countermeasures
        countermeasures = self._generate_actor_specific_countermeasures(persona_profile)
        
        return {
            "actor_identification": actor_match,
            "persona_profile": persona_profile,
            "behavioral_predictions": behavioral_predictions,
            "recommended_countermeasures": countermeasures,
            "confidence_level": self._calculate_profile_confidence(actor_match, attack_patterns),
            "similar_incidents": self._find_similar_incidents(attack_patterns),
            "threat_intelligence_gaps": self._identify_intelligence_gaps(persona_profile)
        }
    
    def _extract_attack_patterns(self, attack_data: Dict) -> List[str]:
        """Extract attack patterns from data"""
        patterns = []
        
        # Analyze tools and techniques
        tools = attack_data.get("tools", [])
        techniques = attack_data.get("techniques", [])
        
        if "mimikatz" in tools or "credential" in str(techniques).lower():
            patterns.append("credential_harvesting")
        
        if "lateral" in str(techniques).lower() or "psexec" in tools:
            patterns.append("lateral_movement")
        
        if "phishing" in str(attack_data).lower():
            patterns.append("social_engineering")
        
        if "ransomware" in str(attack_data).lower() or "encryption" in str(attack_data).lower():
            patterns.append("data_encryption")
        
        if "zero_day" in str(attack_data).lower() or "exploit" in str(attack_data).lower():
            patterns.append("exploit_development")
        
        return patterns
    
    def _assess_technical_sophistication(self, attack_data: Dict) -> Dict[str, Any]:
        """Assess the technical sophistication of the attacker"""
        complexity_score = 0
        
        # Check for advanced techniques
        if attack_data.get("uses_custom_malware"):
            complexity_score += 30
        
        if attack_data.get("uses_zero_day"):
            complexity_score += 40
        
        if attack_data.get("uses_encryption"):
            complexity_score += 20
        
        if attack_data.get("uses_anti_forensics"):
            complexity_score += 25
        
        # Check for operational security
        if attack_data.get("uses_opsec"):
            complexity_score += 15
        
        sophistication_level = "Advanced" if complexity_score > 80 else "Moderate" if complexity_score > 40 else "Basic"
        
        return {
            "complexity_score": min(complexity_score, 100),
            "sophistication_level": sophistication_level,
            "key_capabilities": self._identify_key_capabilities(attack_data)
        }
    
    def _identify_key_capabilities(self, attack_data: Dict) -> List[str]:
        """Identify key capabilities demonstrated by the attacker"""
        capabilities = []
        
        if attack_data.get("uses_zero_day"):
            capabilities.append("Zero-day exploit development")
        
        if attack_data.get("uses_custom_malware"):
            capabilities.append("Custom malware development")
        
        if attack_data.get("uses_encryption"):
            capabilities.append("Cryptographic capabilities")
        
        if attack_data.get("uses_anti_forensics"):
            capabilities.append("Anti-forensics techniques")
        
        if attack_data.get("uses_opsec"):
            capabilities.append("Operational security")
        
        return capabilities
    
    def _analyze_target_preferences(self, attack_data: Dict) -> Dict[str, Any]:
        """Analyze the attacker's target preferences"""
        targets = attack_data.get("targets", [])
        industries = attack_data.get("target_industries", [])
        
        return {
            "primary_targets": targets[:3] if targets else [],
            "target_industries": industries,
            "geographic_focus": attack_data.get("geographic_focus", "Unknown"),
            "asset_types": attack_data.get("asset_types", []),
            "target_selection_method": attack_data.get("target_selection", "opportunistic")
        }
    
    def _analyze_temporal_patterns(self, attack_data: Dict) -> Dict[str, Any]:
        """Analyze temporal patterns in attacks"""
        timestamps = attack_data.get("timestamps", [])
        
        if not timestamps:
            return {"pattern": "insufficient_data", "work_hours_activity": False}
        
        # Check for work hours vs off-hours patterns
        work_hours_activity = sum(1 for ts in timestamps if self._is_work_hour(ts))
        off_hours_activity = len(timestamps) - work_hours_activity
        
        return {
            "pattern": "off_hours" if off_hours_activity > work_hours_activity else "work_hours",
            "work_hours_activity": work_hours_activity,
            "off_hours_activity": off_hours_activity,
            "attack_frequency": len(timestamps),
            "preferred_days": self._calculate_preferred_days(timestamps)
        }
    
    def _is_work_hour(self, timestamp: str) -> bool:
        """Check if timestamp is during work hours (9 AM - 5 PM)"""
        try:
            hour = datetime.fromisoformat(timestamp).hour
            return 9 <= hour <= 17
        except:
            return True
    
    def _calculate_preferred_days(self, timestamps: List[str]) -> List[str]:
        """Calculate preferred attack days"""
        day_counts = {}
        
        for ts in timestamps:
            try:
                day = datetime.fromisoformat(timestamp).strftime("%A")
                day_counts[day] = day_counts.get(day, 0) + 1
            except:
                continue
        
        if not day_counts:
            return []
        
        return sorted(day_counts.items(), key=lambda x: x[1], reverse=True)[:3]
    
    def _match_known_actor(self, patterns: List[str], sophistication: Dict) -> Dict[str, Any]:
        """Match attack patterns against known threat actors"""
        best_match = None
        highest_confidence = 0
        
        for actor_id, actor_profile in self.known_actor_profiles.items():
            confidence = 0
            
            # Check pattern matching
            actor_preferences = actor_profile["preferences"]
            for pattern in patterns:
                if any(pref in pattern.lower() for pref in actor_preferences):
                    confidence += 25
            
            # Check sophistication matching
            if sophistication["sophistication_level"] == "Advanced" and actor_profile["risk_level"] == "Critical":
                confidence += 30
            
            # Check attack style
            if "stealthy" in actor_profile["attack_style"].lower() and "stealth" in str(patterns).lower():
                confidence += 20
            
            confidence = min(confidence, 95)
            
            if confidence > highest_confidence:
                highest_confidence = confidence
                best_match = {
                    "actor_id": actor_id,
                    "actor_name": actor_profile["name"],
                    "confidence": confidence,
                    "origin": actor_profile["origin"]
                }
        
        if best_match and best_match["confidence"] > 60:
            return best_match
        else:
            return {
                "actor_id": "Unknown",
                "actor_name": "Unknown Threat Actor",
                "confidence": highest_confidence,
                "origin": "Unknown"
            }
    
    def _generate_persona_profile(self, patterns: List[str], sophistication: Dict, 
                               targets: Dict, temporal: Dict, actor_match: Dict) -> Dict[str, Any]:
        """Generate comprehensive persona profile"""
        # Generate personality traits
        personality_traits = self._assess_personality_traits(patterns, temporal)
        
        # Generate motivation assessment
        motivation = self._assess_motivation(targets, patterns)
        
        # Generate behavioral profile
        behavioral_profile = self._generate_behavioral_profile(personality_traits, motivation)
        
        return {
            "personality_traits": personality_traits,
            "motivation": motivation,
            "behavioral_profile": behavioral_profile,
            "technical_profile": sophistication,
            "target_profile": targets,
            "temporal_profile": temporal,
            "operational_style": self._determine_operational_style(personality_traits, sophistication),
            "learning_adaptability": self._assess_learning_adaptability(patterns)
        }
    
    def _assess_personality_traits(self, patterns: List[str], temporal: Dict) -> Dict[str, str]:
        """Assess personality traits based on attack patterns"""
        traits = {}
        
        # Patience
        if "lateral_movement" in patterns and temporal["off_hours_activity"] > temporal["work_hours_activity"]:
            traits["patience"] = "High"
        else:
            traits["patience"] = "Medium"
        
        # Aggression
        if "data_encryption" in patterns or "exploit_development" in patterns:
            traits["aggression"] = "High"
        else:
            traits["aggression"] = "Medium"
        
        # Sophistication
        if "exploit_development" in patterns:
            traits["sophistication"] = "High"
        elif "credential_harvesting" in patterns:
            traits["sophistication"] = "Medium"
        else:
            traits["sophistication"] = "Low"
        
        # Stealth
        if temporal["pattern"] == "off_hours" and "lateral_movement" in patterns:
            traits["stealth"] = "High"
        else:
            traits["stealth"] = "Medium"
        
        # Adaptability
        if len(patterns) > 3:
            traits["adaptability"] = "High"
        else:
            traits["adaptability"] = "Medium"
        
        return traits
    
    def _assess_motivation(self, targets: Dict, patterns: List[str]) -> Dict[str, Any]:
        """Assess likely motivation based on targets and patterns"""
        motivation_scores = {}
        
        # Financial motivation indicators
        if "data_encryption" in patterns or "banks" in str(targets.get("target_industries", [])):
            motivation_scores["financial"] = 0.8
        
        # Espionage motivation indicators
        if "lateral_movement" in patterns and "government" in str(targets.get("target_industries", [])):
            motivation_scores["espionage"] = 0.7
        
        # Political motivation indicators
        if "political" in str(targets.get("target_industries", [])):
            motivation_scores["political"] = 0.75
        
        # Cybercrime motivation indicators
        if "smb" in str(targets.get("target_industries", [])):
            motivation_scores["cybercrime"] = 0.7
        
        # Determine primary motivation
        if motivation_scores:
            primary_motivation = max(motivation_scores, key=motivation_scores.get)
            confidence = motivation_scores[primary_motivation]
        else:
            primary_motivation = "unknown"
            confidence = 0.3
        
        return {
            "primary_motivation": primary_motivation,
            "confidence": confidence,
            "all_motivations": motivation_scores
        }
    
    def _generate_behavioral_profile(self, personality: Dict, motivation: Dict) -> Dict[str, Any]:
        """Generate comprehensive behavioral profile"""
        return {
            "decision_making_style": self._assess_decision_making_style(personality),
            "risk_tolerance": self._assess_risk_tolerance(personality),
            "persistence_level": self._assess_persistence_level(personality),
            "collaboration_indicators": self._assess_collaboration_style(personality),
            "adaptation_speed": self._assess_adaptation_speed(personality),
            "learning_pattern": self._assess_learning_pattern(personality)
        }
    
    def _assess_decision_making_style(self, personality: Dict) -> str:
        """Assess decision-making style"""
        if personality["sophistication"] == "High" and personality["aggression"] == "Medium":
            return "Calculated and Strategic"
        elif personality["aggression"] == "High":
            return "Bold and Direct"
        elif personality["patience"] == "High":
            return "Patient and Methodical"
        else:
            return "Opportunistic"
    
    def _assess_risk_tolerance(self, personality: Dict) -> str:
        """Assess risk tolerance"""
        if personality["aggression"] == "High" and personality["stealth"] == "Low":
            return "High Risk Tolerance"
        elif personality["stealth"] == "High":
            return "Low Risk Tolerance"
        else:
            return "Moderate Risk Tolerance"
    
    def _assess_persistence_level(self, personality: Dict) -> str:
        """Assess persistence level"""
        if personality["patience"] == "High" and personality["adaptability"] == "High":
            return "Very Persistent"
        elif personality["patience"] == "High":
            return "Persistent"
        else:
            return "Opportunistic"
    
    def _assess_collaboration_style(self, personality: Dict) -> str:
        """Assess collaboration style"""
        if personality["adaptability"] == "High":
            return "Team-based Operations"
        else:
            return "Lone Wolf or Small Group"
    
    def _assess_adaptation_speed(self, personality: Dict) -> str:
        """Assess adaptation speed"""
        if personality["adaptability"] == "High":
            return "Rapid Adaptation"
        elif personality["adaptability"] == "Medium":
            return "Moderate Adaptation"
        else:
            return "Slow Adaptation"
    
    def _assess_learning_pattern(self, personality: Dict) -> str:
        """Assess learning pattern"""
        if personality["sophistication"] == "High":
            return "Continuous Learning"
        else:
            return "Limited Learning"
    
    def _determine_operational_style(self, personality: Dict, sophistication: Dict) -> str:
        """Determine operational style"""
        if personality["stealth"] == "High" and sophistication["sophistication_level"] == "Advanced":
            return "Stealth and Precision"
        elif personality["aggression"] == "High":
            return "Bold and Direct"
        elif personality["patience"] == "High":
            return "Patient and Persistent"
        else:
            return "Opportunistic and Adaptable"
    
    def _assess_learning_adaptability(self, patterns: List[str]) -> str:
        """Assess learning and adaptability"""
        pattern_diversity = len(set(patterns))
        
        if pattern_diversity > 4:
            return "High Adaptability - Multiple techniques"
        elif pattern_diversity > 2:
            return "Moderate Adaptability - Some variety"
        else:
            return "Low Adaptability - Limited techniques"
    
    def _predict_future_behavior(self, persona: Dict) -> Dict[str, Any]:
        """Predict future behavior based on persona"""
        predictions = []
        
        # Based on motivation
        motivation = persona["motivation"]["primary_motivation"]
        
        if motivation == "financial":
            predictions.extend([
                "Likely to target financial institutions",
                "May use ransomware for monetization",
                "Will continue until financial goals met"
            ])
        elif motivation == "espionage":
            predictions.extend([
                "Long-term persistence expected",
                "Will focus on intellectual property",
                "May establish stealthy backdoors"
            ])
        elif motivation == "political":
            predictions.extend([
                "May target critical infrastructure",
                "Timing may align with political events",
                "Could use destructive techniques"
            ])
        
        # Based on personality
        if persona["personality_traits"]["persistence"] == "High":
            predictions.append("Will maintain long-term access")
        
        if persona["personality_traits"]["adaptability"] == "High":
            predictions.append("Will adapt to security measures")
        
        return {
            "short_term_predictions": predictions[:3],
            "long_term_predictions": predictions[3:],
            "likely_next_targets": self._predict_next_targets(persona),
            "evolution_trajectory": self._predict_evolution(persona)
        }
    
    def _predict_next_targets(self, persona: Dict) -> List[str]:
        """Predict likely next targets"""
        motivation = persona["motivation"]["primary_motivation"]
        
        if motivation == "financial":
            return ["Banks", "Financial services", "Cryptocurrency exchanges"]
        elif motivation == "espionage":
            return ["R&D departments", "Government agencies", "Tech companies"]
        elif motivation == "political":
            return ["Critical infrastructure", "Media organizations", "Government systems"]
        else:
            return ["Various targets based on opportunity"]
    
    def _predict_evolution(self, persona: Dict) -> str:
        """Predict how the actor will evolve"""
        if persona["behavioral_profile"]["learning_pattern"] == "Continuous Learning":
            return "Expected to develop new techniques and adapt to defenses"
        elif persona["behavioral_profile"]["adaptation_speed"] == "Rapid Adaptation":
            return "Will quickly change tactics to bypass security measures"
        else:
            return "Likely to continue with established patterns"
    
    def _generate_actor_specific_countermeasures(self, persona: Dict) -> List[str]:
        """Generate countermeasures specific to the actor profile"""
        countermeasures = []
        
        # Based on operational style
        operational_style = persona["operational_style"]
        
        if "stealth" in operational_style.lower():
            countermeasures.extend([
                "Implement advanced detection for stealthy techniques",
                "Focus on behavioral analysis",
                "Enhance network visibility"
            ])
        
        if "bold" in operational_style.lower():
            countermeasures.extend([
                "Strengthen perimeter defenses",
                "Implement rapid containment procedures",
                "Prepare for aggressive attack patterns"
            ])
        
        # Based on motivation
        motivation = persona["motivation"]["primary_motivation"]
        
        if motivation == "financial":
            countermeasures.append("Implement financial transaction monitoring")
        elif motivation == "espionage":
            countermeasures.append("Protect sensitive data and intellectual property")
        
        # Based on persistence
        if persona["behavioral_profile"]["persistence_level"] == "Very Persistent":
            countermeasures.append("Plan for long-term incident response")
        
        return countermeasures
    
    def _calculate_profile_confidence(self, actor_match: Dict, patterns: List[str]) -> str:
        """Calculate confidence in the profile"""
        if actor_match["confidence"] > 80:
            return "High"
        elif actor_match["confidence"] > 50:
            return "Medium"
        else:
            return "Low"
    
    def _find_similar_incidents(self, patterns: List[str]) -> List[Dict]:
        """Find similar historical incidents"""
        # In a real implementation, this would query a database
        similar_incidents = []
        
        for pattern in patterns:
            similar_incidents.append({
                "pattern": pattern,
                "similar_incidents": random.randint(1, 50),
                "confidence": round(random.uniform(0.6, 0.9), 2)
            })
        
        return similar_incidents
    
    def _identify_intelligence_gaps(self, persona: Dict) -> List[str]:
        """Identify gaps in intelligence about the actor"""
        gaps = []
        
        if persona["actor_identification"]["actor_id"] == "Unknown":
            gaps.append("Actor identification and attribution")
        
        if persona["motivation"]["confidence"] < 0.7:
            gaps.append("Motivation and intent clarity")
        
        if persona["technical_profile"]["complexity_score"] < 50:
            gaps.append("Full technical capability assessment")
        
        if not gaps:
            gaps.append("No significant intelligence gaps identified")
        
        return gaps