"""
Advanced LLM Intent Parser with Enhanced Natural Language Understanding
Provides sophisticated intent classification, entity extraction, and query understanding
"""

import re
import json
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass
from datetime import datetime


class IntentType(Enum):
    """Comprehensive intent types for security queries"""
    IOC_LOOKUP = "ioc_lookup"
    INCIDENT_INVESTIGATION = "incident_investigation"
    THREAT_HUNTING = "threat_hunting"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    MALWARE_ANALYSIS = "malware_analysis"
    NETWORK_ANALYSIS = "network_analysis"
    FORENSIC_INVESTIGATION = "forensic_investigation"
    COMPLIANCE_CHECK = "compliance_check"
    SECURITY_POSTURE = "security_posture"
    TOOL_EXPLANATION = "tool_explanation"
    GENERAL_QUESTION = "general_question"
    CONVERSATIONAL = "conversational"
    ALERT_TRIAGE = "alert_triage"
    THREAT_INTELLIGENCE = "threat_intelligence"
    INCIDENT_RESPONSE = "incident_response"
    LOG_ANALYSIS = "log_analysis"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"


class QueryType(Enum):
    """Detailed query types for granular analysis"""
    IP_REPUTATION = "ip_reputation"
    DOMAIN_REPUTATION = "domain_reputation"
    URL_ANALYSIS = "url_analysis"
    HASH_ANALYSIS = "hash_analysis"
    EMAIL_ANALYSIS = "email_analysis"
    ALERT_INVESTIGATION = "alert_investigation"
    ATTACK_PATTERN_ANALYSIS = "attack_pattern_analysis"
    VULNERABILITY_SCAN = "vulnerability_scan"
    MALWARE_DETECTION = "malware_detection"
    NETWORK_TRAFFIC = "network_traffic"
    SYSTEM_COMPROMISE = "system_compromise"
    DATA_BREACH = "data_breach"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE_MECHANISM = "persistence_mechanism"
    EXFILTRATION_DETECTION = "exfiltration_detection"
    C2_COMMUNICATION = "c2_communication"
    THREAT_ACTOR_ATTRIBUTION = "threat_actor_attribution"
    CAMPAIGN_ANALYSIS = "campaign_analysis"
    MITRE_MAPPING = "mitre_mapping"
    COMPLIANCE_AUDIT = "compliance_audit"
    RISK_ASSESSMENT = "risk_assessment"
    SECURITY_METRICS = "security_metrics"
    KNOWLEDGE_QUERY = "knowledge_query"
    HELP_GUIDANCE = "help_guidance"


class ConfidenceLevel(Enum):
    """Confidence levels for predictions"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Entity:
    """Extracted entity from query"""
    type: str
    value: str
    confidence: float
    start_pos: int
    end_pos: int


@dataclass
class IntentResult:
    """Result of intent parsing"""
    intent: IntentType
    query_type: QueryType
    confidence: ConfidenceLevel
    entities: List[Entity]
    tool_requirements: List[str]
    reasoning: str
    suggested_actions: List[str]
    risk_level: str
    urgency: str


class LLMIntentParser:
    """
    Advanced LLM Intent Parser with multi-level analysis
    Combines rule-based pattern matching with ML-like scoring
    """
    
    def __init__(self):
        self.intent_patterns = self._initialize_intent_patterns()
        self.entity_patterns = self._initialize_entity_patterns()
        self.tool_mapping = self._initialize_tool_mapping()
        self.query_keywords = self._initialize_query_keywords()
        
    def _initialize_intent_patterns(self) -> Dict[str, List[str]]:
        """Initialize comprehensive intent patterns"""
        return {
            IntentType.IOC_LOOKUP.value: [
                r'check\s+(?:ip|domain|url|hash|email)',
                r'lookup\s+(?:ip|domain|url|hash)',
                r'reputation\s+(?:of\s+)?(?:ip|domain|url)',
                r'virustotal\s+(?:check|lookup)',
                r'analyze\s+(?:ip|domain|url|hash)',
                r'investigate\s+(?:ip|domain|url|hash)',
                r'\b(?:vt|virustotal)\b',
                r'is\s+(?:this\s+)?(?:ip|domain|url)\s+(?:malicious|suspicious|safe)',
                r'check\s+reputation'
            ],
            IntentType.INCIDENT_INVESTIGATION.value: [
                r'investigate\s+alert\s+#?\d+',
                r'analyze\s+alert\s+#?\d+',
                r'triage\s+alert',
                r'incident\s+investigation',
                r'security\s+incident',
                r'alert\s+analysis',
                r'investigate\s+event',
                r'security\s+event'
            ],
            IntentType.THREAT_HUNTING.value: [
                r'hunt\s+(?:for\s+)?(?:threats?|ioc|indicators)',
                r'threat\s+hunt',
                r'active\s+(?:threat|hunting)',
                r'search\s+(?:for\s+)?(?:threats?|malicious)',
                r'proactive\s+(?:threat|security)',
                r'find\s+(?:new\s+)?(?:threats?|attacks)',
                r'IOC\s+hunt',
                r'indicator\s+hunt'
            ],
            IntentType.VULNERABILITY_ASSESSMENT.value: [
                r'vulnerability\s+(?:scan|assessment|check)',
                r'CVE\s+(?:lookup|search|check)',
                r'security\s+(?:patch|update)\s+(?:status|check)',
                r'check\s+(?:for\s+)?vulnerabilities',
                r'scan\s+(?:for\s+)?(?:vulns?|cve)',
                r'assess\s+(?:security\s+)?(?:vulnerability|risk)',
                r'patch\s+(?:management|status)'
            ],
            IntentType.MALWARE_ANALYSIS.value: [
                r'malware\s+(?:analysis|detection|check)',
                r'analyze\s+(?:file|sample|executable)',
                r'check\s+(?:file|sample)\s+(?:for\s+)?malware',
                r'ransomware\s+(?:analysis|detection)',
                r'trojan\s+(?:analysis|check)',
                r'virus\s+(?:scan|check|detection)',
                r'suspicious\s+(?:file|process|behavior)',
                r'file\s+(?:analysis|hash\s+check)'
            ],
            IntentType.NETWORK_ANALYSIS.value: [
                r'network\s+(?:analysis|traffic|investigation)',
                r'analyze\s+network\s+(?:traffic|activity)',
                r'check\s+network\s+(?:connections|traffic)',
                r'communication\s+(?:pattern|analysis)',
                r'C2\s+(?:detection|analysis|communication)',
                r'command\s+and\s+control',
                r'network\s+behavior'
            ],
            IntentType.FORENSIC_INVESTIGATION.value: [
                r'forensic\s+(?:analysis|investigation)',
                r'digital\s+forensics',
                r'analyze\s+(?:logs?|evidence|artifacts)',
                r'log\s+(?:analysis|investigation)',
                r'investigate\s+(?:logs?|evidence)',
                r'extract\s+(?:evidence|artifacts)',
                r'chain\s+of\s+custody'
            ],
            IntentType.COMPLIANCE_CHECK.value: [
                r'compliance\s+(?:check|audit|status)',
                r'GDPR\s+(?:compliance|check)',
                r'HIPAA\s+(?:compliance|audit)',
                r'PCI\s+DSS\s+(?:compliance|check)',
                r'security\s+(?:policy|standard)\s+(?:check|compliance)',
                r'audit\s+(?:security|compliance)',
                r'regulatory\s+(?:compliance|check)'
            ],
            IntentType.SECURITY_POSTURE.value: [
                r'security\s+posture',
                r'overall\s+security\s+(?:status|health)',
                r'security\s+(?:health|assessment)',
                r'risk\s+(?:assessment|posture)',
                r'security\s+metrics',
                r'organizational\s+security'
            ],
            IntentType.TOOL_EXPLANATION.value: [
                r'what\s+is\s+(?:virustotal|wazuh|misp|shodan|mcp)',
                r'how\s+does\s+(?:virustotal|wazuh|misp|shodan)',
                r'explain\s+(?:virustotal|wazuh|misp|shodan)',
                r'(?:virustotal|wazuh|misp|shodan)\s+(?:overview|explanation)',
                r'tool\s+(?:explanation|overview|description)'
            ],
            IntentType.ALERT_TRIAGE.value: [
                r'triage\s+alert',
                r'prioritize\s+alert',
                r'assess\s+alert\s+(?:severity|priority)',
                r'alert\s+(?:severity|priority)\s+(?:check|assessment)',
                r'rank\s+alerts?',
                r'alert\s+classification'
            ],
            IntentType.THREAT_INTELLIGENCE.value: [
                r'threat\s+intel(?:ligence)?',
                r'CTI\s+(?:analysis|lookup)',
                r'attack\s+(?:pattern|tactic|technique)',
                r'TTP\s+(?:analysis|mapping)',
                r'indicator\s+(?:intelligence|analysis)',
                r'adversary\s+(?:analysis|attribution)'
            ],
            IntentType.INCIDENT_RESPONSE.value: [
                r'incident\s+response',
                r'contain\s+(?:threat|incident)',
                r'mitigate\s+(?:attack|threat)',
                r'respond\s+to\s+(?:incident|attack)',
                r'IR\s+(?:plan|procedure)',
                r'incident\s+(?:handling|management)'
            ],
            IntentType.LOG_ANALYSIS.value: [
                r'log\s+(?:analysis|investigation)',
                r'analyze\s+logs?',
                r'investigate\s+logs?',
                r'security\s+log\s+(?:analysis|review)',
                r'event\s+log\s+(?:analysis|investigation)',
                r'parse\s+logs?'
            ],
            IntentType.BEHAVIORAL_ANALYSIS.value: [
                r'behavioral\s+(?:analysis|pattern)',
                r'user\s+behavior\s+(?:analysis|anomaly)',
                r'entity\s+behavior',
                r'behavior\s+(?:pattern|anomaly)\s+(?:detection|analysis)',
                r'abnormal\s+behavior'
            ],
            IntentType.GENERAL_QUESTION.value: [
                r'what\s+is',
                r'how\s+does',
                r'explain',
                r'define',
                r'concept',
                r'meaning',
                r'(?:(?:can|could|would|should)\s+you)\s+(?:explain|tell|describe)',
                r'(?:(?:help|info|information)\s+about)\s+\w+'
            ],
            IntentType.CONVERSATIONAL.value: [
                r'^(hi|hello|hey|greetings?)',
                r'(?:(?:good|bad)\s+(?:morning|afternoon|evening))',
                r'thank(s|you)',
                r'(?:(?:who|what)\s+are\s+you)',
                r'(?:(?:can|could)\s+you\s+help)',
                r'(?:(?:I\'m|i am)\s+(?:done|finished))',
                r'(?:bye|goodbye|see you)'
            ]
        }
    
    def _initialize_entity_patterns(self) -> Dict[str, str]:
        """Initialize entity extraction patterns"""
        return {
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'ipv6_address': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'domain': r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
            'url': r'\bhttps?://[^\s<>"{}|\\^`\[\]]+\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'hash_md5': r'\b[a-fA-F0-9]{32}\b',
            'hash_sha1': r'\b[a-fA-F0-9]{40}\b',
            'hash_sha256': r'\b[a-fA-F0-9]{64}\b',
            'alert_id': r'\b(?:alert|incident|case)?\s*#?\s*\d{3,6}\b',
            'cve': r'\bCVE-\d{4}-\d{4,7}\b',
            'port': r'\b(?:port|:)\s*\d{1,5}\b',
            'mac_address': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
            'hostname': r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b',
            'file_path': r'\b(?:[a-zA-Z]:)?[\\/][\w-\\./]+\b',
            'user_account': r'\b(?:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+|\\[a-zA-Z0-9._-]+)\b',
            'process_name': r'\b[\w-]+\.exe\b|\b[\w-]+\.dll\b|\b[\w-]+\.bin\b',
            'registry_key': r'\b[HKEY_][A-Z_]+\\[^\s]+\b',
            'mitre_id': r'\bT\d{4}(?:\.\d{3})?\b'
        }
    
    def _initialize_tool_mapping(self) -> Dict[str, List[str]]:
        """Initialize tool requirement mapping"""
        return {
            IntentType.IOC_LOOKUP.value: ['VirusTotal'],
            IntentType.INCIDENT_INVESTIGATION.value: ['Wazuh', 'VirusTotal', 'MISP', 'Shodan'],
            IntentType.THREAT_HUNTING.value: ['Wazuh', 'VirusTotal', 'MISP'],
            IntentType.VULNERABILITY_ASSESSMENT.value: ['Wazuh', 'Shodan'],
            IntentType.MALWARE_ANALYSIS.value: ['VirusTotal', 'MISP'],
            IntentType.NETWORK_ANALYSIS.value: ['Wazuh', 'Shodan'],
            IntentType.FORENSIC_INVESTIGATION.value: ['Wazuh', 'VirusTotal', 'MISP'],
            IntentType.THREAT_INTELLIGENCE.value: ['MISP', 'VirusTotal'],
            IntentType.ALERT_TRIAGE.value: ['Wazuh', 'VirusTotal'],
            IntentType.LOG_ANALYSIS.value: ['Wazuh'],
            IntentType.BEHAVIORAL_ANALYSIS.value: ['Wazuh', 'MISP'],
            IntentType.INCIDENT_RESPONSE.value: ['Wazuh', 'VirusTotal', 'MISP'],
            IntentType.GENERAL_QUESTION.value: [],
            IntentType.TOOL_EXPLANATION.value: [],
            IntentType.CONVERSATIONAL.value: [],
            IntentType.COMPLIANCE_CHECK.value: ['Wazuh'],
            IntentType.SECURITY_POSTURE.value: ['Wazuh', 'VirusTotal']
        }
    
    def _initialize_query_keywords(self) -> Dict[str, List[str]]:
        """Initialize query type specific keywords"""
        return {
            QueryType.IP_REPUTATION.value: ['ip', 'address', 'reputation', 'virustotal'],
            QueryType.DOMAIN_REPUTATION.value: ['domain', 'website', 'reputation'],
            QueryType.URL_ANALYSIS.value: ['url', 'link', 'website', 'reputation'],
            QueryType.HASH_ANALYSIS.value: ['hash', 'file', 'sample', 'md5', 'sha256', 'sha1'],
            QueryType.EMAIL_ANALYSIS.value: ['email', 'phishing', 'sender'],
            QueryType.ALERT_INVESTIGATION.value: ['alert', 'incident', 'event', 'security'],
            QueryType.ATTACK_PATTERN_ANALYSIS.value: ['attack', 'pattern', 'technique', 'tactic'],
            QueryType.VULNERABILITY_SCAN.value: ['vulnerability', 'cve', 'scan', 'patch'],
            QueryType.MALWARE_DETECTION.value: ['malware', 'virus', 'trojan', 'ransomware'],
            QueryType.NETWORK_TRAFFIC.value: ['network', 'traffic', 'connection', 'communication'],
            QueryType.SYSTEM_COMPROMISE.value: ['compromise', 'breach', 'hack', 'attack'],
            QueryType.DATA_BREACH.value: ['breach', 'exfiltration', 'data leak'],
            QueryType.LATERAL_MOVEMENT.value: ['lateral', 'movement', 'spread', 'propagation'],
            QueryType.PRIVILEGE_ESCALATION.value: ['privilege', 'escalation', 'admin', 'root'],
            QueryType.PERSISTENCE_MECHANISM.value: ['persistence', 'startup', 'registry', 'service'],
            QueryType.EXFILTRATION_DETECTION.value: ['exfiltration', 'data transfer', 'upload'],
            QueryType.C2_COMMUNICATION.value: ['c2', 'command', 'control', 'beacon'],
            QueryType.THREAT_ACTOR_ATTRIBUTION.value: ['actor', 'attribution', 'apt', 'group'],
            QueryType.CAMPAIGN_ANALYSIS.value: ['campaign', 'operation', 'threat'],
            QueryType.MITRE_MAPPING.value: ['mitre', 'att&ck', 'tactic', 'technique'],
            QueryType.COMPLIANCE_AUDIT.value: ['compliance', 'audit', 'policy', 'standard'],
            QueryType.RISK_ASSESSMENT.value: ['risk', 'assessment', 'threat', 'vulnerability'],
            QueryType.SECURITY_METRICS.value: ['metrics', 'statistics', 'kpi', 'measurements'],
            QueryType.KNOWLEDGE_QUERY.value: ['what', 'how', 'explain', 'define', 'concept'],
            QueryType.HELP_GUIDANCE.value: ['help', 'guide', 'instruction', 'how to']
        }
    
    def parse_query(self, query: str) -> IntentResult:
        """
        Parse security query with advanced NLP techniques
        
        Args:
            query: User's security query
            
        Returns:
            IntentResult with comprehensive analysis
        """
        query_lower = query.lower().strip()
        
        # Step 1: Extract entities
        entities = self._extract_entities(query)
        
        # Step 2: Determine intent
        intent, intent_confidence = self._classify_intent(query_lower, entities)
        
        # Step 3: Determine query type
        query_type = self._classify_query_type(query_lower, entities, intent)
        
        # Step 4: Determine tool requirements
        tool_requirements = self._determine_tool_requirements(intent, entities)
        
        # Step 5: Generate reasoning
        reasoning = self._generate_reasoning(intent, query_type, entities, tool_requirements)
        
        # Step 6: Suggest actions
        suggested_actions = self._suggest_actions(intent, query_type, entities)
        
        # Step 7: Assess risk level
        risk_level = self._assess_risk_level(intent, entities, query_lower)
        
        # Step 8: Determine urgency
        urgency = self._determine_urgency(intent, risk_level, query_lower)
        
        return IntentResult(
            intent=intent,
            query_type=query_type,
            confidence=intent_confidence,
            entities=entities,
            tool_requirements=tool_requirements,
            reasoning=reasoning,
            suggested_actions=suggested_actions,
            risk_level=risk_level,
            urgency=urgency
        )
    
    def _extract_entities(self, query: str) -> List[Entity]:
        """Extract all entities from the query"""
        entities = []
        
        for entity_type, pattern in self.entity_patterns.items():
            for match in re.finditer(pattern, query, re.IGNORECASE):
                entity = Entity(
                    type=entity_type,
                    value=match.group(),
                    confidence=self._calculate_entity_confidence(entity_type, match.group()),
                    start_pos=match.start(),
                    end_pos=match.end()
                )
                entities.append(entity)
        
        # Sort by confidence and remove duplicates
        entities = sorted(entities, key=lambda x: x.confidence, reverse=True)
        seen = set()
        unique_entities = []
        for entity in entities:
            if entity.value.lower() not in seen:
                seen.add(entity.value.lower())
                unique_entities.append(entity)
        
        return unique_entities
    
    def _calculate_entity_confidence(self, entity_type: str, value: str) -> float:
        """Calculate confidence score for extracted entity"""
        base_confidence = 0.8
        
        # Adjust based on entity type specificity
        type_confidence = {
            'ip_address': 0.95,
            'ipv6_address': 0.95,
            'domain': 0.90,
            'url': 0.95,
            'email': 0.90,
            'hash_md5': 0.95,
            'hash_sha1': 0.95,
            'hash_sha256': 0.95,
            'alert_id': 0.85,
            'cve': 0.95,
            'port': 0.70,
            'mac_address': 0.90,
            'hostname': 0.75,
            'file_path': 0.80,
            'user_account': 0.75,
            'process_name': 0.80,
            'registry_key': 0.85,
            'mitre_id': 0.95
        }
        
        confidence = type_confidence.get(entity_type, base_confidence)
        
        # Adjust based on value characteristics
        if entity_type in ['ip_address', 'ipv6_address']:
            if self._is_private_ip(value):
                confidence -= 0.1
        elif entity_type == 'domain':
            if value.lower() in ['localhost', 'example.com', 'test.com']:
                confidence -= 0.3
        
        return max(0.1, min(1.0, confidence))
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        private_ranges = [
            (r'10\.', 0),
            (r'172\.(1[6-9]|2[0-9]|3[0-1])\.', 0),
            (r'192\.168\.', 0),
            (r'127\.', 0),
            (r'169\.254\.', 0)
        ]
        
        for pattern, _ in private_ranges:
            if re.match(pattern, ip):
                return True
        return False
    
    def _classify_intent(self, query: str, entities: List[Entity]) -> Tuple[IntentType, ConfidenceLevel]:
        """Classify the primary intent of the query"""
        intent_scores = {}
        
        # Score each intent based on pattern matches
        for intent, patterns in self.intent_patterns.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, query, re.IGNORECASE):
                    score += 1
            intent_scores[intent] = score
        
        # Boost scores based on entities
        for entity in entities:
            if entity.type in ['ip_address', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256']:
                intent_scores[IntentType.IOC_LOOKUP.value] += 2
            elif entity.type == 'alert_id':
                intent_scores[IntentType.INCIDENT_INVESTIGATION.value] += 2
            elif entity.type == 'cve':
                intent_scores[IntentType.VULNERABILITY_ASSESSMENT.value] += 2
            elif entity.type == 'mitre_id':
                intent_scores[IntentType.THREAT_INTELLIGENCE.value] += 2
        
        # Find highest scoring intent
        if not intent_scores or max(intent_scores.values()) == 0:
            return IntentType.GENERAL_QUESTION, ConfidenceLevel.LOW
        
        max_intent = max(intent_scores, key=intent_scores.get)
        max_score = intent_scores[max_intent]
        
        # Determine confidence level
        if max_score >= 3:
            confidence = ConfidenceLevel.HIGH
        elif max_score >= 2:
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.LOW
        
        return IntentType(max_intent), confidence
    
    def _classify_query_type(self, query: str, entities: List[Entity], intent: IntentType) -> QueryType:
        """Classify the specific query type"""
        query_type_scores = {}
        
        # Score each query type based on keywords
        for query_type, keywords in self.query_keywords.items():
            score = 0
            for keyword in keywords:
                if keyword in query:
                    score += 1
            query_type_scores[query_type] = score
        
        # Boost based on entities
        for entity in entities:
            if entity.type == 'ip_address':
                query_type_scores[QueryType.IP_REPUTATION.value] += 3
            elif entity.type == 'domain':
                query_type_scores[QueryType.DOMAIN_REPUTATION.value] += 3
            elif entity.type == 'url':
                query_type_scores[QueryType.URL_ANALYSIS.value] += 3
            elif entity.type in ['hash_md5', 'hash_sha1', 'hash_sha256']:
                query_type_scores[QueryType.HASH_ANALYSIS.value] += 3
            elif entity.type == 'email':
                query_type_scores[QueryType.EMAIL_ANALYSIS.value] += 3
            elif entity.type == 'alert_id':
                query_type_scores[QueryType.ALERT_INVESTIGATION.value] += 3
            elif entity.type == 'cve':
                query_type_scores[QueryType.VULNERABILITY_SCAN.value] += 3
            elif entity.type == 'mitre_id':
                query_type_scores[QueryType.MITRE_MAPPING.value] += 3
        
        # Find highest scoring query type
        if not query_type_scores or max(query_type_scores.values()) == 0:
            return QueryType.KNOWLEDGE_QUERY
        
        return QueryType(max(query_type_scores, key=query_type_scores.get))
    
    def _determine_tool_requirements(self, intent: IntentType, entities: List[Entity]) -> List[str]:
        """Determine which security tools are required"""
        base_tools = self.tool_mapping.get(intent.value, [])
        
        # Enhance based on entities
        for entity in entities:
            if entity.type in ['ip_address', 'domain', 'url']:
                if 'VirusTotal' not in base_tools:
                    base_tools.append('VirusTotal')
            elif entity.type in ['hash_md5', 'hash_sha1', 'hash_sha256']:
                if 'VirusTotal' not in base_tools:
                    base_tools.append('VirusTotal')
            elif entity.type == 'ip_address':
                if 'Shodan' not in base_tools:
                    base_tools.append('Shodan')
        
        return list(set(base_tools))
    
    def _generate_reasoning(self, intent: IntentType, query_type: QueryType, 
                           entities: List[Entity], tools: List[str]) -> str:
        """Generate human-readable reasoning for the classification"""
        reasoning_parts = []
        
        # Intent reasoning
        reasoning_parts.append(f"Classified as {intent.value.replace('_', ' ')} intent")
        
        # Query type reasoning
        reasoning_parts.append(f"Query type identified as {query_type.value.replace('_', ' ')}")
        
        # Entity reasoning
        if entities:
            entity_types = ', '.join(set(e.type for e in entities))
            reasoning_parts.append(f"Extracted entities: {entity_types}")
        
        # Tool reasoning
        if tools:
            reasoning_parts.append(f"Requires tools: {', '.join(tools)}")
        else:
            reasoning_parts.append("No external tools required - can be answered from knowledge base")
        
        return '. '.join(reasoning_parts) + '.'
    
    def _suggest_actions(self, intent: IntentType, query_type: QueryType, 
                         entities: List[Entity]) -> List[str]:
        """Suggest appropriate actions based on the query"""
        actions = []
        
        if intent == IntentType.IOC_LOOKUP:
            actions.append("Query threat intelligence databases for IOC reputation")
            actions.append("Check historical analysis and detection ratios")
            actions.append("Identify related campaigns and threat actors")
        elif intent == IntentType.INCIDENT_INVESTIGATION:
            actions.append("Gather all available telemetry and logs")
            actions.append("Identify attack timeline and affected systems")
            actions.append("Correlate with threat intelligence sources")
            actions.append("Assess impact and determine containment strategy")
        elif intent == IntentType.THREAT_HUNTING:
            actions.append("Search for similar patterns across the environment")
            actions.append("Identify potential compromise indicators")
            actions.append("Review historical data for related activity")
        elif intent == IntentType.VULNERABILITY_ASSESSMENT:
            actions.append("Check current patch status and vulnerability exposure")
            actions.append("Assess potential attack surface")
            actions.append("Prioritize patching based on risk and exploitability")
        elif intent == IntentType.MALWARE_ANALYSIS:
            actions.append("Perform deep behavioral analysis")
            actions.append("Identify persistence mechanisms")
            actions.append("Determine communication channels and exfiltration paths")
        elif intent == IntentType.NETWORK_ANALYSIS:
            actions.append("Analyze network traffic patterns")
            actions.append("Identify suspicious connections and data transfers")
            actions.append("Map network topology and lateral movement")
        elif intent == IntentType.FORENSIC_INVESTIGATION:
            actions.append("Preserve evidence and maintain chain of custody")
            actions.append("Extract and analyze artifacts")
            actions.append("Reconstruct timeline of events")
        elif intent == IntentType.INCIDENT_RESPONSE:
            actions.append("Activate appropriate response playbook")
            actions.append("Implement containment measures")
            actions.append("Begin eradication and recovery procedures")
        
        # Add entity-specific actions
        for entity in entities:
            if entity.type == 'ip_address':
                actions.append(f"Conduct geolocation and network analysis for {entity.value}")
            elif entity.type == 'hash':
                actions.append(f"Perform deep malware analysis for {entity.value}")
            elif entity.type == 'domain':
                actions.append(f"Analyze domain infrastructure and history for {entity.value}")
        
        return actions[:5]  # Limit to top 5 suggestions
    
    def _assess_risk_level(self, intent: IntentType, entities: List[Entity], query: str) -> str:
        """Assess the risk level implied by the query"""
        high_risk_keywords = ['compromise', 'breach', 'attack', 'hack', 'malware', 
                           'ransomware', 'critical', 'severe', 'emergency']
        medium_risk_keywords = ['suspicious', 'unusual', 'anomaly', 'alert', 'warning']
        
        for keyword in high_risk_keywords:
            if keyword in query:
                return 'Critical'
        
        for keyword in medium_risk_keywords:
            if keyword in query:
                return 'Medium'
        
        # Check entity types
        high_risk_entities = ['hash_md5', 'hash_sha1', 'hash_sha256', 'cve']
        for entity in entities:
            if entity.type in high_risk_entities:
                return 'High'
        
        # Default based on intent
        if intent in [IntentType.INCIDENT_INVESTIGATION, IntentType.MALWARE_ANALYSIS]:
            return 'High'
        elif intent in [IntentType.THREAT_HUNTING, IntentType.VULNERABILITY_ASSESSMENT]:
            return 'Medium'
        else:
            return 'Low'
    
    def _determine_urgency(self, intent: IntentType, risk_level: str, query: str) -> str:
        """Determine the urgency level of the query"""
        urgent_keywords = ['immediate', 'urgent', 'emergency', 'critical', 'asap', 'now']
        
        for keyword in urgent_keywords:
            if keyword in query:
                return 'Immediate'
        
        if risk_level == 'Critical':
            return 'High'
        elif risk_level == 'High':
            return 'Medium'
        elif intent in [IntentType.INCIDENT_INVESTIGATION, IntentType.MALWARE_ANALYSIS]:
            return 'Medium'
        else:
            return 'Normal'
    
    def get_query_summary(self, query: str) -> Dict[str, Any]:
        """Get a comprehensive summary of the query analysis"""
        result = self.parse_query(query)
        
        return {
            'original_query': query,
            'intent': result.intent.value,
            'query_type': result.query_type.value,
            'confidence': result.confidence.value,
            'entities': [
                {
                    'type': e.type,
                    'value': e.value,
                    'confidence': e.confidence
                }
                for e in result.entities
            ],
            'required_tools': result.tool_requirements,
            'reasoning': result.reasoning,
            'suggested_actions': result.suggested_actions,
            'risk_level': result.risk_level,
            'urgency': result.urgency,
            'timestamp': datetime.utcnow().isoformat()
        }


# Singleton instance for easy access
intent_parser = LLMIntentParser()