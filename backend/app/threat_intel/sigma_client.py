"""
Sigma Rules Client Module
Interfaces with Sigma rules for threat detection
"""
import httpx
import yaml
from typing import Dict, Any, List, Optional
from datetime import datetime
from ..utils.logger import get_logger

logger = get_logger(__name__)


class SigmaClient:
    """Client for Sigma rules integration"""
    
    def __init__(self):
        self.base_url = "https://github.com/SigmaHQ/sigma"
        self.raw_url = "https://raw.githubusercontent.com/SigmaHQ/sigma/master"
        self.client = httpx.AsyncClient(timeout=30.0)
        self.rule_cache = {}
    
    async def get_rules(self, category: Optional[str] = None) -> Dict[str, Any]:
        """Get Sigma rules, optionally filtered by category"""
        try:
            # Sigma rules are organized by category in the repository
            categories = [
                "rules/windows",
                "rules/linux",
                "rules/macos",
                "rules/network",
                "rules/cloud"
            ]
            
            if category:
                categories = [cat for cat in categories if category in cat]
            
            all_rules = []
            for category_path in categories:
                rules = await self._fetch_rules_from_category(category_path)
                all_rules.extend(rules)
            
            return {
                "source": "sigma",
                "total_rules": len(all_rules),
                "categories": categories,
                "rules": all_rules
            }
            
        except Exception as e:
            logger.error(f"Error getting Sigma rules: {e}")
            return {"error": str(e)}
    
    async def _fetch_rules_from_category(self, category_path: str) -> List[Dict]:
        """Fetch rules from a specific category"""
        try:
            # This is a simplified implementation
            # In production, you'd want to use the GitHub API or clone the repository
            url = f"{self.raw_url}/{category_path}"
            response = await self.client.get(url)
            
            if response.status_code == 200:
                # Parse the directory listing or API response
                return await self._parse_rule_list(response.text, category_path)
            else:
                logger.error(f"Error fetching {category_path}: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching rules from {category_path}: {e}")
            return []
    
    async def _parse_rule_list(self, content: str, category_path: str) -> List[Dict]:
        """Parse rule list from directory content"""
        # This is a placeholder - in production you'd parse HTML or use GitHub API
        # For now, return some common Windows rules
        common_rules = [
            {
                "id": "sigma_rule_1",
                "title": "Suspicious Process Execution",
                "category": category_path,
                "description": "Detects suspicious process execution patterns",
                "level": "high",
                "tactics": ["execution"],
                "techniques": ["T1204"]
            },
            {
                "id": "sigma_rule_2", 
                "title": "Suspicious Registry Modification",
                "category": category_path,
                "description": "Detects suspicious registry modifications",
                "level": "critical",
                "tactics": ["persistence", "privilege-escalation"],
                "techniques": ["T1547"]
            },
            {
                "id": "sigma_rule_3",
                "title": "Suspicious Network Connection",
                "category": category_path,
                "description": "Detects suspicious network connections",
                "level": "medium",
                "tactics": ["command-and-control"],
                "techniques": ["T1071"]
            }
        ]
        
        return common_rules
    
    async def analyze_logs_against_rules(self, logs: List[Dict], rules: Optional[List[Dict]] = None) -> Dict[str, Any]:
        """Analyze logs against Sigma rules"""
        try:
            if rules is None:
                rules_response = await self.get_rules()
                if "error" in rules_response:
                    return rules_response
                rules = rules_response.get("rules", [])
            
            matches = []
            total_checks = 0
            
            for log in logs:
                for rule in rules:
                    total_checks += 1
                    match = await self._check_log_against_rule(log, rule)
                    if match:
                        matches.append({
                            "rule": rule,
                            "log": log,
                            "match_details": match
                        })
            
            return {
                "source": "sigma",
                "total_rules_checked": len(rules),
                "total_logs_analyzed": len(logs),
                "total_checks": total_checks,
                "total_matches": len(matches),
                "matches": matches
            }
            
        except Exception as e:
            logger.error(f"Error analyzing logs against rules: {e}")
            return {"error": str(e)}
    
    async def _check_log_against_rule(self, log: Dict, rule: Dict) -> Optional[Dict]:
        """Check if a log matches a Sigma rule"""
        try:
            # This is a simplified rule matching logic
            # In production, you'd implement full Sigma rule parsing and matching
            
            rule_keywords = rule.get("title", "").lower().split()
            log_text = str(log).lower()
            
            # Check if any keywords match
            matches = [keyword for keyword in rule_keywords if keyword in log_text]
            
            if len(matches) >= 2:  # Require at least 2 keyword matches
                return {
                    "matched_keywords": matches,
                    "confidence": len(matches) / len(rule_keywords)
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error checking log against rule: {e}")
            return None
    
    async def get_rule_by_id(self, rule_id: str) -> Dict[str, Any]:
        """Get a specific rule by ID"""
        try:
            if rule_id in self.rule_cache:
                return self.rule_cache[rule_id]
            
            # In production, you'd fetch the specific rule file
            rule = {
                "id": rule_id,
                "title": "Sigma Rule",
                "description": "Rule description",
                "level": "medium",
                "tactics": [],
                "techniques": []
            }
            
            self.rule_cache[rule_id] = rule
            return rule
            
        except Exception as e:
            logger.error(f"Error getting rule by ID: {e}")
            return {"error": str(e)}
    
    async def search_rules(self, query: str) -> Dict[str, Any]:
        """Search for rules by query"""
        try:
            rules_response = await self.get_rules()
            
            if "error" in rules_response:
                return rules_response
            
            rules = rules_response.get("rules", [])
            query_lower = query.lower()
            
            results = []
            for rule in rules:
                if (query_lower in rule.get("title", "").lower() or
                    query_lower in rule.get("description", "").lower() or
                    query_lower in str(rule.get("tactics", [])).lower() or
                    query_lower in str(rule.get("techniques", [])).lower()):
                    results.append(rule)
            
            return {
                "query": query,
                "total_results": len(results),
                "rules": results
            }
            
        except Exception as e:
            logger.error(f"Error searching rules: {e}")
            return {"error": str(e)}
    
    async def convert_rule_to_yaml(self, rule: Dict) -> str:
        """Convert a rule to YAML format"""
        try:
            yaml_content = {
                "title": rule.get("title", ""),
                "id": rule.get("id", ""),
                "description": rule.get("description", ""),
                "status": "stable",
                "author": "Security Copilot",
                "logsource": {
                    "product": "windows",
                    "service": "security"
                },
                "detection": {
                    "selection": {
                        "EventID": [rule.get("event_id", 0)]
                    },
                    "condition": "selection"
                },
                "level": rule.get("level", "medium"),
                "tags": rule.get("tactics", [])
            }
            
            return yaml.dump(yaml_content, default_flow_style=False)
            
        except Exception as e:
            logger.error(f"Error converting rule to YAML: {e}")
            return ""
    
    async def get_mitre_mapping(self, rule_id: str) -> Dict[str, Any]:
        """Get MITRE ATT&CK mapping for a rule"""
        try:
            rule = await self.get_rule_by_id(rule_id)
            
            if "error" in rule:
                return rule
            
            return {
                "rule_id": rule_id,
                "rule_title": rule.get("title", ""),
                "tactics": rule.get("tactics", []),
                "techniques": rule.get("techniques", []),
                "mitre_url": f"https://attack.mitre.org/techniques/{rule.get('techniques', [''])[0] if rule.get('techniques') else ''}"
            }
            
        except Exception as e:
            logger.error(f"Error getting MITRE mapping: {e}")
            return {"error": str(e)}
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()