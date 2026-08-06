"""
MITRE ATT&CK Client Module
Interfaces with MITRE ATT&CK framework for threat intelligence
"""
import httpx
from typing import Dict, Any, List, Optional
from datetime import datetime
from ..utils.logger import get_logger

logger = get_logger(__name__)


class MITREAttackClient:
    """Client for MITRE ATT&CK framework integration"""
    
    def __init__(self):
        self.base_url = "https://attack.mitre.org/api"
        self.client = httpx.AsyncClient(timeout=30.0)
        self.cache = {}
        self.cache_expiry = {}
        self.cache_duration = 3600  # 1 hour cache
    
    async def get_techniques(self, tactic: Optional[str] = None) -> Dict[str, Any]:
        """Get MITRE ATT&CK techniques, optionally filtered by tactic"""
        try:
            cache_key = f"techniques_{tactic}" if tactic else "techniques_all"
            
            if self._is_cached(cache_key):
                return self.cache[cache_key]
            
            if tactic:
                url = f"{self.base_url}/techniques/{tactic}"
            else:
                url = f"{self.base_url}/techniques"
            
            response = await self.client.get(url)
            
            if response.status_code == 200:
                data = response.json()
                parsed_data = self._parse_techniques(data)
                self._set_cache(cache_key, parsed_data)
                return parsed_data
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error getting techniques: {e}")
            return {"error": str(e)}
    
    async def get_tactics(self) -> Dict[str, Any]:
        """Get MITRE ATT&CK tactics"""
        try:
            cache_key = "tactics"
            
            if self._is_cached(cache_key):
                return self.cache[cache_key]
            
            url = f"{self.base_url}/tactics"
            response = await self.client.get(url)
            
            if response.status_code == 200:
                data = response.json()
                parsed_data = self._parse_tactics(data)
                self._set_cache(cache_key, parsed_data)
                return parsed_data
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error getting tactics: {e}")
            return {"error": str(e)}
    
    async def get_groups(self) -> Dict[str, Any]:
        """Get MITRE ATT&CK threat groups"""
        try:
            cache_key = "groups"
            
            if self._is_cached(cache_key):
                return self.cache[cache_key]
            
            url = f"{self.base_url}/groups"
            response = await self.client.get(url)
            
            if response.status_code == 200:
                data = response.json()
                parsed_data = self._parse_groups(data)
                self._set_cache(cache_key, parsed_data)
                return parsed_data
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error getting groups: {e}")
            return {"error": str(e)}
    
    async def get_software(self) -> Dict[str, Any]:
        """Get MITRE ATT&CK software"""
        try:
            cache_key = "software"
            
            if self._is_cached(cache_key):
                return self.cache[cache_key]
            
            url = f"{self.base_url}/software"
            response = await self.client.get(url)
            
            if response.status_code == 200:
                data = response.json()
                parsed_data = self._parse_software(data)
                self._set_cache(cache_key, parsed_data)
                return parsed_data
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error getting software: {e}")
            return {"error": str(e)}
    
    async def search_techniques(self, query: str) -> Dict[str, Any]:
        """Search for techniques by name or description"""
        try:
            all_techniques = await self.get_techniques()
            
            if "error" in all_techniques:
                return all_techniques
            
            results = []
            query_lower = query.lower()
            
            for technique in all_techniques.get("techniques", []):
                if (query_lower in technique.get("name", "").lower() or
                    query_lower in technique.get("description", "").lower()):
                    results.append(technique)
            
            return {
                "query": query,
                "total_results": len(results),
                "techniques": results
            }
            
        except Exception as e:
            logger.error(f"Error searching techniques: {e}")
            return {"error": str(e)}
    
    async def analyze_technique(self, technique_id: str) -> Dict[str, Any]:
        """Analyze a specific technique by ID"""
        try:
            cache_key = f"technique_{technique_id}"
            
            if self._is_cached(cache_key):
                return self.cache[cache_key]
            
            url = f"{self.base_url}/techniques/{technique_id}"
            response = await self.client.get(url)
            
            if response.status_code == 200:
                data = response.json()
                parsed_data = self._parse_technique_detail(data)
                self._set_cache(cache_key, parsed_data)
                return parsed_data
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error analyzing technique: {e}")
            return {"error": str(e)}
    
    async def get_mitigations(self, technique_id: Optional[str] = None) -> Dict[str, Any]:
        """Get mitigations for techniques"""
        try:
            cache_key = f"mitigations_{technique_id}" if technique_id else "mitigations_all"
            
            if self._is_cached(cache_key):
                return self.cache[cache_key]
            
            if technique_id:
                url = f"{self.base_url}/techniques/{technique_id}/mitigations"
            else:
                url = f"{self.base_url}/mitigations"
            
            response = await self.client.get(url)
            
            if response.status_code == 200:
                data = response.json()
                parsed_data = self._parse_mitigations(data)
                self._set_cache(cache_key, parsed_data)
                return parsed_data
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error getting mitigations: {e}")
            return {"error": str(e)}
    
    async def map_iocs_to_techniques(self, iocs: Dict[str, Any]) -> Dict[str, Any]:
        """Map IOCs to potential MITRE ATT&CK techniques"""
        try:
            mapping = {
                "timestamp": datetime.now().isoformat(),
                "techniques": [],
                "tactics": [],
                "confidence_scores": {}
            }
            
            # Get all techniques for analysis
            all_techniques = await self.get_techniques()
            
            if "error" in all_techniques:
                return all_techniques
            
            techniques = all_techniques.get("techniques", [])
            
            # Analyze IOCs and map to techniques
            technique_matches = []
            
            # Check for network-related IOCs
            if iocs.get("ip_addresses") or iocs.get("domains") or iocs.get("urls"):
                network_techniques = [
                    t for t in techniques 
                    if any(keyword in t.get("name", "").lower() 
                          for keyword in ["command", "c2", "exfiltration", "remote"])
                ]
                technique_matches.extend(network_techniques)
            
            # Check for file-related IOCs
            if iocs.get("file_hashes") or iocs.get("file_paths"):
                file_techniques = [
                    t for t in techniques 
                    if any(keyword in t.get("name", "").lower() 
                          for keyword in ["file", "execution", "injection"])
                ]
                technique_matches.extend(file_techniques)
            
            # Check for process-related IOCs
            if iocs.get("processes"):
                process_techniques = [
                    t for t in techniques 
                    if any(keyword in t.get("name", "").lower() 
                          for keyword in ["process", "execution", "privilege"])
                ]
                technique_matches.extend(process_techniques)
            
            # Deduplicate and score matches
            unique_techniques = {}
            for technique in technique_matches:
                tech_id = technique.get("id", "")
                if tech_id not in unique_techniques:
                    unique_techniques[tech_id] = technique
                    unique_techniques[tech_id]["confidence"] = 1
                else:
                    unique_techniques[tech_id]["confidence"] += 1
            
            # Convert to list and sort by confidence
            sorted_techniques = sorted(
                unique_techniques.values(),
                key=lambda x: x.get("confidence", 0),
                reverse=True
            )
            
            mapping["techniques"] = sorted_techniques[:10]  # Top 10
            
            # Extract tactics from techniques
            tactics = set()
            for technique in mapping["techniques"]:
                tactics.update(technique.get("tactics", []))
            mapping["tactics"] = list(tactics)
            
            return mapping
            
        except Exception as e:
            logger.error(f"Error mapping IOCs to techniques: {e}")
            return {"error": str(e)}
    
    def _parse_techniques(self, data: List[Dict]) -> Dict[str, Any]:
        """Parse techniques response"""
        techniques = []
        for item in data:
            technique = {
                "id": item.get("technique_id", ""),
                "name": item.get("name", ""),
                "description": item.get("description", ""),
                "tactics": item.get("tactics", []),
                "url": f"https://attack.mitre.org/techniques/{item.get('technique_id', '')}"
            }
            techniques.append(technique)
        
        return {
            "source": "mitre_attack",
            "total_techniques": len(techniques),
            "techniques": techniques
        }
    
    def _parse_tactics(self, data: List[Dict]) -> Dict[str, Any]:
        """Parse tactics response"""
        tactics = []
        for item in data:
            tactic = {
                "id": item.get("tactic_id", ""),
                "name": item.get("name", ""),
                "description": item.get("description", ""),
                "url": f"https://attack.mitre.org/tactics/{item.get('tactic_id', '')}"
            }
            tactics.append(tactic)
        
        return {
            "source": "mitre_attack",
            "total_tactics": len(tactics),
            "tactics": tactics
        }
    
    def _parse_groups(self, data: List[Dict]) -> Dict[str, Any]:
        """Parse threat groups response"""
        groups = []
        for item in data:
            group = {
                "id": item.get("group_id", ""),
                "name": item.get("name", ""),
                "description": item.get("description", ""),
                "associated_techniques": item.get("techniques", []),
                "url": f"https://attack.mitre.org/groups/{item.get('group_id', '')}"
            }
            groups.append(group)
        
        return {
            "source": "mitre_attack",
            "total_groups": len(groups),
            "groups": groups
        }
    
    def _parse_software(self, data: List[Dict]) -> Dict[str, Any]:
        """Parse software response"""
        software = []
        for item in data:
            soft = {
                "id": item.get("software_id", ""),
                "name": item.get("name", ""),
                "description": item.get("description", ""),
                "type": item.get("type", ""),
                "associated_techniques": item.get("techniques", []),
                "url": f"https://attack.mitre.org/software/{item.get('software_id', '')}"
            }
            software.append(soft)
        
        return {
            "source": "mitre_attack",
            "total_software": len(software),
            "software": software
        }
    
    def _parse_technique_detail(self, data: Dict) -> Dict[str, Any]:
        """Parse detailed technique response"""
        technique = data.get("object", {})
        
        return {
            "source": "mitre_attack",
            "id": technique.get("technique_id", ""),
            "name": technique.get("name", ""),
            "description": technique.get("description", ""),
            "tactics": technique.get("tactics", []),
            "detection": technique.get("detection", []),
            "mitigation": technique.get("mitigation", []),
            "examples": technique.get("examples", []),
            "references": technique.get("references", []),
            "url": f"https://attack.mitre.org/techniques/{technique.get('technique_id', '')}"
        }
    
    def _parse_mitigations(self, data: List[Dict]) -> Dict[str, Any]:
        """Parse mitigations response"""
        mitigations = []
        for item in data:
            mitigation = {
                "id": item.get("mitigation_id", ""),
                "name": item.get("name", ""),
                "description": item.get("description", ""),
                "related_techniques": item.get("techniques", []),
                "url": f"https://attack.mitre.org/mitigations/{item.get('mitigation_id', '')}"
            }
            mitigations.append(mitigation)
        
        return {
            "source": "mitre_attack",
            "total_mitigations": len(mitigations),
            "mitigations": mitigations
        }
    
    def _is_cached(self, key: str) -> bool:
        """Check if data is cached and not expired"""
        if key not in self.cache:
            return False
        
        if key not in self.cache_expiry:
            return False
        
        return datetime.now().timestamp() < self.cache_expiry[key]
    
    def _set_cache(self, key: str, data: Any):
        """Set data in cache with expiry"""
        self.cache[key] = data
        self.cache_expiry[key] = datetime.now().timestamp() + self.cache_duration
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()