"""
AlienVault OTX Client Module
Interfaces with AlienVault OTX API for threat intelligence
"""
import httpx
from typing import Dict, Any, List, Optional
from datetime import datetime
from ..utils.logger import get_logger

logger = get_logger(__name__)


class AlienVaultClient:
    """Client for AlienVault OTX API integration"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json"
        }
        self.client = httpx.AsyncClient(headers=self.headers, timeout=30.0)
    
    async def check_indicator(self, indicator: str) -> Dict[str, Any]:
        """Check an indicator against AlienVault OTX"""
        try:
            logger.info(f"Checking indicator: {indicator}")
            
            # Determine indicator type and appropriate endpoint
            if self._is_ip(indicator):
                section = "reputation"
                endpoint = f"indicators/IPv4/{indicator}/{section}"
            elif self._is_domain(indicator):
                section = "reputation"
                endpoint = f"indicators/domain/{indicator}/{section}"
            elif self._is_url(indicator):
                endpoint = f"indicators/url/{indicator}"
            elif self._is_hash(indicator):
                endpoint = f"indicators/file/{indicator}"
            else:
                # Generic search
                endpoint = f"indicators/indicator/{indicator}"
            
            response = await self.client.get(
                f"{self.base_url}/{endpoint}"
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_indicator_response(data, indicator)
            elif response.status_code == 401:
                return {"error": "Invalid API key"}
            elif response.status_code == 404:
                return {
                    "source": "alienvault",
                    "indicator": indicator,
                    "reputation": "Clean",
                    "pulse_count": 0,
                    "first_seen": "N/A",
                    "last_seen": "N/A",
                    "tags": [],
                    "risk_level": "Low"
                }
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded"}
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error checking indicator: {e}")
            return {"error": str(e)}
    
    async def get_pulse(self, pulse_id: str) -> Dict[str, Any]:
        """Get pulse details from AlienVault OTX"""
        try:
            logger.info(f"Getting pulse: {pulse_id}")
            
            response = await self.client.get(
                f"{self.base_url}/pulses/{pulse_id}"
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_pulse_response(data)
            elif response.status_code == 401:
                return {"error": "Invalid API key"}
            elif response.status_code == 404:
                return {"error": "Pulse not found"}
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded"}
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error getting pulse: {e}")
            return {"error": str(e)}
    
    async def search_ioc(self, ioc: str) -> Dict[str, Any]:
        """Search for IOCs in AlienVault OTX"""
        try:
            logger.info(f"Searching IOC: {ioc}")
            
            response = await self.client.get(
                f"{self.base_url}/indicators/search",
                params={"q": ioc}
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_search_response(data)
            elif response.status_code == 401:
                return {"error": "Invalid API key"}
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded"}
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error searching IOC: {e}")
            return {"error": str(e)}
    
    async def get_reputation(self, indicator: str) -> Dict[str, Any]:
        """Get reputation for an indicator from AlienVault OTX"""
        try:
            logger.info(f"Getting reputation for: {indicator}")
            
            result = await self.check_indicator(indicator)
            
            if "error" in result:
                return result
            
            # Extract reputation information
            reputation_score = 0
            if result.get("pulse_count", 0) > 0:
                reputation_score = min(100, result.get("pulse_count", 0) * 10)
            
            return {
                "source": "alienvault",
                "indicator": indicator,
                "reputation_score": reputation_score,
                "risk_level": self._calculate_risk_level(reputation_score),
                "pulse_count": result.get("pulse_count", 0),
                "tags": result.get("tags", [])
            }
            
        except Exception as e:
            logger.error(f"Error getting reputation: {e}")
            return {"error": str(e)}
    
    def _is_ip(self, indicator: str) -> bool:
        """Check if indicator is an IP address"""
        parts = indicator.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def _is_domain(self, indicator: str) -> bool:
        """Check if indicator is a domain"""
        return '.' in indicator and not self._is_ip(indicator) and not indicator.startswith('http')
    
    def _is_url(self, indicator: str) -> bool:
        """Check if indicator is a URL"""
        return indicator.startswith('http://') or indicator.startswith('https://')
    
    def _is_hash(self, indicator: str) -> bool:
        """Check if indicator is a hash"""
        # MD5: 32 chars, SHA1: 40 chars, SHA256: 64 chars
        hex_chars = set('0123456789abcdef')
        if len(indicator) in [32, 40, 64]:
            return all(c.lower() in hex_chars for c in indicator)
        return False
    
    def _parse_indicator_response(self, data: Dict[str, Any], indicator: str) -> Dict[str, Any]:
        """Parse AlienVault indicator response"""
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        
        # Extract tags from pulses
        tags = set()
        for pulse in pulses:
            pulse_tags = pulse.get("tags", [])
            tags.update(pulse_tags)
        
        # Determine reputation
        pulse_count = len(pulses)
        if pulse_count > 5:
            reputation = "Malicious"
            risk_level = "High"
        elif pulse_count > 2:
            reputation = "Suspicious"
            risk_level = "Medium"
        elif pulse_count > 0:
            reputation = "Low Confidence"
            risk_level = "Low"
        else:
            reputation = "Clean"
            risk_level = "Low"
        
        # Get first/last seen
        first_seen = "N/A"
        last_seen = "N/A"
        if pulses:
            first_seen = pulses[0].get("created", "N/A")
            last_seen = pulses[-1].get("created", "N/A")
        
        return {
            "source": "alienvault",
            "indicator": indicator,
            "reputation": reputation,
            "pulse_count": pulse_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "tags": list(tags),
            "risk_level": risk_level,
            "pulses": [
                {
                    "id": pulse.get("id", ""),
                    "name": pulse.get("name", ""),
                    "description": pulse.get("description", ""),
                    "created": pulse.get("created", ""),
                    "author": pulse.get("author_name", "")
                }
                for pulse in pulses[:10]  # Limit to first 10 pulses
            ]
        }
    
    def _parse_pulse_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse AlienVault pulse response"""
        return {
            "source": "alienvault",
            "pulse_id": data.get("id", ""),
            "name": data.get("name", ""),
            "description": data.get("description", ""),
            "created": data.get("created", ""),
            "modified": data.get("modified", ""),
            "author": data.get("author_name", ""),
            "tags": data.get("tags", []),
            "indicators": data.get("indicators", []),
            "targeted_countries": data.get("targeted_countries", []),
            "malware_families": data.get("malware_families", [])
        }
    
    def _parse_search_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse AlienVault search response"""
        results = data.get("results", [])
        
        return {
            "source": "alienvault",
            "query": data.get("query", ""),
            "matches": results,
            "total_matches": len(results)
        }
    
    def _calculate_risk_level(self, reputation_score: int) -> str:
        """Calculate risk level based on reputation score"""
        if reputation_score >= 75:
            return "Critical"
        elif reputation_score >= 50:
            return "High"
        elif reputation_score >= 25:
            return "Medium"
        else:
            return "Low"
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()