"""
VirusTotal Client Module
Interfaces with VirusTotal API for threat intelligence
"""
import httpx
from typing import Dict, Any, List, Optional
from datetime import datetime
from ..utils.logger import get_logger

logger = get_logger(__name__)


class VirusTotalClient:
    """Client for VirusTotal API integration"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": api_key,
            "accept": "application/json"
        }
        self.client = httpx.AsyncClient(headers=self.headers, timeout=30.0)
    
    async def analyze_file(self, file_hash: str) -> Dict[str, Any]:
        """Analyze a file hash using VirusTotal"""
        try:
            logger.info(f"Analyzing file hash: {file_hash}")
            
            # Get file report
            response = await self.client.get(
                f"{self.base_url}/files/{file_hash}"
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_file_analysis(data)
            elif response.status_code == 401:
                return {"error": "Invalid API key"}
            elif response.status_code == 404:
                return {"error": "File not found in VirusTotal"}
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error analyzing file: {e}")
            return {"error": str(e)}
    
    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a URL using VirusTotal"""
        try:
            logger.info(f"Analyzing URL: {url}")
            
            # First encode the URL
            url_id = self._encode_url(url)
            
            # Get URL report
            response = await self.client.get(
                f"{self.base_url}/urls/{url_id}"
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_url_analysis(data)
            elif response.status_code == 401:
                return {"error": "Invalid API key"}
            elif response.status_code == 404:
                return {"error": "URL not found in VirusTotal"}
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error analyzing URL: {e}")
            return {"error": str(e)}
    
    async def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """Analyze an IP address using VirusTotal"""
        try:
            logger.info(f"Analyzing IP: {ip_address}")
            
            response = await self.client.get(
                f"{self.base_url}/ip_addresses/{ip_address}"
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_ip_analysis(data)
            elif response.status_code == 401:
                return {"error": "Invalid API key"}
            elif response.status_code == 404:
                return {"error": "IP not found in VirusTotal"}
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error analyzing IP: {e}")
            return {"error": str(e)}
    
    async def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze a domain using VirusTotal"""
        try:
            logger.info(f"Analyzing domain: {domain}")
            
            response = await self.client.get(
                f"{self.base_url}/domains/{domain}"
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_domain_analysis(data)
            elif response.status_code == 401:
                return {"error": "Invalid API key"}
            elif response.status_code == 404:
                return {"error": "Domain not found in VirusTotal"}
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error analyzing domain: {e}")
            return {"error": str(e)}
    
    async def batch_analyze(self, iocs: Dict[str, List[str]]) -> Dict[str, Any]:
        """Batch analyze multiple IOCs"""
        results = {
            "analyses": {},
            "timestamp": datetime.now().isoformat(),
            "total_iocs": 0,
            "successful": 0,
            "failed": 0
        }
        
        # Count total IOCs
        for ioc_type, ioc_list in iocs.items():
            results["total_iocs"] += len(ioc_list)
        
        # Analyze each IOC type
        if "file_hashes" in iocs:
            for hash_type, hashes in iocs["file_hashes"].items():
                for hash_value in hashes:
                    result = await self.analyze_file(hash_value)
                    results["analyses"][f"file_{hash_value}"] = result
                    if "error" not in result:
                        results["successful"] += 1
                    else:
                        results["failed"] += 1
        
        if "ip_addresses" in iocs:
            for ip in iocs["ip_addresses"]:
                result = await self.analyze_ip(ip)
                results["analyses"][f"ip_{ip}"] = result
                if "error" not in result:
                    results["successful"] += 1
                else:
                    results["failed"] += 1
        
        if "domains" in iocs:
            for domain in iocs["domains"]:
                result = await self.analyze_domain(domain)
                results["analyses"][f"domain_{domain}"] = result
                if "error" not in result:
                    results["successful"] += 1
                else:
                    results["failed"] += 1
        
        if "urls" in iocs:
            for url in iocs["urls"]:
                result = await self.analyze_url(url)
                results["analyses"][f"url_{url}"] = result
                if "error" not in result:
                    results["successful"] += 1
                else:
                    results["failed"] += 1
        
        return results
    
    def _parse_file_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal file analysis response"""
        attributes = data.get("data", {}).get("attributes", {})
        
        return {
            "source": "virustotal",
            "ioc_type": "file",
            "hash": data.get("data", {}).get("id", ""),
            "detection_ratio": f"{attributes.get('last_analysis_stats', {}).get('malicious', 0)}/{attributes.get('last_analysis_stats', {}).get('harmless', 0) + attributes.get('last_analysis_stats', {}).get('malicious', 0)}",
            "positive_detections": attributes.get('last_analysis_stats', {}).get('malicious', 0),
            "total_engines": sum(attributes.get('last_analysis_stats', {}).values()),
            "file_type": attributes.get('type_description', 'Unknown'),
            "file_size": attributes.get('size', 0),
            "first_seen": attributes.get('first_submission_date', ''),
            "last_seen": attributes.get('last_submission_date', ''),
            "reputation_score": attributes.get('reputation', 0),
            "popular_threat_classification": attributes.get('popular_threat_classification', {}),
            "meaningful_name": attributes.get('meaningful_name', ''),
            "tags": attributes.get('tags', []),
            "risk_level": self._calculate_file_risk(attributes)
        }
    
    def _parse_url_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal URL analysis response"""
        attributes = data.get("data", {}).get("attributes", {})
        
        return {
            "source": "virustotal",
            "ioc_type": "url",
            "url": data.get("data", {}).get("id", ""),
            "detection_ratio": f"{attributes.get('last_analysis_stats', {}).get('malicious', 0)}/{attributes.get('last_analysis_stats', {}).get('harmless', 0) + attributes.get('last_analysis_stats', {}).get('malicious', 0)}",
            "positive_detections": attributes.get('last_analysis_stats', {}).get('malicious', 0),
            "total_engines": sum(attributes.get('last_analysis_stats', {}).values()),
            "first_seen": attributes.get('first_submission_date', ''),
            "last_seen": attributes.get('last_submission_date', ''),
            "reputation_score": attributes.get('reputation', 0),
            "categories": attributes.get('categories', {}),
            "risk_level": self._calculate_url_risk(attributes)
        }
    
    def _parse_ip_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal IP analysis response"""
        attributes = data.get("data", {}).get("attributes", {})
        
        return {
            "source": "virustotal",
            "ioc_type": "ip",
            "ip": data.get("data", {}).get("id", ""),
            "country": attributes.get('country', ''),
            "continent": attributes.get('continent', ''),
            "network": attributes.get('network', ''),
            "asn": attributes.get('asn', 0),
            "asn_owner": attributes.get('as_owner', ''),
            "reputation_score": attributes.get('reputation', 0),
            "last_analysis_stats": attributes.get('last_analysis_stats', {}),
            "total_votes": attributes.get('total_votes', {}),
            "risk_level": self._calculate_ip_risk(attributes)
        }
    
    def _parse_domain_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal domain analysis response"""
        attributes = data.get("data", {}).get("attributes", {})
        
        return {
            "source": "virustotal",
            "ioc_type": "domain",
            "domain": data.get("data", {}).get("id", ""),
            "detection_ratio": f"{attributes.get('last_analysis_stats', {}).get('malicious', 0)}/{attributes.get('last_analysis_stats', {}).get('harmless', 0) + attributes.get('last_analysis_stats', {}).get('malicious', 0)}",
            "positive_detections": attributes.get('last_analysis_stats', {}).get('malicious', 0),
            "total_engines": sum(attributes.get('last_analysis_stats', {}).values()),
            "reputation_score": attributes.get('reputation', 0),
            "last_dns_records": attributes.get('last_dns_records', []),
            "categories": attributes.get('categories', {}),
            "whois": attributes.get('whois', ''),
            "creation_date": attributes.get('creation_date', ''),
            "last_modification_date": attributes.get('last_modification_date', ''),
            "risk_level": self._calculate_domain_risk(attributes)
        }
    
    def _calculate_file_risk(self, attributes: Dict[str, Any]) -> str:
        """Calculate risk level for file"""
        malicious = attributes.get('last_analysis_stats', {}).get('malicious', 0)
        reputation = attributes.get('reputation', 0)
        
        if malicious > 10:
            return "critical"
        elif malicious > 5:
            return "high"
        elif malicious > 0:
            return "medium"
        elif reputation < -10:
            return "medium"
        else:
            return "low"
    
    def _calculate_url_risk(self, attributes: Dict[str, Any]) -> str:
        """Calculate risk level for URL"""
        malicious = attributes.get('last_analysis_stats', {}).get('malicious', 0)
        reputation = attributes.get('reputation', 0)
        
        if malicious > 5:
            return "critical"
        elif malicious > 2:
            return "high"
        elif malicious > 0:
            return "medium"
        elif reputation < -5:
            return "medium"
        else:
            return "low"
    
    def _calculate_ip_risk(self, attributes: Dict[str, Any]) -> str:
        """Calculate risk level for IP"""
        malicious = attributes.get('last_analysis_stats', {}).get('malicious', 0)
        reputation = attributes.get('reputation', 0)
        
        if malicious > 5:
            return "critical"
        elif malicious > 2:
            return "high"
        elif malicious > 0:
            return "medium"
        elif reputation < -5:
            return "medium"
        else:
            return "low"
    
    def _calculate_domain_risk(self, attributes: Dict[str, Any]) -> str:
        """Calculate risk level for domain"""
        malicious = attributes.get('last_analysis_stats', {}).get('malicious', 0)
        reputation = attributes.get('reputation', 0)
        
        if malicious > 5:
            return "critical"
        elif malicious > 2:
            return "high"
        elif malicious > 0:
            return "medium"
        elif reputation < -5:
            return "medium"
        else:
            return "low"
    
    def _encode_url(self, url: str) -> str:
        """Encode URL for VirusTotal API"""
        import base64
        url_bytes = url.encode('utf-8')
        base64_bytes = base64.b64encode(url_bytes)
        return base64_bytes.decode('utf-8').rstrip('=')
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()