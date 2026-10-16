"""
AbuseIPDB Client Module
Interfaces with AbuseIPDB API for IP threat intelligence
"""
import httpx
from typing import Dict, Any, List, Optional
from datetime import datetime
from ..utils.logger import get_logger

logger = get_logger(__name__)


class AbuseIPDBClient:
    """Client for AbuseIPDB API integration"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        self.client = httpx.AsyncClient(headers=self.headers, timeout=30.0)
    
    async def check_ip(self, ip_address: str, max_age_days: int = 90) -> Dict[str, Any]:
        """Check an IP address against AbuseIPDB"""
        try:
            logger.info(f"Checking IP: {ip_address}")
            
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": max_age_days,
                "verbose": ""
            }
            
            response = await self.client.get(
                f"{self.base_url}/check",
                params=params
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_ip_check(data)
            elif response.status_code == 401:
                return {"error": "Invalid API key"}
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded"}
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error checking IP: {e}")
            return {"error": str(e)}
    
    async def report_ip(self, ip_address: str, categories: List[int], 
                       comment: str = "") -> Dict[str, Any]:
        """Report an IP address to AbuseIPDB"""
        try:
            logger.info(f"Reporting IP: {ip_address}")
            
            data = {
                "ip": ip_address,
                "categories": categories,
                "comment": comment
            }
            
            response = await self.client.post(
                f"{self.base_url}/report",
                json=data
            )
            
            if response.status_code == 200:
                return {
                    "source": "abuseipdb",
                    "status": "success",
                    "message": "IP reported successfully",
                    "ip": ip_address
                }
            elif response.status_code == 401:
                return {"error": "Invalid API key"}
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded"}
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error reporting IP: {e}")
            return {"error": str(e)}
    
    async def check_bulk_ips(self, ip_addresses: List[str], 
                            max_age_days: int = 90) -> Dict[str, Any]:
        """Check multiple IP addresses in bulk"""
        try:
            results = {
                "analyses": {},
                "timestamp": datetime.now().isoformat(),
                "total_ips": len(ip_addresses),
                "successful": 0,
                "failed": 0,
                "malicious_count": 0,
                "suspicious_count": 0,
                "clean_count": 0
            }
            
            for ip in ip_addresses:
                result = await self.check_ip(ip, max_age_days)
                results["analyses"][ip] = result
                
                if "error" not in result:
                    results["successful"] += 1
                    
                    # Categorize results
                    confidence_score = result.get("abuse_confidence_score", 0)
                    if confidence_score >= 75:
                        results["malicious_count"] += 1
                    elif confidence_score >= 25:
                        results["suspicious_count"] += 1
                    else:
                        results["clean_count"] += 1
                else:
                    results["failed"] += 1
            
            return results
            
        except Exception as e:
            logger.error(f"Error checking bulk IPs: {e}")
            return {"error": str(e)}
    
    async def get_blacklist(self, limit: int = 10000, 
                          minimum_confidence: int = 25) -> Dict[str, Any]:
        """Get the AbuseIPDB blacklist"""
        try:
            params = {
                "limit": limit,
                "minimumConfidenceScore": minimum_confidence
            }
            
            response = await self.client.get(
                f"{self.base_url}/blacklist",
                params=params
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_blacklist(data)
            elif response.status_code == 401:
                return {"error": "Invalid API key"}
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded"}
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error getting blacklist: {e}")
            return {"error": str(e)}
    
    async def get_report(self, ip_address: str) -> Dict[str, Any]:
        """Get detailed report for an IP address"""
        try:
            # First check the IP
            check_result = await self.check_ip(ip_address)
            
            if "error" in check_result:
                return check_result
            
            # Add additional context
            report = {
                "source": "abuseipdb",
                "ip_address": ip_address,
                "timestamp": datetime.now().isoformat(),
                "risk_assessment": self._assess_risk(check_result),
                "detailed_info": check_result
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error getting report: {e}")
            return {"error": str(e)}
    
    def _parse_ip_check(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse AbuseIPDB IP check response"""
        ip_data = data.get("data", {})
        
        return {
            "source": "abuseipdb",
            "ioc_type": "ip",
            "ip_address": ip_data.get("ipAddress", ""),
            "is_public": ip_data.get("isPublic", False),
            "ip_version": ip_data.get("ipVersion", 0),
            "is_whitelisted": ip_data.get("isWhitelisted", False),
            "country_code": ip_data.get("countryCode", ""),
            "country_name": ip_data.get("countryName", ""),
            "abuse_confidence_score": ip_data.get("abuseConfidenceScore", 0),
            "total_reports": ip_data.get("totalReports", 0),
            "num_distinct_users": ip_data.get("numDistinctUsers", 0),
            "last_reported_at": ip_data.get("lastReportedAt", ""),
            "isp": ip_data.get("isp", ""),
            "domain": ip_data.get("domain", ""),
            "hostnames": ip_data.get("hostnames", []),
            "usage_type": ip_data.get("usageType", ""),
            "reports": self._parse_reports(ip_data.get("reports", [])),
            "risk_level": self._calculate_risk_level(ip_data)
        }
    
    def _parse_reports(self, reports: List[Dict]) -> List[Dict]:
        """Parse individual reports"""
        parsed_reports = []
        
        for report in reports:
            parsed_report = {
                "reported_at": report.get("reportedAt", ""),
                "comment": report.get("comment", ""),
                "categories": self._parse_categories(report.get("categories", [])),
                "reporter_id": report.get("reporterId", ""),
                "reporter_country": report.get("reporterCountryCode", "")
            }
            parsed_reports.append(parsed_report)
        
        return parsed_reports
    
    def _parse_categories(self, categories: List[Dict]) -> List[str]:
        """Parse category information"""
        return [cat.get("name", "") for cat in categories]
    
    def _parse_blacklist(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse blacklist response"""
        ip_addresses = data.get("data", [])
        
        return {
            "source": "abuseipdb",
            "total_addresses": len(ip_addresses),
            "ip_addresses": ip_addresses,
            "generated_at": data.get("meta", {}).get("generatedAt", "")
        }
    
    def _calculate_risk_level(self, ip_data: Any) -> str:
        """Calculate risk level based on AbuseIPDB data"""
        # Handle case where ip_data might not be a dict
        if not isinstance(ip_data, dict):
            return "medium"
            
        confidence_score = ip_data.get("abuseConfidenceScore", 0)
        total_reports = ip_data.get("totalReports", 0)
        is_whitelisted = ip_data.get("isWhitelisted", False)
        
        if is_whitelisted:
            return "low"
        
        if confidence_score >= 75:
            return "critical"
        elif confidence_score >= 50:
            return "high"
        elif confidence_score >= 25:
            return "medium"
        elif total_reports > 10:
            return "medium"
        else:
            return "low"
    
    def _assess_risk(self, check_result: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive risk assessment"""
        confidence_score = check_result.get("abuse_confidence_score", 0)
        total_reports = check_result.get("total_reports", 0)
        risk_level = check_result.get("risk_level", "low")
        
        recommendations = []
        
        if risk_level in ["critical", "high"]:
            recommendations.append("Block this IP address immediately")
            recommendations.append("Investigate systems that communicated with this IP")
            recommendations.append("Check for additional IOCs associated with this IP")
        elif risk_level == "medium":
            recommendations.append("Monitor traffic to/from this IP")
            recommendations.append("Consider blocking if suspicious activity continues")
        else:
            recommendations.append("Continue monitoring")
        
        return {
            "risk_level": risk_level,
            "confidence_score": confidence_score,
            "total_reports": total_reports,
            "recommendations": recommendations,
            "requires_action": risk_level in ["critical", "high"]
        }
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()