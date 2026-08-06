"""
IOC Extractor Module
Extracts Indicators of Compromise from collected logs
"""
import re
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime
from ipaddress import ip_address, IPv4Address, IPv6Address
from urllib.parse import urlparse
from ..utils.logger import get_logger

logger = get_logger(__name__)


class IOCExtractor:
    """Extracts IOCs from log data"""
    
    def __init__(self):
        self.patterns = {
            'ip': self._compile_ip_patterns(),
            'hash': self._compile_hash_patterns(),
            'url': self._compile_url_patterns(),
            'email': self._compile_email_patterns(),
            'domain': self._compile_domain_patterns(),
            'registry': self._compile_registry_patterns(),
            'file_path': self._compile_file_path_patterns(),
            'process': self._compile_process_patterns()
        }
    
    def extract_iocs(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract all IOCs from collected logs"""
        iocs = {
            "extraction_timestamp": datetime.now().isoformat(),
            "total_logs_processed": len(logs),
            "ip_addresses": [],
            "domains": [],
            "urls": [],
            "email_addresses": [],
            "file_hashes": {},
            "registry_keys": [],
            "file_paths": [],
            "processes": [],
            "users": [],
            "summary": {}
        }
        
        for log in logs:
            log_iocs = self._extract_from_log(log)
            self._merge_iocs(iocs, log_iocs)
        
        # Deduplicate and classify IOCs
        iocs = self._deduplicate_iocs(iocs)
        iocs["summary"] = self._generate_summary(iocs)
        
        return iocs
    
    def _extract_from_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Extract IOCs from a single log entry"""
        iocs = {
            "ip_addresses": [],
            "domains": [],
            "urls": [],
            "email_addresses": [],
            "file_hashes": {},
            "registry_keys": [],
            "file_paths": [],
            "processes": [],
            "users": []
        }
        
        # Get log text content
        text_content = self._get_log_text(log)
        
        # Extract using patterns
        for ioc_type, pattern in self.patterns.items():
            matches = pattern.findall(text_content)
            if ioc_type == 'hash':
                for hash_value in matches:
                    hash_type = self._identify_hash_type(hash_value)
                    if hash_type not in iocs["file_hashes"]:
                        iocs["file_hashes"][hash_type] = []
                    iocs["file_hashes"][hash_type].append(hash_value)
            else:
                if ioc_type in iocs:
                    iocs[ioc_type].extend(matches)
        
        # Extract structured data if available
        if "ioc_candidates" in log:
            self._extract_structured_iocs(log["ioc_candidates"], iocs)
        
        # Extract user information
        if "user" in log and log["user"]:
            iocs["users"].append(str(log["user"]))
        
        return iocs
    
    def _get_log_text(self, log: Dict[str, Any]) -> str:
        """Convert log to searchable text"""
        text_parts = []
        
        # Add basic fields
        for field in ["log_name", "source", "type", "computer_name"]:
            if field in log:
                text_parts.append(str(log[field]))
        
        # Add data content
        if "data" in log:
            data = log["data"]
            if isinstance(data, dict):
                for key, value in data.items():
                    text_parts.append(f"{key}: {value}")
            else:
                text_parts.append(str(data))
        
        # Add XML representation if available
        if "xml_representation" in log:
            text_parts.append(log["xml_representation"])
        
        return " ".join(text_parts)
    
    def _extract_structured_iocs(self, structured_data: Dict, iocs: Dict):
        """Extract IOCs from structured data"""
        for key, values in structured_data.items():
            if key in iocs and isinstance(values, list):
                iocs[key].extend(values)
    
    def _merge_iocs(self, main_iocs: Dict, new_iocs: Dict):
        """Merge extracted IOCs into main collection"""
        for key, values in new_iocs.items():
            if key in main_iocs:
                if isinstance(main_iocs[key], list):
                    main_iocs[key].extend(values)
                elif isinstance(main_iocs[key], dict):
                    for hash_type, hash_values in values.items():
                        if hash_type not in main_iocs[key]:
                            main_iocs[key][hash_type] = []
                        main_iocs[key][hash_type].extend(hash_values)
    
    def _deduplicate_iocs(self, iocs: Dict) -> Dict:
        """Remove duplicate IOCs while preserving order"""
        for key in ["ip_addresses", "domains", "urls", "email_addresses", 
                    "registry_keys", "file_paths", "processes", "users"]:
            if key in iocs:
                iocs[key] = list(dict.fromkeys(iocs[key]))
        
        # Deduplicate hashes
        for hash_type in iocs["file_hashes"]:
            iocs["file_hashes"][hash_type] = list(dict.fromkeys(iocs["file_hashes"][hash_type]))
        
        return iocs
    
    def _generate_summary(self, iocs: Dict) -> Dict[str, int]:
        """Generate summary statistics"""
        return {
            "unique_ip_addresses": len(iocs["ip_addresses"]),
            "unique_domains": len(iocs["domains"]),
            "unique_urls": len(iocs["urls"]),
            "unique_emails": len(iocs["email_addresses"]),
            "total_file_hashes": sum(len(hashes) for hashes in iocs["file_hashes"].values()),
            "unique_registry_keys": len(iocs["registry_keys"]),
            "unique_file_paths": len(iocs["file_paths"]),
            "unique_processes": len(iocs["processes"]),
            "unique_users": len(iocs["users"])
        }
    
    def _compile_ip_patterns(self) -> re.Pattern:
        """Compile IP address patterns"""
        # IPv4 and IPv6 patterns
        ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        return re.compile(f'{ipv4_pattern}|{ipv6_pattern}')
    
    def _compile_hash_patterns(self) -> re.Pattern:
        """Compile hash patterns (MD5, SHA1, SHA256)"""
        md5 = r'\b[a-fA-F0-9]{32}\b'
        sha1 = r'\b[a-fA-F0-9]{40}\b'
        sha256 = r'\b[a-fA-F0-9]{64}\b'
        return re.compile(f'{md5}|{sha1}|{sha256}')
    
    def _compile_url_patterns(self) -> re.Pattern:
        """Compile URL patterns"""
        return re.compile(
            r'\b(?:https?://|ftp://)[^\s/$.?#].[^\s]*',
            re.IGNORECASE
        )
    
    def _compile_email_patterns(self) -> re.Pattern:
        """Compile email patterns"""
        return re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            re.IGNORECASE
        )
    
    def _compile_domain_patterns(self) -> re.Pattern:
        """Compile domain patterns"""
        return re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            re.IGNORECASE
        )
    
    def _compile_registry_patterns(self) -> re.Pattern:
        """Compile Windows registry key patterns"""
        return re.compile(
            r'\b[HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU|HKCR|HKU][\\].*',
            re.IGNORECASE
        )
    
    def _compile_file_path_patterns(self) -> re.Pattern:
        """Compile file path patterns"""
        return re.compile(
            r'\b[A-Z]:\\(?:[^<>:"/\\|?*\n\r]+\\)*[^<>:"/\\|?*\n\r]*',
            re.IGNORECASE
        )
    
    def _compile_process_patterns(self) -> re.Pattern:
        """Compile process name patterns"""
        return re.compile(
            r'\b[a-zA-Z0-9_\-]+\.exe\b|\b[a-zA-Z0-9_\-]+\.dll\b',
            re.IGNORECASE
        )
    
    def _identify_hash_type(self, hash_value: str) -> str:
        """Identify hash type based on length"""
        length = len(hash_value)
        if length == 32:
            return "MD5"
        elif length == 40:
            return "SHA1"
        elif length == 64:
            return "SHA256"
        else:
            return "Unknown"


class IOCPrioritizer:
    """Prioritizes IOCs based on risk and relevance"""
    
    def __init__(self):
        self.high_risk_domains = [
            'malware.com', 'evil.com', 'suspicious.net'
        ]
        self.high_risk_ports = [4444, 6666, 1337, 31337]
    
    def prioritize_iocs(self, iocs: Dict[str, Any]) -> Dict[str, Any]:
        """Prioritize IOCs based on risk factors"""
        prioritized = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        # Prioritize IP addresses
        for ip in iocs.get("ip_addresses", []):
            priority = self._assess_ip_risk(ip)
            prioritized[priority].append({"type": "ip", "value": ip})
        
        # Prioritize domains
        for domain in iocs.get("domains", []):
            priority = self._assess_domain_risk(domain)
            prioritized[priority].append({"type": "domain", "value": domain})
        
        # Prioritize file hashes
        for hash_type, hashes in iocs.get("file_hashes", {}).items():
            for hash_value in hashes:
                priority = self._assess_hash_risk(hash_value, hash_type)
                prioritized[priority].append({
                    "type": "hash",
                    "hash_type": hash_type,
                    "value": hash_value
                })
        
        # Prioritize URLs
        for url in iocs.get("urls", []):
            priority = self._assess_url_risk(url)
            prioritized[priority].append({"type": "url", "value": url})
        
        return prioritized
    
    def _assess_ip_risk(self, ip: str) -> str:
        """Assess risk level of IP address"""
        try:
            ip_obj = ip_address(ip)
            
            # Check for private/internal IPs
            if ip_obj.is_private:
                return "low"
            
            # Check for loopback
            if ip_obj.is_loopback:
                return "low"
            
            # Check for reserved ranges
            if ip_obj.is_reserved:
                return "medium"
            
            # External IPs get higher priority
            return "high"
            
        except ValueError:
            return "medium"
    
    def _assess_domain_risk(self, domain: str) -> str:
        """Assess risk level of domain"""
        domain_lower = domain.lower()
        
        # Check against known bad domains
        if any(bad in domain_lower for bad in self.high_risk_domains):
            return "critical"
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.zip', '.mov']
        if any(domain_lower.endswith(tld) for tld in suspicious_tlds):
            return "high"
        
        # Check for domain age indicators (new registrations)
        # This would need external API integration
        
        return "medium"
    
    def _assess_hash_risk(self, hash_value: str, hash_type: str) -> str:
        """Assess risk level of file hash"""
        # This would typically check against threat intelligence feeds
        # For now, use heuristics
        
        # SHA256 hashes are more reliable than MD5
        if hash_type == "MD5":
            return "medium"
        elif hash_type in ["SHA1", "SHA256"]:
            return "high"
        
        return "medium"
    
    def _assess_url_risk(self, url: str) -> str:
        """Assess risk level of URL"""
        try:
            parsed = urlparse(url)
            
            # Check for suspicious protocols
            if parsed.scheme in ['ftp', 'http']:
                return "high"
            
            # Check for IP addresses instead of domains
            try:
                ip_address(parsed.netloc)
                return "high"
            except ValueError:
                pass
            
            # Check for suspicious paths
            suspicious_paths = ['/upload', '/admin', '/login', '/wp-admin']
            if any(path in parsed.path.lower() for path in suspicious_paths):
                return "high"
            
            return "medium"
            
        except Exception:
            return "medium"