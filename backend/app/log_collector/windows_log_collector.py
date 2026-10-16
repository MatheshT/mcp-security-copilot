"""
Windows Log Collector Module
Collects Windows Event Logs, Sysmon logs, and Windows Defender logs
"""
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32security
    import pythoncom
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False

from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
import xml.etree.ElementTree as ET
import re
from ..utils.logger import get_logger

logger = get_logger(__name__)


class PowerShellLogCollector:
    """Fallback collector used on non-Windows hosts or when PowerShell log collection is unavailable."""
    async def collect_logs(self, hours_back: int = 24) -> Dict[str, Any]:
        return {
            "source": "powershell",
            "collected_at": datetime.now().isoformat(),
            "hours_back": hours_back,
            "total_logs": 0,
            "logs": [],
            "mock_data": True,
            "platform_available": WINDOWS_AVAILABLE,
        }


class FirewallLogCollector:
    """Fallback collector for firewall logs on non-Windows or restricted hosts."""
    async def collect_logs(self, hours_back: int = 24) -> Dict[str, Any]:
        return {
            "source": "firewall",
            "collected_at": datetime.now().isoformat(),
            "hours_back": hours_back,
            "total_logs": 0,
            "logs": [],
            "mock_data": True,
            "platform_available": WINDOWS_AVAILABLE,
        }


class IISLogCollector:
    """Fallback collector for IIS logs when the host is not Windows or IIS is not installed."""
    async def collect_logs(self, hours_back: int = 24) -> Dict[str, Any]:
        return {
            "source": "iis",
            "collected_at": datetime.now().isoformat(),
            "hours_back": hours_back,
            "total_logs": 0,
            "logs": [],
            "mock_data": True,
            "platform_available": WINDOWS_AVAILABLE,
        }


class WindowsLogCollector:
    """Collects various Windows log sources"""
    
    def __init__(self):
        self.log_sources = {
            'windows_event': WindowsEventLogCollector(),
            'sysmon': SysmonLogCollector(),
            'defender': DefenderLogCollector(),
            'powershell': PowerShellLogCollector(),
            'firewall': FirewallLogCollector(),
            'iis': IISLogCollector()
        }
    
    async def collect_all_logs(self, hours_back: int = 24) -> Dict[str, Any]:
        """Collect logs from all configured sources"""
        if not WINDOWS_AVAILABLE:
            logger.warning("Windows log collection not available on this platform")
            return {
                "error": "Windows log collection requires Windows platform",
                "logs": [],
                "platform_available": False
            }
        
        results = {}
        for source_name, collector in self.log_sources.items():
            try:
                logger.info(f"Collecting logs from {source_name}")
                results[source_name] = await collector.collect_logs(hours_back)
            except Exception as e:
                logger.error(f"Error collecting from {source_name}: {e}")
                results[source_name] = {"error": str(e), "logs": []}
        return results
    
    async def collect_specific_source(self, source: str, hours_back: int = 24) -> Dict[str, Any]:
        """Collect logs from a specific source"""
        if not WINDOWS_AVAILABLE:
            logger.warning("Windows log collection not available on this platform")
            return {
                "error": "Windows log collection requires Windows platform",
                "logs": [],
                "platform_available": False
            }
        
        if source not in self.log_sources:
            raise ValueError(f"Unknown log source: {source}")
        return await self.log_sources[source].collect_logs(hours_back)


class WindowsEventLogCollector:
    """Collects Windows Event Logs"""
    
    EVENT_LOGS = [
        'Security',
        'System',
        'Application',
        'Windows PowerShell',
        'Microsoft-Windows-Sysmon/Operational'
    ]
    
    def __init__(self):
        self.server = None  # None for local machine
    
    async def collect_logs(self, hours_back: int = 24) -> Dict[str, Any]:
        """Collect Windows Event Logs"""
        if not WINDOWS_AVAILABLE:
            return self._generate_mock_logs("windows_event", hours_back)
        
        logs = []
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        
        for log_name in self.EVENT_LOGS:
            try:
                log_data = self._collect_log_file(log_name, cutoff_time)
                logs.extend(log_data)
            except Exception as e:
                logger.error(f"Error collecting {log_name}: {e}")
        
        return {
            "source": "windows_event",
            "collected_at": datetime.now().isoformat(),
            "hours_back": hours_back,
            "total_logs": len(logs),
            "logs": logs
        }
    
    def _collect_log_file(self, log_name: str, cutoff_time: datetime) -> List[Dict]:
        """Collect events from a specific log file"""
        logs = []
        try:
            hand = win32evtlog.OpenEventLog(self.server, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events = 1
            while events:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
                for event in events:
                    event_time = event.TimeGenerated
                    if event_time < cutoff_time:
                        events = None
                        break
                    
                    log_entry = self._parse_event(event, log_name)
                    if log_entry:
                        logs.append(log_entry)
            
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            logger.error(f"Error reading {log_name}: {e}")
        
        return logs
    
    def _parse_event(self, event, log_name: str) -> Optional[Dict]:
        """Parse Windows Event Log entry"""
        try:
            return {
                "log_source": "windows_event",
                "log_name": log_name,
                "event_id": event.EventID,
                "timestamp": event.TimeGenerated.isoformat(),
                "computer_name": event.ComputerName,
                "source": event.SourceName,
                "category": str(event.EventCategory),
                "type": {
                    1: "Error",
                    2: "Warning",
                    4: "Information",
                    8: "Success Audit",
                    16: "Failure Audit",
                    0: "Success"
                }.get(event.EventType, "Information"),
                "record_number": event.RecordNumber,
                "user": event.Sid if hasattr(event, 'Sid') else None,
                "data": self._extract_event_data(event),
                "xml_representation": self._get_event_xml(event)
            }
        except Exception as e:
            logger.error(f"Error parsing event: {e}")
            return None
    
    def _extract_event_data(self, event) -> Dict[str, Any]:
        """Extract relevant data from event"""
        data = {}
        if event.StringInserts:
            data["strings"] = event.StringInserts
        if event.Data:
            data["raw_data"] = event.Data.hex() if isinstance(event.Data, bytes) else str(event.Data)
        return data
    
    def _get_event_xml(self, event) -> str:
        """Get XML representation of event if available"""
        try:
            return win32evtlogutil.SafeFormatEvent(event)
        except:
            return ""
    
    def _generate_mock_logs(self, source: str, hours_back: int) -> Dict[str, Any]:
        """Generate mock logs for demonstration when Windows APIs are not available"""
        import random
        
        mock_logs = []
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        
        # Generate some sample logs
        for i in range(50):
            event_types = ["Information", "Warning", "Error"]
            sources = ["Security", "System", "Application", "PowerShell"]
            
            mock_log = {
                "log_source": source,
                "log_name": random.choice(sources),
                "event_id": random.randint(1000, 9999),
                "timestamp": (cutoff_time + timedelta(hours=random.random() * hours_back)).isoformat(),
                "computer_name": "DESKTOP-" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=7)),
                "source": random.choice(sources),
                "category": "Mock Category",
                "type": random.choice(event_types),
                "record_number": i,
                "user": f"User{random.randint(1, 10)}",
                "data": {
                    "strings": [f"Mock data string {j}" for j in range(3)],
                    "mock": True
                },
                "xml_representation": f"<Event><System><EventID>{random.randint(1000, 9999)}</EventID></System></Event>"
            }
            mock_logs.append(mock_log)
        
        return {
            "source": source,
            "collected_at": datetime.now().isoformat(),
            "hours_back": hours_back,
            "total_logs": len(mock_logs),
            "logs": mock_logs,
            "mock_data": True,
            "platform_available": False
        }


class SysmonLogCollector:
    """Collects Sysmon logs specifically"""
    
    SYSMON_EVENT_IDS = {
        1: "Process creation",
        2: "File creation time changed",
        3: "Network connection",
        4: "Sysmon service state changed",
        5: "Process terminated",
        6: "Driver loaded",
        7: "Image loaded",
        8: "CreateRemoteThread",
        9: "RawAccessRead",
        10: "ProcessAccess",
        11: "FileCreate",
        12: "Registry object added or deleted",
        13: "Registry value set",
        14: "Registry value renamed",
        15: "FileCreateStreamHash",
        16: "Sysmon config change",
        17: "Pipe created",
        18: "Pipe connected",
        19: "WMI Event filter",
        20: "WMI Event consumer",
        21: "WMI Event consumer to filter",
        22: "DNS query",
        23: "File delete",
        24: "Clipboard change",
        25: "Process tampering",
        26: "Image loaded",
        27: "File block executable",
        28: "File block shredded"
    }
    
    def __init__(self):
        self.collector = WindowsEventLogCollector()
    
    async def collect_logs(self, hours_back: int = 24) -> Dict[str, Any]:
        """Collect Sysmon logs"""
        if not WINDOWS_AVAILABLE:
            # Generate mock Sysmon logs
            mock_logs = self.collector._generate_mock_logs("sysmon", hours_back)["logs"]
            enhanced_logs = []
            for log in mock_logs:
                enhanced = self._enhance_sysmon_log(log)
                if enhanced:
                    enhanced_logs.append(enhanced)
            return {
                "source": "sysmon",
                "collected_at": datetime.now().isoformat(),
                "hours_back": hours_back,
                "total_logs": len(enhanced_logs),
                "logs": enhanced_logs,
                "mock_data": True,
                "platform_available": False
            }
        
        # Sysmon logs are in Windows Event Log under specific channel
        sysmon_logs = self.collector._collect_log_file(
            'Microsoft-Windows-Sysmon/Operational',
            datetime.now() - timedelta(hours=hours_back)
        )
        
        # Filter and enhance Sysmon-specific events
        enhanced_logs = []
        for log in sysmon_logs:
            enhanced = self._enhance_sysmon_log(log)
            if enhanced:
                enhanced_logs.append(enhanced)
        
        return {
            "source": "sysmon",
            "collected_at": datetime.now().isoformat(),
            "hours_back": hours_back,
            "total_logs": len(enhanced_logs),
            "logs": enhanced_logs
        }
    
    def _enhance_sysmon_log(self, log: Dict) -> Optional[Dict]:
        """Enhance Sysmon log with additional context"""
        event_id = log.get("event_id")
        if event_id not in self.SYSMON_EVENT_IDS:
            return None
        
        log["event_type"] = self.SYSMON_EVENT_IDS[event_id]
        log["ioc_candidates"] = self._extract_iocs(log)
        
        return log
    
    def _extract_iocs(self, log: Dict) -> Dict[str, List[str]]:
        """Extract potential IOCs from Sysmon log"""
        iocs = {
            "ip_addresses": [],
            "domains": [],
            "hashes": [],
            "processes": [],
            "users": []
        }
        
        data = log.get("data", {})
        strings = data.get("strings", [])
        
        # Extract IPs and domains from network events
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b'
        
        for string in strings:
            if isinstance(string, str):
                iocs["ip_addresses"].extend(re.findall(ip_pattern, string))
                iocs["domains"].extend(re.findall(domain_pattern, string))
        
        # Extract hashes (MD5, SHA1, SHA256)
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b'   # SHA256
        ]
        
        for string in strings:
            if isinstance(string, str):
                for pattern in hash_patterns:
                    matches = re.findall(pattern, string)
                    iocs["hashes"].extend(matches)
        
        return iocs


class DefenderLogCollector:
    """Collects Windows Defender logs"""
    
    def __init__(self):
        self.collector = WindowsEventLogCollector()
    
    async def collect_logs(self, hours_back: int = 24) -> Dict[str, Any]:
        """Collect Windows Defender logs"""
        if not WINDOWS_AVAILABLE:
            # Generate mock Defender logs
            mock_logs = self.collector._generate_mock_logs("defender", hours_back)["logs"]
            enhanced_logs = []
            for log in mock_logs:
                enhanced = self._enhance_defender_log(log)
                if enhanced:
                    enhanced_logs.append(enhanced)
            return {
                "source": "defender",
                "collected_at": datetime.now().isoformat(),
                "hours_back": hours_back,
                "total_logs": len(enhanced_logs),
                "logs": enhanced_logs,
                "mock_data": True,
                "platform_available": False
            }
        
        defender_logs = self.collector._collect_log_file(
            'Microsoft-Windows-Windows Defender/Operational',
            datetime.now() - timedelta(hours=hours_back)
        )
        
        # Filter and enhance Defender-specific events
        enhanced_logs = []
        for log in defender_logs:
            enhanced = self._enhance_defender_log(log)
            if enhanced:
                enhanced_logs.append(enhanced)
        
        return {
            "source": "defender",
            "collected_at": datetime.now().isoformat(),
            "hours_back": hours_back,
            "total_logs": len(enhanced_logs),
            "logs": enhanced_logs
        }
    
    def _enhance_defender_log(self, log: Dict) -> Optional[Dict]:
        """Enhance Defender log with threat information"""
        event_id = log.get("event_id")
        
        # Focus on threat detection events
        threat_events = [1116, 1117, 1118, 1119, 1120, 1121, 1122, 1123]
        if event_id not in threat_events:
            return None
        
        log["threat_type"] = self._classify_threat(event_id)
        log["severity"] = self._get_severity(event_id)
        log["ioc_candidates"] = self._extract_defender_iocs(log)
        
        return log
    
    def _classify_threat(self, event_id: int) -> str:
        """Classify threat type based on event ID"""
        threat_types = {
            1116: "Malware detected",
            1117: "Spyware detected",
            1118: "Potentially unwanted program detected",
            1119: "Threat action failed",
            1120: "Threat remediation started",
            1121: "Threat remediation succeeded",
            1122: "Threat remediation failed",
            1123: "Threat cleanup"
        }
        return threat_types.get(event_id, "Unknown threat")
    
    def _get_severity(self, event_id: int) -> str:
        """Get severity level for event"""
        high_severity = [1116, 1117, 1118]
        return "High" if event_id in high_severity else "Medium"
    
    def _extract_defender_iocs(self, log: Dict) -> Dict[str, List[str]]:
        """Extract IOCs from Defender logs"""
        iocs = {
            "threat_names": [],
            "file_paths": [],
            "hashes": [],
            "urls": []
        }
        
        data = log.get("data", {})
        strings = data.get("strings", [])
        
        for string in strings:
            if isinstance(string, str):
                # Extract file paths
                if '\\' in string and (".exe" in string or ".dll" in string):
                    iocs["file_paths"].append(string)
                
                # Extract URLs
                if string.startswith(("http://", "https://")):
                    iocs["urls"].append(string)
                
                # Extract threat names
                if any(keyword in string.lower() for keyword in ["trojan", "malware", "virus", "ransomware"]):
                    iocs["threat_names"].append(string)
        
        return iocs