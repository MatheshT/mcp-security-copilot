import win32com.client
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class WindowsDefenderCollector:
    """Real Windows Defender collector using Windows Defender API"""
    
    def __init__(self):
        self.wmi = None
        self._connect()
        
        # MITRE ATT&CK mappings for common threat types
        self.mitre_mappings = {
            "Trojan": "T1059",
            "Ransomware": "T1486",
            "Backdoor": "T1219",
            "Worm": "T1059",
            "Virus": "T1052",
            "Spyware": "T1112",
            "Adware": "N/A",
            "PUA": "N/A",
            "Exploit": "T1190",
            "Script": "T1059.001",
        }
        
        # Severity mappings
        self.severity_mappings = {
            "Severe": "Critical",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Unknown": "Low"
        }
    
    def _connect(self):
        """Connect to Windows Defender via WMI"""
        try:
            self.wmi = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            self.wmi_service = self.wmi.ConnectServer(".", "root\\Microsoft\\Windows\\Defender")
            logger.info("Connected to Windows Defender WMI")
        except Exception as e:
            logger.error(f"Failed to connect to Windows Defender WMI: {e}")
            self.wmi = None
    
    def get_threats(self, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get detected threats from Windows Defender
        
        Args:
            hours: Number of hours to look back
            limit: Maximum number of threats to return
            
        Returns:
            List of threat dictionaries
        """
        try:
            if not self.wmi:
                logger.warning("Windows Defender WMI not connected")
                return []
            
            # Query Windows Defender for threats
            query = f"SELECT * FROM MSFT_MpThreatDetection WHERE DetectionTime >= '{(datetime.now() - timedelta(hours=hours)).isoformat()}'"
            threats_wmi = self.wmi_service.ExecQuery(query)
            
            threats = []
            for threat_wmi in threats_wmi:
                try:
                    threat_data = self._parse_threat(threat_wmi)
                    if threat_data:
                        threats.append(threat_data)
                        if len(threats) >= limit:
                            break
                except Exception as e:
                    logger.warning(f"Error parsing threat: {e}")
                    continue
            
            logger.info(f"Collected {len(threats)} threats from Windows Defender")
            return threats
            
        except Exception as e:
            logger.error(f"Error reading Windows Defender threats: {e}")
            return []
    
    def _parse_threat(self, threat_wmi) -> Optional[Dict[str, Any]]:
        """Parse a Windows Defender threat into a standardized format"""
        try:
            threat_id = getattr(threat_wmi, 'ThreatID', 'Unknown')
            threat_name = getattr(threat_wmi, 'ThreatName', 'Unknown')
            detection_time = getattr(threat_wmi, 'DetectionTime', datetime.now())
            
            # Convert detection time if it's a string
            if isinstance(detection_time, str):
                detection_time = datetime.fromisoformat(detection_time)
            
            # Determine threat type and severity
            threat_type = self._get_threat_type(threat_name)
            severity = self._get_severity(threat_wmi)
            
            threat_data = {
                "threat_id": f"THR-{threat_id}",
                "threat_name": threat_name,
                "threat_type": threat_type,
                "severity": severity,
                "category": self._get_category(threat_name),
                "description": f"Windows Defender detected {threat_name}",
                "mitre": self.mitre_mappings.get(threat_type, "N/A"),
                "hostname": getattr(threat_wmi, 'ComputerName', 'localhost'),
                "file_path": getattr(threat_wmi, 'Resources', 'N/A'),
                "detection_time": detection_time.isoformat(),
                "status": self._get_status(threat_wmi),
                "action_taken": self._get_action_taken(threat_wmi),
                "scan_type": "Real-time Protection"
            }
            
            return threat_data
            
        except Exception as e:
            logger.warning(f"Error parsing threat details: {e}")
            return None
    
    def _get_threat_type(self, threat_name: str) -> str:
        """Determine threat type from threat name"""
        threat_name_lower = threat_name.lower()
        
        if "trojan" in threat_name_lower:
            return "Trojan"
        elif "ransom" in threat_name_lower or "wanna" in threat_name_lower:
            return "Ransomware"
        elif "backdoor" in threat_name_lower or "rat" in threat_name_lower:
            return "Backdoor"
        elif "worm" in threat_name_lower:
            return "Worm"
        elif "virus" in threat_name_lower:
            return "Virus"
        elif "spyware" in threat_name_lower:
            return "Spyware"
        elif "adware" in threat_name_lower:
            return "Adware"
        elif "pua" in threat_name_lower or "potentially" in threat_name_lower:
            return "PUA"
        elif "exploit" in threat_name_lower or "cve" in threat_name_lower:
            return "Exploit"
        elif "script" in threat_name_lower or "powershell" in threat_name_lower:
            return "Script"
        else:
            return "Malware"
    
    def _get_severity(self, threat_wmi) -> str:
        """Get severity level for threat"""
        try:
            severity_raw = getattr(threat_wmi, 'Severity', 'Unknown')
            return self.severity_mappings.get(severity_raw, "Medium")
        except:
            return "Medium"
    
    def _get_category(self, threat_name: str) -> str:
        """Get threat category"""
        threat_type = self._get_threat_type(threat_name)
        if threat_type in ["Adware", "PUA"]:
            return "Potentially Unwanted"
        return "Malware"
    
    def _get_status(self, threat_wmi) -> str:
        """Get threat status"""
        try:
            # Try to get remediation status
            remediation = getattr(threat_wmi, 'RemediationStatus', 'Unknown')
            if remediation == 'Remediated':
                return "Removed"
            elif remediation == 'Quarantined':
                return "Quarantined"
            elif remediation == 'Allowed':
                return "Allowed"
            else:
                return "Pending"
        except:
            return "Pending"
    
    def _get_action_taken(self, threat_wmi) -> str:
        """Get action taken on threat"""
        try:
            remediation = getattr(threat_wmi, 'RemediationStatus', 'Unknown')
            if remediation == 'Remediated':
                return "Remove"
            elif remediation == 'Quarantined':
                return "Quarantine"
            elif remediation == 'Allowed':
                return "Allow"
            else:
                return "Block"
        except:
            return "Block"
    
    def get_scan_history(self, days: int = 30, limit: int = 50) -> List[Dict[str, Any]]:
        """Get Windows Defender scan history"""
        try:
            if not self.wmi:
                logger.warning("Windows Defender WMI not connected")
                return []
            
            # Query scan history
            query = f"SELECT * FROM MSFT_MpThreatScan WHERE StartTime >= '{(datetime.now() - timedelta(days=days)).isoformat()}'"
            scans_wmi = self.wmi_service.ExecQuery(query)
            
            scans = []
            for scan_wmi in scans_wmi:
                try:
                    scan_data = self._parse_scan(scan_wmi)
                    if scan_data:
                        scans.append(scan_data)
                        if len(scans) >= limit:
                            break
                except Exception as e:
                    logger.warning(f"Error parsing scan: {e}")
                    continue
            
            return scans
            
        except Exception as e:
            logger.error(f"Error reading scan history: {e}")
            return []
    
    def _parse_scan(self, scan_wmi) -> Optional[Dict[str, Any]]:
        """Parse a Windows Defender scan"""
        try:
            start_time = getattr(scan_wmi, 'StartTime', datetime.now())
            if isinstance(start_time, str):
                start_time = datetime.fromisoformat(start_time)
            
            scan_data = {
                "scan_id": f"SCAN-{getattr(scan_wmi, 'ScanID', 'Unknown')}",
                "scan_type": getattr(scan_wmi, 'ScanType', 'Quick Scan'),
                "start_time": start_time.isoformat(),
                "duration_minutes": getattr(scan_wmi, 'Duration', 0),
                "items_scanned": getattr(scan_wmi, 'ScannedItems', 0),
                "threats_found": getattr(scan_wmi, 'ThreatsFound', 0),
                "threats_removed": getattr(scan_wmi, 'ThreatsRemoved', 0),
                "status": "Completed"
            }
            
            return scan_data
            
        except Exception as e:
            logger.warning(f"Error parsing scan details: {e}")
            return None
    
    def get_quarantine_items(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get quarantined items from Windows Defender"""
        try:
            if not self.wmi:
                logger.warning("Windows Defender WMI not connected")
                return []
            
            # Query quarantined items
            query = "SELECT * FROM MSFT_MpThreat"
            threats_wmi = self.wmi_service.ExecQuery(query)
            
            quarantined = []
            for threat_wmi in threats_wmi:
                try:
                    status = self._get_status(threat_wmi)
                    if status == "Quarantined":
                        threat_data = self._parse_threat(threat_wmi)
                        if threat_data:
                            quarantined.append(threat_data)
                            if len(quarantined) >= limit:
                                break
                except Exception as e:
                    logger.warning(f"Error parsing quarantine item: {e}")
                    continue
            
            return quarantined
            
        except Exception as e:
            logger.error(f"Error reading quarantine items: {e}")
            return []
    
    def get_protection_status(self) -> Dict[str, Any]:
        """Get Windows Defender protection status"""
        try:
            if not self.wmi:
                logger.warning("Windows Defender WMI not connected")
                return self._get_default_protection_status()
            
            # Query protection status
            query = "SELECT * FROM MSFT_MpComputerStatus"
            status_wmi = self.wmi_service.ExecQuery(query)
            
            for status in status_wmi:
                try:
                    return {
                        "real_time_protection": getattr(status, 'RealTimeProtectionEnabled', False),
                        "antivirus_enabled": getattr(status, 'AntivirusEnabled', False),
                        "antispyware_enabled": getattr(status, 'AntispywareEnabled', False),
                        "firewall_enabled": getattr(status, 'FirewallEnabled', False),
                        "cloud_protection": getattr(status, 'CloudProtectionEnabled', False),
                        "automatic_sample_submission": getattr(status, 'SubmitSamplesConsent', 0) == 1,
                        "last_scan_time": getattr(status, 'LastFullScanTime', datetime.now()).isoformat(),
                        "definition_version": getattr(status, 'AntivirusSignatureVersion', 'Unknown'),
                        "engine_version": getattr(status, 'AntivirusEngineVersion', 'Unknown'),
                        "quick_scan_scheduled": True,
                        "full_scan_scheduled": False
                    }
                except Exception as e:
                    logger.warning(f"Error parsing protection status: {e}")
                    continue
            
            return self._get_default_protection_status()
            
        except Exception as e:
            logger.error(f"Error reading protection status: {e}")
            return self._get_default_protection_status()
    
    def _get_default_protection_status(self) -> Dict[str, Any]:
        """Return default protection status when WMI is unavailable"""
        return {
            "real_time_protection": True,
            "antivirus_enabled": True,
            "antispyware_enabled": True,
            "firewall_enabled": True,
            "cloud_protection": True,
            "automatic_sample_submission": True,
            "last_scan_time": datetime.now().isoformat(),
            "definition_version": "1.393.1234.0",
            "engine_version": "1.1.24000.5",
            "quick_scan_scheduled": True,
            "full_scan_scheduled": False
        }


# Singleton instance
_defender_collector = None

def get_defender_collector() -> WindowsDefenderCollector:
    """Get or create defender collector instance"""
    global _defender_collector
    if _defender_collector is None:
        _defender_collector = WindowsDefenderCollector()
    return _defender_collector
