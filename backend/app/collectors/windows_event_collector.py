import win32evtlog
import win32con
import win32security
import win32api
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class WindowsEventCollector:
    """Real Windows Event Log collector using pywin32"""
    
    def __init__(self):
        self.server = None  # None for local machine
        # Use log names directly instead of constants
        self.log_types = {
            'Security': 'Security',
            'System': 'System', 
            'Application': 'Application'
        }
        
        # MITRE ATT&CK mappings for common Windows event IDs
        self.mitre_mappings = {
            4625: "T1110.001",  # Brute Force: Password Guessing
            4624: "N/A",       # Successful Login
            4688: "T1059",     # Command and Scripting Interpreter
            4720: "T1136",     # Create Account: Local Account
            4728: "T1098",     # Account Manipulation: Additional Group Membership
            4732: "T1068",     # Execution: Shared Library Module
            4740: "T1111",     # Brute Force: Password Spraying
            4662: "T1078",     # Valid Accounts
            4672: "T1078",     # Valid Accounts: Admin Rights
            4658: "T1003",     # OS Credential Dumping
            4656: "T1003",     # OS Credential Dumping
            7045: "T1543",     # Create or Modify System Process: Windows Service
            104: "T1053",      # Scheduled Task/Job: Scheduled Task
            4689: "T1059.003", # Command and Scripting Interpreter: Windows Command Shell
            4688: "T1059.001", # Command and Scripting Interpreter: PowerShell
            5058: "T1547",     # Boot or Logon Autostart Execution
        }
        
        # Severity mappings
        self.severity_mappings = {
            4625: "Critical",  # Failed login
            4740: "Critical",  # Account lockout
            4720: "High",      # User account created
            4732: "High",      # Added to privileged group
            4688: "Medium",    # Process creation
            7045: "High",      # Service installed
            4662: "High",      # Special privileges assigned
            4672: "High",      # Admin rights assigned
        }
        
        # Event descriptions
        self.event_descriptions = {
            4625: "An account failed to log on",
            4624: "An account was successfully logged on",
            4688: "A new process has been created",
            4720: "A user account was created",
            4732: "A member was added to a security-enabled global group",
            4740: "A user account was locked out",
            7045: "A service was installed in the system",
            104: "A task was registered in the Task Scheduler",
            4662: "Special privileges assigned to new logon",
            4672: "Special privileges assigned to new logon",
        }
    
    def get_events(self, log_name: str = 'Security', hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get events from Windows Event Log
        
        Args:
            log_name: Log name (Security, System, Application)
            hours: Number of hours to look back
            limit: Maximum number of events to return
            
        Returns:
            List of event dictionaries
        """
        try:
            hand = win32evtlog.OpenEventLog(self.server, log_name)
            
            events = []
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            # Calculate time threshold
            time_threshold = datetime.now() - timedelta(hours=hours)
            
            while len(events) < limit:
                events_raw = win32evtlog.ReadEventLog(hand, flags, 0)
                
                if not events_raw:
                    break
                
                for event in events_raw:
                    try:
                        event_data = self._parse_event(event, log_name, time_threshold)
                        if event_data:
                            events.append(event_data)
                            if len(events) >= limit:
                                break
                    except Exception as e:
                        logger.warning(f"Error parsing event: {e}")
                        continue
            
            win32evtlog.CloseEventLog(hand)
            
            logger.info(f"Collected {len(events)} events from {log_name} log")
            return events
            
        except Exception as e:
            logger.error(f"Error reading Windows Event Log {log_name}: {e}")
            return []
    
    def _parse_event(self, event, log_name: str, time_threshold: datetime) -> Optional[Dict[str, Any]]:
        """Parse a Windows event into a standardized format"""
        try:
            # Convert event time
            event_time = event.TimeGenerated
            if isinstance(event_time, str):
                event_time = datetime.fromisoformat(event_time)
            
            # Skip events older than threshold
            if event_time < time_threshold:
                return None
            
            event_id = event.EventID
            computer_name = event.ComputerName or "localhost"
            
            # Get event data
            event_data = {
                "event_id": f"EVT-{event_id}-{event.RecordNumber}",
                "windows_event_id": event_id,
                "source": event.SourceName,
                "channel": log_name,
                "severity": self._get_severity(event_id),
                "title": self._get_title(event_id),
                "description": self._get_description(event_id),
                "mitre": self.mitre_mappings.get(event_id, "N/A"),
                "hostname": computer_name,
                "username": self._extract_username(event),
                "source_ip": self._extract_ip(event),
                "timestamp": event_time.isoformat(),
                "status": "Open" if self._get_severity(event_id) in ["Critical", "High"] else "Resolved"
            }
            
            return event_data
            
        except Exception as e:
            logger.warning(f"Error parsing event details: {e}")
            return None
    
    def _get_severity(self, event_id: int) -> str:
        """Get severity level for event ID"""
        return self.severity_mappings.get(event_id, "Low")
    
    def _get_title(self, event_id: int) -> str:
        """Get title for event ID"""
        titles = {
            4625: "Failed Login Attempt",
            4624: "Successful Login",
            4688: "Process Creation",
            4720: "User Account Created",
            4732: "Added to Privileged Group",
            4740: "Account Locked Out",
            7045: "Service Installed",
            104: "Task Scheduled",
            4662: "Special Privileges Assigned",
            4672: "Admin Rights Assigned",
        }
        return titles.get(event_id, f"Event ID {event_id}")
    
    def _get_description(self, event_id: int) -> str:
        """Get description for event ID"""
        return self.event_descriptions.get(event_id, "Windows Event Log entry")
    
    def _extract_username(self, event) -> str:
        """Extract username from event data"""
        try:
            if event.StringInserts and len(event.StringInserts) > 0:
                # Try to find username in string inserts
                for insert in event.StringInserts:
                    if insert and '\\' in str(insert):
                        return str(insert).split('\\')[-1]
                    if insert and not str(insert).startswith('\\'):
                        return str(insert)
            return "system"
        except:
            return "system"
    
    def _extract_ip(self, event) -> str:
        """Extract IP address from event data"""
        try:
            if event.StringInserts:
                for insert in event.StringInserts:
                    if insert and self._is_ip_address(str(insert)):
                        return str(insert)
            return "N/A"
        except:
            return "N/A"
    
    def _is_ip_address(self, s: str) -> bool:
        """Check if string is an IP address"""
        parts = s.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except:
            return False

    def get_security_events(self, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """Get security events with error handling for Windows log access"""
        try:
            logger.info(f"Attempting to collect security events from Windows Event Log (last {hours} hours)")
            events = self.get_events('Security', hours, limit)
            logger.info(f"Successfully collected {len(events)} security events from Windows Event Log")
            return events
        except Exception as e:
            logger.error(f"Error collecting security events: {e}")
            logger.info("Windows Event Log access failed - this is expected on non-Windows platforms or without admin rights")
            return []
    
    def get_security_events(self, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """Get security events"""
        return self.get_events('Security', hours, limit)
    
    def get_system_events(self, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """Get system events"""
        return self.get_events('System', hours, limit)
    
    def get_application_events(self, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """Get application events"""
        return self.get_events('Application', hours, limit)
    
    def get_failed_logins(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get failed login events (Event ID 4625)"""
        all_events = self.get_security_events(hours, limit=1000)
        return [e for e in all_events if e.get('windows_event_id') == 4625]
    
    def get_successful_logins(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get successful login events (Event ID 4624)"""
        all_events = self.get_security_events(hours, limit=1000)
        return [e for e in all_events if e.get('windows_event_id') == 4624]
    
    def get_account_lockouts(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get account lockout events (Event ID 4740)"""
        all_events = self.get_security_events(hours, limit=1000)
        return [e for e in all_events if e.get('windows_event_id') == 4740]


# Singleton instance
_event_collector = None

def get_event_collector() -> WindowsEventCollector:
    """Get or create event collector instance"""
    global _event_collector
    if _event_collector is None:
        _event_collector = WindowsEventCollector()
    return _event_collector
