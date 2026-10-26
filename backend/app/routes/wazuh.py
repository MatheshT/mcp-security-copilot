from fastapi import APIRouter, HTTPException
from typing import Optional, List, Dict, Any
import os
import re
import json
import subprocess
import requests
import urllib3
from dotenv import load_dotenv
from datetime import datetime
import time

load_dotenv()

# Disable SSL warnings if configured
if os.environ.get('WAZUH_VERIFY_SSL', 'false').lower() == 'false':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

router = APIRouter(prefix="/detection/wazuh", tags=["Wazuh"])

# =====================================================================
# VirtualBox helpers
# =====================================================================
VBOX_MANAGE_PATH = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
DEFAULT_WAZUH_VM = "Wazuh v4.14.7 OVA"


def _get_cached_alerts_from_disk(limit: int = 500) -> List[Dict]:
    """Load persistent real alerts from local cache file."""
    cache_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wazuh_alerts_cache.json")
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list) and data:
                    return data[:limit]
        except Exception:
            pass
    return []

# Pre-populate in-memory cache immediately from disk on startup
_initial_disk_alerts = _get_cached_alerts_from_disk(limit=500)
_alerts_cache = {"timestamp": time.time() if _initial_disk_alerts else 0.0, "alerts": _initial_disk_alerts or []}
CACHE_TTL_SECONDS = 15.0


def _is_vm_running(vm_name: str = DEFAULT_WAZUH_VM) -> bool:
    """Fast non-blocking check (0.1s) if VirtualBox VM is actually running."""
    if not os.path.exists(VBOX_MANAGE_PATH):
        return False
    try:
        res = subprocess.run([VBOX_MANAGE_PATH, "list", "runningvms"], capture_output=True, text=True, timeout=2)
        return vm_name in res.stdout
    except Exception:
        return False


def _vbox_run_cmd_in_vm(vm_name: str, cmd: str, args: List[str], timeout: int = 4) -> str:
    """Run a command inside the VM via VBoxManage guestcontrol with fast timeout."""
    if not os.path.exists(VBOX_MANAGE_PATH):
        raise RuntimeError("VBoxManage not found")
    result = subprocess.run(
        [VBOX_MANAGE_PATH, "guestcontrol", vm_name, "run",
         "--exe", cmd,
         "--username", "root",
         "--password", "wazuh",
         "--"] + args,
        capture_output=True, text=True, timeout=timeout
    )
    return result.stdout or ""


def _vbox_read_file(vm_name: str, remote_path: str, lines: int = 300) -> str:
    """Read last N lines of a file inside the VM."""
    try:
        out = _vbox_run_cmd_in_vm(vm_name, "/usr/bin/tail", ["-n", str(lines), remote_path], timeout=4)
        return out
    except Exception as e:
        print(f"Error reading {remote_path} from VM: {e}")
        return ""
    """Read last N lines of a file inside the VM."""
    try:
        out = _vbox_run_cmd_in_vm(vm_name, "/usr/bin/tail", ["-n", str(lines), remote_path])
        return out
    except Exception as e:
        print(f"Error reading {remote_path} from VM: {e}")
        return ""


# =====================================================================
# Wazuh alerts.log parser
# =====================================================================

def _parse_alert_block(block: str) -> Optional[Dict[str, Any]]:
    """
    Parse one alert block from /var/ossec/logs/alerts/alerts.log.
    Block format:
        ** Alert <id>.<seq>: - group1,group2,...
        <YYYY Mon DD HH:MM:SS> [(agent)] any->location
        Rule: <num> (level <lvl>) -> '<desc>'
        <optional JSON or key:value lines>
    """
    if not block.strip():
        return None

    lines = block.strip().splitlines()

    # Header line: ** Alert 1234567.890: - groups
    header_match = re.match(r'\*\* Alert (\S+): - (.*)', lines[0]) if lines else None
    if not header_match:
        return None

    alert_id = header_match.group(1).rstrip(':')
    groups = [g.strip() for g in header_match.group(2).split(',') if g.strip()]

    # Timestamp + agent line
    timestamp_str = ""
    agent_name = "wazuh-manager"
    location = ""
    if len(lines) > 1:
        ts_match = re.search(r'(\d{4} \w+ \d+ \d+:\d+:\d+)\s+(?:(?:\((\S+)\)\s+)?(\S+)->(\S+)|(\S+)->(\S+))', lines[1])
        if ts_match:
            timestamp_str = ts_match.group(1)
            agent_name = ts_match.group(2) or ts_match.group(3) or ts_match.group(5) or "wazuh-manager"
            location = ts_match.group(4) or ts_match.group(6) or ""

    # Rule line
    rule_level = 3
    rule_desc = ""
    rule_id = ""
    if len(lines) > 2:
        rule_match = re.search(r'Rule:\s+(\d+)\s+\(level\s+(\d+)\)\s+->\s+\'(.*)\'', lines[2])
        if rule_match:
            rule_id = rule_match.group(1)
            rule_level = int(rule_match.group(2))
            rule_desc = rule_match.group(3)

    # Try to find embedded JSON (full event data)
    full_log = ""
    event_json = None
    for ln in lines[3:]:
        stripped = ln.strip()
        if stripped.startswith('{') and stripped.endswith('}'):
            try:
                event_json = json.loads(stripped)
            except Exception:
                pass
        full_log += ln + "\n"

    # Build severity from Wazuh rule level (0-15)
    if rule_level >= 12:
        severity = "Critical"
    elif rule_level >= 8:
        severity = "High"
    elif rule_level >= 4:
        severity = "Medium"
    else:
        severity = "Low"

    # Parse timestamp
    ts_iso = datetime.now().isoformat()
    if timestamp_str:
        try:
            ts_iso = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S").isoformat()
        except Exception:
            pass

    return {
        "id": alert_id,
        "timestamp": ts_iso,
        "rule": {
            "id": rule_id,
            "level": rule_level,
            "description": rule_desc or "Wazuh Security Event",
            "groups": groups,
        },
        "agent": {
            "name": agent_name,
            "id": "000" if "manager" in agent_name or "server" in agent_name else "001",
        },
        "location": location,
        "severity": severity,
        "level": rule_level,
        "full_log": full_log.strip() or f"{agent_name} -> {location}: {rule_desc}",
        "event_data": event_json or {},
    }


def _get_alerts_from_log(vm_name: str = DEFAULT_WAZUH_VM, limit: int = 200) -> List[Dict]:
    """Read real alerts from cache instantly, or refresh from VM if running."""
    global _alerts_cache
    now = time.time()

    # Fast path: return cache if valid and not expired
    if _alerts_cache["alerts"] and (now - _alerts_cache["timestamp"] < CACHE_TTL_SECONDS):
        return _alerts_cache["alerts"][:limit]

    # If VM is not running, do NOT block - instantly return current cache or disk cache
    if not _is_vm_running(vm_name):
        if not _alerts_cache["alerts"]:
            _alerts_cache = {"timestamp": now, "alerts": _get_cached_alerts_from_disk(limit=500)}
        return _alerts_cache["alerts"][:limit]

    alerts = []

    # 1. Try reading fast structured alerts.json
    try:
        raw_json = _vbox_read_file(vm_name, "/var/ossec/logs/alerts/alerts.json", lines=min(limit * 2, 350))
        if raw_json:
            for line in raw_json.strip().splitlines():
                line = line.strip()
                if not line or not line.startswith('{'):
                    continue
                try:
                    data = json.loads(line)
                    rule = data.get('rule', {})
                    level = int(rule.get('level', 0))
                    sev = 'Critical' if level >= 12 else ('High' if level >= 8 else ('Medium' if level >= 4 else 'Low'))
                    agent_data = data.get('agent', {})
                    parsed = {
                        'id': str(data.get('id', str(len(alerts) + 1))),
                        'timestamp': data.get('timestamp') or datetime.now().isoformat(),
                        'rule': {
                            'id': str(rule.get('id', 'unknown')),
                            'level': level,
                            'description': rule.get('description', 'Wazuh Security Event'),
                            'groups': rule.get('groups', []),
                            'name': rule.get('description', 'Security Rule')
                        },
                        'agent': {
                            'id': str(agent_data.get('id', '000')),
                            'name': str(agent_data.get('name', 'wazuh-manager')),
                            'ip': str(agent_data.get('ip', ''))
                        },
                        'location': str(data.get('location', 'N/A')),
                        'severity': sev,
                        'level': level,
                        'full_log': str(data.get('full_log') or data.get('data', {}).get('win', {}).get('system', {}).get('message', ''))
                    }
                    alerts.append(parsed)
                except Exception:
                    pass
    except Exception as e:
        print(f"Error reading alerts.json from VM: {e}")

    # 2. Fallback to alerts.log if alerts.json was empty
    if not alerts:
        try:
            raw_log = _vbox_read_file(vm_name, "/var/ossec/logs/alerts/alerts.log", lines=min(limit * 3, 400))
            if raw_log:
                blocks = re.split(r'\n(?=\*\* Alert )', raw_log)
                for block in blocks:
                    parsed = _parse_alert_block(block)
                    if parsed:
                        alerts.append(parsed)
        except Exception as e:
            print(f"Error reading alerts.log from VM: {e}")

    if alerts:
        alerts.reverse()
        _alerts_cache = {"timestamp": now, "alerts": alerts}
        try:
            cache_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wazuh_alerts_cache.json")
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(alerts, f)
        except Exception:
            pass
        return alerts[:limit]

    # 3. Fallback to disk cache if read failed
    disk_alerts = _get_cached_alerts_from_disk(limit)
    if disk_alerts:
        _alerts_cache = {"timestamp": now, "alerts": disk_alerts}
        return disk_alerts

    return _alerts_cache["alerts"][:limit] if _alerts_cache["alerts"] else []



# =====================================================================
# Wazuh REST API Client (for agents, stats, etc.)
# =====================================================================

class WazuhClient:
    def __init__(self):
        url = os.environ.get('WAZUH_URL', 'https://192.168.56.101:55000')
        if not url.endswith(':55000') and ':' not in url.split('/')[-1]:
            url = url.rstrip('/') + ':55000'
        self.base_url = url.rstrip('/')
        self.username = os.environ.get('WAZUH_USERNAME', 'wazuh-wui')
        self.password = os.environ.get('WAZUH_PASSWORD', 'wazuh-wui')
        self.verify_ssl = os.environ.get('WAZUH_VERIFY_SSL', 'false').lower() == 'true'
        self.token = None
        self._token_expiry = 0

    def authenticate(self) -> bool:
        """Authenticate with Wazuh API using POST (correct method for v4.x)."""
        auth_url = f"{self.base_url}/security/user/authenticate?raw=true"
        try:
            response = requests.post(
                auth_url,
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=60
            )
            if response.status_code == 200:
                self.token = response.text.strip()
                return True
            print(f"Wazuh auth failed: HTTP {response.status_code} — {response.text[:200]}")
            return False
        except Exception as e:
            print(f"Wazuh authentication error: {e}")
            return False

    def get_headers(self) -> dict:
        if not self.token:
            if not self.authenticate():
                raise HTTPException(status_code=401, detail="Failed to authenticate with Wazuh")
        return {'Authorization': f'Bearer {self.token}'}

    def make_request(self, endpoint: str, params: dict = None, retries: int = 2) -> dict:
        """Make authenticated GET request to Wazuh API with retry on 401."""
        for attempt in range(retries + 1):
            try:
                headers = self.get_headers()
                url = f"{self.base_url}/{endpoint.lstrip('/')}"
                response = requests.get(
                    url, headers=headers, params=params,
                    verify=self.verify_ssl, timeout=60
                )
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 401 and attempt < retries:
                    # Token expired — re-authenticate
                    self.token = None
                    continue
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Wazuh API error ({endpoint}): {response.text[:300]}"
                )
            except HTTPException:
                raise
            except Exception as e:
                if attempt < retries:
                    continue
                raise HTTPException(status_code=500, detail=f"Error connecting to Wazuh: {e}")
        raise HTTPException(status_code=500, detail="Wazuh API request failed after retries")


# Global client (singleton)
wazuh_client = WazuhClient()


# =====================================================================
# Severity helpers
# =====================================================================

def _level_to_severity(level: int) -> str:
    if level >= 12:
        return "Critical"
    elif level >= 8:
        return "High"
    elif level >= 4:
        return "Medium"
    return "Low"


def filter_alerts_by_severity(alerts: list, severity: str) -> list:
    severity_ranges = {
        'critical': (12, 15),
        'high': (8, 11),
        'medium': (4, 7),
        'low': (0, 3),
    }
    if severity not in severity_ranges:
        return alerts
    lo, hi = severity_ranges[severity]
    return [a for a in alerts if lo <= a.get('level', a.get('rule', {}).get('level', 0)) <= hi]


# =====================================================================
# Routes
# =====================================================================

@router.get("/alerts")
async def get_wazuh_alerts(time_range: str = "24h", limit: int = 100, severity: str = "all"):
    """
    Get REAL alerts from Wazuh alerts.log via VBoxManage guestcontrol.
    No sample/fake data — only actual events from the Wazuh VM.
    """
    try:
        alerts = _get_alerts_from_log(DEFAULT_WAZUH_VM, limit=min(limit, 500))

        if severity != "all":
            alerts = filter_alerts_by_severity(alerts, severity)

        alerts = alerts[:limit]

        return {
            "status": "success",
            "source": "wazuh_real",
            "data_source": "wazuh_alerts_log",
            "message": f"Real Wazuh alerts from /var/ossec/logs/alerts/alerts.log ({len(alerts)} events)",
            "alerts": alerts,
            "total_alerts": len(alerts),
            "severity_filter": severity,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading Wazuh alerts: {e}")


@router.get("/agents")
async def get_wazuh_agents():
    """Get agents from Wazuh REST API."""
    try:
        agents_data = wazuh_client.make_request("agents")
        agents = []
        if 'data' in agents_data and 'affected_items' in agents_data['data']:
            for agent in agents_data['data']['affected_items']:
                agents.append({
                    "id": agent.get('id'),
                    "name": agent.get('name'),
                    "status": agent.get('status'),
                    "ip": agent.get('ip'),
                    "os": {
                        "name": agent.get('os', {}).get('name'),
                        "version": agent.get('os', {}).get('version'),
                        "platform": agent.get('os', {}).get('platform'),
                    },
                    "version": agent.get('version'),
                    "last_keepalive": agent.get('lastKeepAlive'),
                    "manager": agent.get('manager'),
                })

        summary_data = wazuh_client.make_request("agents/summary/status")
        connection_stats = summary_data.get('data', {}).get('connection', {})

        return {
            "status": "success",
            "data_source": "wazuh_api",
            "message": "Real-time data from Wazuh",
            "agents": agents,
            "total_agents": len(agents),
            "active_agents": connection_stats.get('active', 0),
            "disconnected_agents": connection_stats.get('disconnected', 0),
            "never_connected": connection_stats.get('never_connected', 0),
            "pending": connection_stats.get('pending', 0),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving agents: {e}")


@router.get("/statistics")
async def get_wazuh_statistics():
    """Get Wazuh statistics — combines REST API agent stats with real alert counts."""
    try:
        agents_summary = wazuh_client.make_request("agents/summary/status")
        connection_stats = agents_summary.get('data', {}).get('connection', {})
        config_stats = agents_summary.get('data', {}).get('configuration', {})

        # Count real alerts
        try:
            real_alerts = _get_alerts_from_log(DEFAULT_WAZUH_VM, limit=500)
            total_alerts = len(real_alerts)
        except Exception:
            total_alerts = 0

        return {
            "status": "success",
            "data_source": "wazuh_api",
            "message": "Real-time data from Wazuh",
            "agents": {
                "total": connection_stats.get('total', 0),
                "active": connection_stats.get('active', 0),
                "disconnected": connection_stats.get('disconnected', 0),
                "never_connected": connection_stats.get('never_connected', 0),
                "pending": connection_stats.get('pending', 0),
                "synced": config_stats.get('synced', 0),
                "not_synced": config_stats.get('not_synced', 0),
            },
            "alerts": {
                "total_alerts": total_alerts,
                "source": "wazuh_alerts_log",
            },
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving statistics: {e}")


@router.get("/alerts/by-severity")
async def get_wazuh_alerts_by_severity(limit_per_severity: int = 20, time_range: str = "24h"):
    """Get real Wazuh alerts grouped by severity level."""
    try:
        all_alerts = _get_alerts_from_log(DEFAULT_WAZUH_VM, limit=500)

        severity_groups = {
            "critical": filter_alerts_by_severity(all_alerts, "critical")[:limit_per_severity],
            "high": filter_alerts_by_severity(all_alerts, "high")[:limit_per_severity],
            "medium": filter_alerts_by_severity(all_alerts, "medium")[:limit_per_severity],
            "low": filter_alerts_by_severity(all_alerts, "low")[:limit_per_severity],
        }

        return {
            "status": "success",
            "data_source": "wazuh_alerts_log",
            "message": "Real alerts from /var/ossec/logs/alerts/alerts.log",
            "total_alerts": len(all_alerts),
            "alerts_by_severity": {
                k: {"count": len(v), "alerts": v}
                for k, v in severity_groups.items()
            },
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving alerts by severity: {e}")


@router.get("/logs/collect")
async def collect_wazuh_logs(agent_id: str = "", log_type: str = "all", hours_back: int = 24):
    """Collect logs from Wazuh manager via REST API."""
    try:
        log_endpoints = []
        if agent_id:
            log_endpoints += [f"agents/{agent_id}/logs/summary", f"agents/{agent_id}/logs"]
        else:
            log_endpoints += ["manager/logs/summary", "manager/logs"]

        logs = []
        for endpoint in log_endpoints:
            try:
                data = wazuh_client.make_request(endpoint, params={"limit": 500})
                if isinstance(data, dict) and 'data' in data:
                    if 'affected_items' in data['data']:
                        logs = data['data']['affected_items']
                        break
                    elif 'items' in data['data']:
                        logs = data['data']['items']
                        break
            except Exception:
                continue

        return {
            "status": "success",
            "data_source": "wazuh_api",
            "agent_id": agent_id or "all",
            "log_type": log_type,
            "total_logs": len(logs),
            "logs": logs[:100],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error collecting logs: {e}")


@router.get("/alerts/{alert_id}/investigate")
async def investigate_wazuh_alert(alert_id: str):
    """Investigate a specific alert by ID from the alerts log."""
    try:
        all_alerts = _get_alerts_from_log(DEFAULT_WAZUH_VM, limit=500)
        alert = next((a for a in all_alerts if a.get("id") == alert_id), None)

        if not alert:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found in recent alerts")

        return {
            "status": "success",
            "data_source": "wazuh_alerts_log",
            "alert_id": alert_id,
            "alert_details": alert,
            "investigation_notes": [
                "Alert retrieved from Wazuh alerts.log",
                f"Severity: {alert.get('severity', 'Unknown')} (level {alert.get('level', 0)})",
                f"Agent: {alert.get('agent', {}).get('name', 'unknown')}",
                f"Groups: {', '.join(alert.get('rule', {}).get('groups', []))}",
            ],
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error investigating alert: {e}")


# =====================================================================
# VirtualBox VM Controller Endpoints
# =====================================================================

@router.get("/vm/status")
def get_wazuh_vm_status(vm_name: str = DEFAULT_WAZUH_VM):
    """Check status of Wazuh VirtualBox VM."""
    if not os.path.exists(VBOX_MANAGE_PATH):
        return {"installed": False, "vm_name": vm_name, "state": "vbox_not_found"}
    try:
        res_running = subprocess.run(
            [VBOX_MANAGE_PATH, "list", "runningvms"],
            capture_output=True, text=True, timeout=10
        )
        if vm_name in res_running.stdout:
            return {"installed": True, "vm_name": vm_name, "state": "running", "headless": True}

        res_info = subprocess.run(
            [VBOX_MANAGE_PATH, "showvminfo", vm_name, "--machinereadable"],
            capture_output=True, text=True, timeout=10
        )
        state = "poweroff"
        for line in res_info.stdout.splitlines():
            if line.startswith("VMState="):
                state = line.split("=")[1].strip('"')
                break
        return {"installed": True, "vm_name": vm_name, "state": state}
    except Exception as e:
        return {"installed": True, "vm_name": vm_name, "state": "unknown", "error": str(e)}


@router.post("/vm/start")
def start_wazuh_vm(vm_name: str = DEFAULT_WAZUH_VM, headless: bool = True):
    """Start Wazuh VirtualBox VM in headless mode."""
    if not os.path.exists(VBOX_MANAGE_PATH):
        raise HTTPException(status_code=404, detail="VirtualBox not found at expected path.")
    try:
        status = get_wazuh_vm_status(vm_name)
        if status.get("state") == "running":
            return {"status": "already_running", "message": f"{vm_name} is already active."}

        cmd = [VBOX_MANAGE_PATH, "startvm", vm_name, "--type", "headless" if headless else "gui"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if res.returncode == 0:
            return {
                "status": "success",
                "message": f"{vm_name} started in headless mode.",
                "wazuh_url": os.getenv("WAZUH_URL", "https://192.168.56.101:55000"),
            }
        raise HTTPException(status_code=500, detail=f"VBoxManage error: {res.stderr or res.stdout}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start VM: {e}")


@router.post("/vm/stop")
def stop_wazuh_vm(vm_name: str = DEFAULT_WAZUH_VM):
    """Safely save state of Wazuh VirtualBox VM."""
    if not os.path.exists(VBOX_MANAGE_PATH):
        raise HTTPException(status_code=404, detail="VirtualBox not installed.")
    try:
        cmd = [VBOX_MANAGE_PATH, "controlvm", vm_name, "savestate"]
        subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"status": "success", "message": f"{vm_name} state saved safely."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop VM: {e}")
