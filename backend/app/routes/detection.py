import asyncio
import re
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
import logging
from ..mcp.wazuh_server import WazuhServer
from ..auth.dependencies import get_current_user
from ..auth.models import User
from ..database import SessionLocal
from ..log_collector.models import Alert
from ..wazuh_automation import get_wazuh_automation_worker
from pathlib import Path
import os
import requests
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/detection", tags=["detection"])

# Initialize Wazuh server
wazuh_server = WazuhServer()


class AlertUpdate(BaseModel):
    status: str


class WazuhConfig(BaseModel):
    url: str
    username: str | None = None
    password: str | None = None


@router.get("/wazuh/alerts")
async def get_wazuh_alerts(time_range: str = "24h"):
    """Get Wazuh alerts with optional time range filter"""
    try:
        result = wazuh_server.get_alerts()
        if result.status == "success":
            alerts = result.data.get("alerts", [])
            return {
                "status": "success",
                "source": "wazuh",
                "message": "No live Wazuh alerts were available" if not alerts else "Real Wazuh alerts",
                "alerts": alerts,
                "total_alerts": len(alerts),
                "time_range": time_range
            }

        logger.warning("Wazuh returned a non-success result: %s", result.details)
        return {
            "status": "success",
            "source": "wazuh",
            "message": "Wazuh is unavailable; returning no live alerts",
            "alerts": [],
            "total_alerts": 0,
            "time_range": time_range,
            "details": result.details,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching Wazuh alerts: {e}")
        return {
            "status": "success",
            "source": "wazuh",
            "message": "Wazuh is unavailable; returning no live alerts",
            "alerts": [],
            "total_alerts": 0,
            "time_range": time_range,
            "details": str(e),
        }


@router.get("/wazuh/agents")
async def get_wazuh_agents():
    """Get Wazuh agents status"""
    try:
        result = wazuh_server.get_agents()
        if result.status == "success":
            agents = result.data.get("agents", [])
            return {
                "status": "success",
                "source": "wazuh",
                "message": "No live Wazuh agents were available" if not agents else "Real Wazuh agents",
                "agents": agents,
                "total_agents": len(agents),
                "active_agents": len([a for a in agents if str(a.get("status", "")).lower() == "active"]),
                "connected_agents": len(agents),
            }

        logger.warning("Wazuh returned a non-success agent result: %s", result.details)
        return {
            "status": "success",
            "source": "wazuh",
            "message": "Wazuh is unavailable; returning no live agents",
            "agents": [],
            "total_agents": 0,
            "active_agents": 0,
            "connected_agents": 0,
            "details": result.details,
        }
    except Exception as e:
        logger.error(f"Error fetching Wazuh agents: {e}")
        return {
            "status": "success",
            "source": "wazuh",
            "message": "Wazuh is unavailable; returning no live agents",
            "agents": [],
            "total_agents": 0,
            "active_agents": 0,
            "connected_agents": 0,
            "details": str(e),
        }


@router.get("/alerts")
async def get_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000)
):
    """Get security alerts with optional filters"""
    try:
        combined_alerts = []

        # 1. Fetch from live Wazuh if available
        try:
            wazuh_result = wazuh_server.get_alerts()
            if wazuh_result.status == "success":
                wazuh_alerts = wazuh_result.data.get("alerts", [])
                for a in wazuh_alerts:
                    combined_alerts.append({
                        "id": str(a.get("id", a.get("alert_id", uuid.uuid4().hex[:8]))),
                        "title": a.get("rule", {}).get("description", a.get("name", "Wazuh Security Event")),
                        "description": a.get("full_log", a.get("rule", {}).get("description", "Security alert")),
                        "severity": str(a.get("severity", "medium")).lower(),
                        "source": "Wazuh",
                        "status": str(a.get("status", "active")),
                        "timestamp": a.get("timestamp", datetime.utcnow().isoformat()),
                        "rule_id": a.get("rule", {}).get("id", "N/A"),
                        "agent_name": a.get("agent", {}).get("name", "wazuh-agent")
                    })
        except Exception as we:
            logger.debug(f"Wazuh fetch skipped: {we}")

        # 2. Fetch from SQLite Database
        db = SessionLocal()
        try:
            db_alerts = db.query(Alert).order_by(Alert.first_seen.desc()).limit(100).all()
            for da in db_alerts:
                sev_val = da.severity.value if hasattr(da.severity, "value") else str(da.severity)
                combined_alerts.append({
                    "id": da.alert_id,
                    "title": da.title,
                    "description": da.description,
                    "severity": sev_val.lower(),
                    "source": da.source or "System Log Collector",
                    "status": da.status or "active",
                    "timestamp": da.first_seen.isoformat() if da.first_seen else datetime.utcnow().isoformat(),
                    "rule_id": da.detection_rule or "RULE-SYS-01",
                    "agent_name": da.affected_hosts[0] if da.affected_hosts else "local-host"
                })
        except Exception as dbe:
            logger.debug(f"DB alerts fetch error: {dbe}")
        finally:
            db.close()

        # 3. If still empty, try direct alerts log reader
        if not combined_alerts:
            try:
                from .wazuh import _get_alerts_from_log
                raw_alerts = _get_alerts_from_log(limit=limit)
                for a in raw_alerts:
                    combined_alerts.append({
                        "id": str(a.get("id")),
                        "title": a.get("rule", {}).get("description", "Wazuh Security Event"),
                        "description": a.get("full_log", ""),
                        "severity": str(a.get("severity", "medium")).lower(),
                        "source": "Wazuh SIEM",
                        "status": "open",
                        "timestamp": a.get("timestamp", datetime.utcnow().isoformat()),
                        "rule_id": str(a.get("rule", {}).get("id", "N/A")),
                        "agent_name": a.get("agent", {}).get("name", "Windows11")
                    })
            except Exception as e:
                logger.debug(f"Direct alerts log fallback skipped: {e}")

        # Apply filters
        filtered_alerts = combined_alerts
        if severity:
            filtered_alerts = [a for a in filtered_alerts if str(a.get("severity", "")).lower() == severity.lower()]
        if status:
            filtered_alerts = [a for a in filtered_alerts if str(a.get("status", "")).lower() == status.lower()]
        if source:
            filtered_alerts = [a for a in filtered_alerts if source.lower() in str(a.get("source", "")).lower()]

        filtered_alerts = filtered_alerts[:limit]

        return {
            "status": "success",
            "alerts": filtered_alerts,
            "total_count": len(filtered_alerts),
            "filters": {
                "severity": severity,
                "status": status,
                "source": source,
                "limit": limit
            }
        }
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return {
            "status": "error",
            "alerts": [],
            "total_count": 0,
            "error": str(e)
        }


@router.put("/alerts/{alert_id}/status")
async def update_alert_status(alert_id: str, update: AlertUpdate):
    """Update alert status"""
    try:
        # In a real implementation, this would update the status in a database
        logger.info(f"Updating alert {alert_id} status to {update.status}")
        return {
            "alert_id": alert_id,
            "status": update.status,
            "message": "Alert status updated successfully"
        }
    except Exception as e:
        logger.error(f"Error updating alert status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/event-logs")
async def get_event_logs(
    time_range: str = "24h",
    source: Optional[str] = None,
    level: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000)
):
    """Get event logs with optional filters"""
    try:
        # Get active events from Wazuh
        wazuh_result = wazuh_server.get_active_events()
        
        if wazuh_result.status == "success":
            events = wazuh_result.data.get("events", [])
            
            # Apply filters
            if source:
                events = [e for e in events if str(e.get("source", "")).lower() == source.lower()]
            if level:
                events = [e for e in events if str(e.get("level", "")).lower() == level.lower()]
            
            # Limit results
            events = events[:limit]
            
            return {
                "logs": events,
                "total_count": len(events),
                "time_range": time_range,
                "filters": {
                    "source": source,
                    "level": level,
                    "limit": limit
                }
            }
        else:
            logger.error(f"Failed to get event logs: {wazuh_result.details}")
            raise HTTPException(status_code=500, detail=wazuh_result.details)
    except Exception as e:
        logger.error(f"Error fetching event logs: {e}")
        return {
            "logs": [],
            "total_count": 0,
            "time_range": time_range,
            "filters": {
                "source": source,
                "level": level,
                "limit": limit
            },
            "error": str(e)
        }



@router.post("/wazuh/test")
async def test_wazuh_connection(cfg: WazuhConfig):
    """Test connectivity to a Wazuh API URL using provided credentials."""
    try:
        # Normalize URL: remove port 55000 if present
        parsed = urlparse(cfg.url)
        netloc = parsed.hostname or parsed.netloc
        if parsed.port == 55000:
            netloc = parsed.hostname
        normalized = urlunparse((parsed.scheme, netloc, parsed.path or '', '', '', ''))
        test_url = normalized.rstrip('/') + '/security/user/authenticate'
        payload = {
            "username": cfg.username or os.getenv('WAZUH_USERNAME'),
            "password": cfg.password or os.getenv('WAZUH_PASSWORD')
        }
        resp = requests.post(test_url, json=payload, headers={"Content-Type": "application/json"}, timeout=10, verify=False)
        if resp.status_code >= 200 and resp.status_code < 300:
            return {"ok": True, "status_code": resp.status_code, "detail": "Successfully connected to Wazuh."}
        return {"ok": False, "status_code": resp.status_code, "detail": resp.text}
    except Exception as e:
        logger.error(f"Wazuh test connection failed: {e}")
        return {"ok": False, "detail": str(e)}


@router.post("/wazuh/settings")
async def save_wazuh_settings(cfg: WazuhConfig):
    """Save Wazuh settings to runtime and persist to backend/.env file."""
    try:
        # Normalize URL: remove port 55000 if present
        parsed = urlparse(cfg.url)
        netloc = parsed.hostname or parsed.netloc
        if parsed.port == 55000:
            netloc = parsed.hostname
        normalized = urlunparse((parsed.scheme, netloc, parsed.path or '', '', '', ''))

        # Update runtime instance
        wazuh_server.base_url = normalized
        if cfg.username:
            wazuh_server.username = cfg.username
        if cfg.password:
            wazuh_server.password = cfg.password

        # Update environment variables
        os.environ['WAZUH_API_URL'] = normalized
        if cfg.username:
            os.environ['WAZUH_USERNAME'] = cfg.username
        if cfg.password:
            os.environ['WAZUH_PASSWORD'] = cfg.password

        # Persist to backend/.env if present
        try:
            env_path = Path(__file__).resolve().parents[3] / '.env'
            if env_path.exists():
                lines = env_path.read_text().splitlines()
                def set_var(lines, key, value):
                    prefix = key + '='
                    for i,l in enumerate(lines):
                        if l.startswith(prefix):
                            lines[i] = f"{key}={value}"
                            return lines
                    lines.append(f"{key}={value}")
                    return lines

                lines = set_var(lines, 'WAZUH_API_URL', normalized)
                if cfg.username:
                    lines = set_var(lines, 'WAZUH_USERNAME', cfg.username)
                if cfg.password:
                    lines = set_var(lines, 'WAZUH_PASSWORD', cfg.password)

                env_path.write_text('\n'.join(lines) + '\n')
        except Exception as e:
            logger.error(f"Failed to persist .env updates: {e}")

        return {"ok": True, "detail": "Wazuh settings updated."}
    except Exception as e:
        logger.error(f"Failed to save Wazuh settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/wazuh/agents/{agent_id}/restart")
async def restart_wazuh_agent(agent_id: str):
    """Restart a Wazuh agent"""
    try:
        # In a real implementation, this would call the Wazuh API to restart the agent
        logger.info(f"Restarting Wazuh agent {agent_id}")
        return {
            "agent_id": agent_id,
            "message": "Agent restart command sent successfully"
        }
    except Exception as e:
        logger.error(f"Error restarting agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/wazuh/automation/status")
async def get_wazuh_automation_status(current_user: User = Depends(get_current_user)):
    worker = get_wazuh_automation_worker()
    return {
        "mode": "dry_run",
        "running": worker.running,
        "interval_seconds": worker.interval_seconds,
        "max_alerts_per_run": worker.max_alerts_per_run,
        "last_run": worker.last_run,
        "last_status": worker.last_result.get("status"),
        "last_processed": worker.last_result.get("processed", 0),
    }


@router.post("/wazuh/automation/run")
async def run_wazuh_automation_once(current_user: User = Depends(get_current_user)):
    worker = get_wazuh_automation_worker()
    return await asyncio.to_thread(worker.run_once)


@router.get("/wazuh/automation/events")
async def get_wazuh_automation_events(
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    with SessionLocal() as db:
        records = (
            db.query(Alert)
            .filter(Alert.alert_type == "wazuh_failed_authentication")
            .order_by(Alert.updated_at.desc())
            .limit(limit)
            .all()
        )
        return {
            "mode": "dry_run",
            "events": [
                {
                    "alert_id": record.alert_id,
                    "title": record.title,
                    "severity": getattr(record.severity, "value", record.severity),
                    "status": record.status,
                    "created_at": record.created_at.isoformat() if record.created_at else None,
                    "metadata": record.alert_metadata or {},
                }
                for record in records
            ],
        }


@router.get("/statistics")
async def get_detection_statistics():
    """Get overall detection statistics"""
    try:
        # Get alerts from Wazuh
        wazuh_result = wazuh_server.get_alerts()
        
        if wazuh_result.status == "success":
            alerts = wazuh_result.data.get("alerts", [])
            
            # Calculate statistics
            severity_distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            source_distribution = {}
            
            for alert in alerts:
                severity = str(alert.get("severity", "Unknown")).title()
                if severity in severity_distribution:
                    severity_distribution[severity] += 1
                else:
                    severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
                
                source = str(alert.get("source", "Unknown"))
                source_distribution[source] = source_distribution.get(source, 0) + 1
            
            return {
                "total_alerts": len(alerts),
                "severity_distribution": severity_distribution,
                "source_distribution": source_distribution,
                "critical_alerts": severity_distribution.get("Critical", 0),
                "high_alerts": severity_distribution.get("High", 0),
                "medium_alerts": severity_distribution.get("Medium", 0),
                "low_alerts": severity_distribution.get("Low", 0)
            }
        else:
            logger.error(f"Failed to get statistics: {wazuh_result.details}")
            raise HTTPException(status_code=500, detail=wazuh_result.details)
    except Exception as e:
        logger.error(f"Error fetching detection statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/threat-intel/lookup")
async def threat_intel_lookup(indicator: str = Query(..., description="IP, domain, hash, or URL")):
    """Live threat intelligence lookup using VirusTotal, AbuseIPDB, and MITRE ATT&CK"""
    from ..threat_intel.virustotal_client import VirusTotalClient
    from ..threat_intel.abuseipdb_client import AbuseIPDBClient
    from ..threat_intel.mitre_attack_client import MITREAttackClient
    
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    
    result = {
        "indicator": indicator,
        "virustotal": None,
        "abuseipdb": None,
        "mitre": None,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # 1. VirusTotal
    if vt_key:
        try:
            vt = VirusTotalClient(vt_key)
            if re.match(r'^[a-fA-F0-9]{32,64}$', indicator):
                result["virustotal"] = await vt.analyze_file(indicator)
            elif re.match(r'^(http|https)://', indicator):
                result["virustotal"] = await vt.analyze_url(indicator)
            elif re.match(r'^\d{1,3}(\.\d{1,3}){3}$', indicator):
                result["virustotal"] = await vt.analyze_ip(indicator)
            else:
                result["virustotal"] = await vt.analyze_domain(indicator)
        except Exception as e:
            result["virustotal"] = {"error": str(e)}
            
    # 2. AbuseIPDB
    if abuse_key and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', indicator):
        try:
            ab = AbuseIPDBClient(abuse_key)
            result["abuseipdb"] = await ab.check_ip(indicator)
        except Exception as e:
            result["abuseipdb"] = {"error": str(e)}

    # 3. MITRE Techniques
    try:
        mitre = MITREAttackClient()
        techniques = await mitre.get_techniques()
        result["mitre"] = techniques
    except Exception as e:
        result["mitre"] = {"error": str(e)}

    return result