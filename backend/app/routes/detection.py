from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
import logging
from ..mcp.wazuh_server import WazuhServer
from pydantic import BaseModel
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
            
            # Calculate statistics
            severity_distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for alert in alerts:
                severity = str(alert.get("severity", "Unknown")).title()
                if severity in severity_distribution:
                    severity_distribution[severity] += 1
                else:
                    severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
            
            return {
                "alerts": alerts,
                "total_alerts": len(alerts),
                "severity_distribution": severity_distribution,
                "time_range": time_range
            }
        else:
            logger.error(f"Failed to get Wazuh alerts: {result.details}")
            raise HTTPException(status_code=500, detail=result.details)
    except Exception as e:
        logger.error(f"Error fetching Wazuh alerts: {e}")
        # Return mock data for demonstration
        return {
            "alerts": [],
            "total_alerts": 0,
            "severity_distribution": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
            "time_range": time_range,
            "error": str(e)
        }


@router.get("/wazuh/agents")
async def get_wazuh_agents():
    """Get Wazuh agents status"""
    try:
        # Since get_endpoint_info requires an endpoint_id, we'll return mock data for now
        # In a real implementation, you would have a method to list all agents
        return {
            "agents": [],
            "total_agents": 0,
            "active_agents": 0,
            "connected_agents": 0,
            "error": "Wazuh agent listing not implemented in MCP server"
        }
    except Exception as e:
        logger.error(f"Error fetching Wazuh agents: {e}")
        return {
            "agents": [],
            "total_agents": 0,
            "active_agents": 0,
            "connected_agents": 0,
            "error": str(e)
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
        # Get alerts from Wazuh
        wazuh_result = wazuh_server.get_alerts()
        
        if wazuh_result.status == "success":
            alerts = wazuh_result.data.get("alerts", [])
            
            # Apply filters
            if severity:
                alerts = [a for a in alerts if str(a.get("severity", "")).lower() == severity.lower()]
            if status:
                alerts = [a for a in alerts if str(a.get("status", "")).lower() == status.lower()]
            if source:
                alerts = [a for a in alerts if str(a.get("source", "")).lower() == source.lower()]
            
            # Limit results
            alerts = alerts[:limit]
            
            return {
                "alerts": alerts,
                "total_count": len(alerts),
                "filters": {
                    "severity": severity,
                    "status": status,
                    "source": source,
                    "limit": limit
                }
            }
        else:
            logger.error(f"Failed to get alerts: {wazuh_result.details}")
            raise HTTPException(status_code=500, detail=wazuh_result.details)
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return {
            "alerts": [],
            "total_count": 0,
            "filters": {
                "severity": severity,
                "status": status,
                "source": source,
                "limit": limit
            },
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