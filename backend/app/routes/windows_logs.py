from fastapi import APIRouter, HTTPException
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()

from ..collectors.windows_event_collector import get_event_collector
from ..mcp.windows_logs_server import WindowsLogsServer

router = APIRouter(prefix="/windows-logs", tags=["Windows Logs"])

@router.get("/security")
async def get_security_events(hours: int = 24, limit: int = 100):
    """
    Get security events from Windows Event Logs
    Prioritizes real Windows logs over mock data
    """
    try:
        use_real_logs = os.getenv("USE_REAL_WINDOWS_LOGS", "true").lower() == "true"
        
        if not use_real_logs:
            return {
                "status": "success",
                "data_source": "disabled",
                "message": "Real Windows logs collection is disabled in configuration",
                "events": []
            }
        
        # Try to get real Windows events
        collector = get_event_collector()
        security_events = collector.get_security_events(hours=hours, limit=limit)
        
        if security_events and len(security_events) > 0:
            return {
                "status": "success",
                "data_source": "real_windows_logs",
                "message": f"Successfully collected {len(security_events)} security events from Windows Event Log",
                "events": security_events,
                "total_count": len(security_events)
            }
        else:
            # Fall back to MCP server which has fallback logic
            windows_server = WindowsLogsServer()
            result = windows_server.get_security_events()
            
            return {
                "status": "success",
                "data_source": result.data.get("data_source", "fallback"),
                "message": result.details,
                "events": result.data.get("events", []),
                "total_count": result.data.get("total_count", 0)
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error collecting security events: {str(e)}")

@router.get("/system")
async def get_system_events(hours: int = 24, limit: int = 100):
    """Get system events from Windows Event Logs"""
    try:
        collector = get_event_collector()
        system_events = collector.get_system_events(hours=hours, limit=limit)
        
        return {
            "status": "success",
            "data_source": "real_windows_logs" if system_events else "no_data",
            "events": system_events,
            "total_count": len(system_events)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error collecting system events: {str(e)}")

@router.get("/application")
async def get_application_events(hours: int = 24, limit: int = 100):
    """Get application events from Windows Event Logs"""
    try:
        collector = get_event_collector()
        app_events = collector.get_application_events(hours=hours, limit=limit)
        
        return {
            "status": "success",
            "data_source": "real_windows_logs" if app_events else "no_data",
            "events": app_events,
            "total_count": len(app_events)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error collecting application events: {str(e)}")

@router.get("/stats")
async def get_windows_log_stats():
    """Get statistics about Windows log collection"""
    try:
        collector = get_event_collector()
        
        # Get sample counts from different log sources
        security_events = collector.get_security_events(hours=24, limit=1000)
        system_events = collector.get_system_events(hours=24, limit=1000)
        application_events = collector.get_application_events(hours=24, limit=1000)
        
        return {
            "status": "success",
            "statistics": {
                "security_events_24h": len(security_events),
                "system_events_24h": len(system_events),
                "application_events_24h": len(application_events),
                "total_events_24h": len(security_events) + len(system_events) + len(application_events),
                "data_source": "real_windows_logs" if (security_events or system_events or application_events) else "no_data"
            },
            "configuration": {
                "use_real_windows_logs": os.getenv("USE_REAL_WINDOWS_LOGS", "true"),
                "windows_hostname": os.getenv("WINDOWS_HOSTNAME", "localhost"),
                "hours_back": int(os.getenv("WINDOWS_LOG_HOURS_BACK", "24")),
                "log_limit": int(os.getenv("WINDOWS_LOG_LIMIT", "100"))
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting Windows log stats: {str(e)}")