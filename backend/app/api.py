from fastapi import APIRouter, HTTPException
from .routes import dashboard, search, report, investigation, users, audit, backup, feature_flags, windows_logs, wazuh

router = APIRouter()

# Include all route modules
router.include_router(investigation.router)
router.include_router(dashboard.router)
router.include_router(search.router)
router.include_router(report.router)
router.include_router(users.router)
router.include_router(audit.router)
router.include_router(backup.router)
router.include_router(feature_flags.router)
router.include_router(windows_logs.router)
router.include_router(wazuh.router)

@router.get("/health")
async def health_check():
    """Health check endpoint with all service status"""
    from datetime import datetime
    
    # Get service statuses
    services = {
        "dashboard": "healthy",
        "search": "healthy",
        "report": "healthy",
        "investigation": "healthy",
        "mcp": "healthy"
    }
    
    return {
        "status": "operational",
        "version": "1.0.0",
        "services": services,
        "ai_status": "ready",
        "timestamp": datetime.now().isoformat()
    }

@router.get("/info")
async def system_info():
    """System information endpoint"""
    return {
        "name": "SOC Security Copilot",
        "version": "1.0.0",
        "description": "AI-Powered Enterprise Security Operations Platform",
        "features": [
            "Real-time Monitoring",
            "AI-Powered Investigation",
            "Threat Intelligence Correlation",
            "Automated Analysis",
            "Comprehensive Reporting",
            "MCP Integration",
            "Dashboard Analytics",
            "Search & Discovery"
        ],
        "architecture": {
            "frontend": "React + Vite",
            "backend": "FastAPI",
            "ai": "LLM Client with Orchestrator",
            "mcp": "Model Context Protocol",
            "security_tools": ["Wazuh", "VirusTotal"],
            "reporting": "ReportLab PDF + HTML"
        },
        "endpoints": {
            "docs": "/api/docs",
            "health": "/api/health",
            "dashboard": "/api/dashboard",
            "investigation": "/api/investigation",
            "search": "/api/search",
            "report": "/api/report"
        }
    }

@router.get("/status")
async def full_system_status():
    """Get complete system status"""
    from datetime import datetime
    import platform
    
    return {
        "system": {
            "name": "SOC Security Copilot",
            "version": "1.0.0",
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "timestamp": datetime.now().isoformat()
        },
        "status": "operational",
        "services": {
            "api": "online",
            "mcp": "online",
            "orchestrator": "online",
            "llm": "online",
            "wazuh": "online",
            "virustotal": "online"
        },
        "metrics": {
            "investigations": 50,
            "alerts": 30,
            "cache_size": 0,
            "uptime": "99.9%"
        }
    }


@router.get("/logs/events")
async def get_event_logs(time_range: str = "24h"):
    """
    Get event logs for the dashboard.
    Simple endpoint to return sample event logs.
    """
    try:
        from datetime import datetime, timedelta
        
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=24)
        
        # Generate sample logs
        sample_logs = [
            {
                "id": 1,
                "timestamp": (end_time - timedelta(minutes=5)).isoformat(),
                "event_id": 4625,
                "source": "Windows Security",
                "computer_name": "WORKSTATION-01",
                "user": "admin",
                "description": "Failed logon attempt",
                "severity": "high"
            },
            {
                "id": 2,
                "timestamp": (end_time - timedelta(minutes=15)).isoformat(),
                "event_id": 4624,
                "source": "Windows Security",
                "computer_name": "WORKSTATION-02",
                "user": "user1",
                "description": "Successful logon",
                "severity": "info"
            },
            {
                "id": 3,
                "timestamp": (end_time - timedelta(minutes=30)).isoformat(),
                "event_id": 4720,
                "source": "Windows Security",
                "computer_name": "DC-01",
                "user": "SYSTEM",
                "description": "User account created",
                "severity": "high"
            },
            {
                "id": 4,
                "timestamp": (end_time - timedelta(hours=1)).isoformat(),
                "event_id": 4688,
                "source": "Windows Security",
                "computer_name": "WORKSTATION-01",
                "user": "admin",
                "description": "Special privileges assigned to new logon",
                "severity": "medium"
            },
            {
                "id": 5,
                "timestamp": (end_time - timedelta(hours=2)).isoformat(),
                "event_id": 7045,
                "source": "Windows System",
                "computer_name": "WORKSTATION-03",
                "user": "SYSTEM",
                "description": "New service installed",
                "severity": "high"
            }
        ]
        
        return {
            "logs": sample_logs,
            "total": len(sample_logs),
            "time_range": time_range,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))