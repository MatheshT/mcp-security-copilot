from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Optional
from ..services.dashboard_service import dashboard_service
from ..schemas import DashboardStats, Investigation
from ..mcp.registry import mcp_registry
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """Get dashboard statistics with MCP integration"""
    try:
        return dashboard_service.get_dashboard_stats()
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/wazuh")
async def get_wazuh_dashboard():
    """Get Wazuh dashboard data with real alerts and agents"""
    try:
        from .wazuh import _get_alerts_from_log, wazuh_client
        
        # 1. Real alerts
        real_alerts = _get_alerts_from_log(limit=50)
        
        # 2. Real agents
        agents_data = []
        try:
            raw_agents = wazuh_client.make_request("agents")
            if 'data' in raw_agents and 'affected_items' in raw_agents['data']:
                agents_data = raw_agents['data']['affected_items']
        except Exception:
            pass
            
        total_agents = len(agents_data)
        active_agents = len([a for a in agents_data if a.get("status") == "active"])
        
        # Compute alert stats
        critical_count = len([a for a in real_alerts if a.get("severity") == "Critical"])
        high_count = len([a for a in real_alerts if a.get("severity") == "High"])
        medium_count = len([a for a in real_alerts if a.get("severity") == "Medium"])
        low_count = len([a for a in real_alerts if a.get("severity") == "Low"])
        
        # Top rules
        rule_counts = {}
        for a in real_alerts:
            desc = a.get("rule", {}).get("description", "Security Event")
            rule_counts[desc] = rule_counts.get(desc, 0) + 1
        top_rules = [{"rule": k, "count": v} for k, v in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]]

        return {
            "connected": True,
            "source": "wazuh_real",
            "agents": {
                "total": total_agents,
                "active": active_agents
            },
            "agents_data": agents_data,
            "alerts": {
                "total": len(real_alerts),
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count
            },
            "top_rules": top_rules,
            "recent_alerts": real_alerts[:10]
        }
    except Exception as e:
        logger.error(f"Error fetching Wazuh dashboard data: {e}")
        return {
            "connected": False,
            "source": "wazuh",
            "error": str(e),
            "agents": {"total": 0, "active": 0},
            "agents_data": [],
            "alerts": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            "top_rules": [],
            "recent_alerts": []
        }

@router.get("/investigations", response_model=List[Investigation])
async def get_investigations(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    """Get recent investigations with pagination"""
    try:
        return dashboard_service.get_investigations(limit, offset)
    except Exception as e:
        logger.error(f"Error fetching investigations: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/investigations/{alert_id}", response_model=Investigation)
async def get_investigation_by_id(alert_id: str):
    """Get investigation by alert ID"""
    try:
        investigation = dashboard_service.get_investigation_by_id(alert_id)
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return investigation
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching investigation {alert_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/recommendations/{alert_id}")
async def get_recommendations(alert_id: str):
    """Get recommendations for an alert"""
    try:
        recommendations = dashboard_service.get_recommendations(alert_id)
        return {"alert_id": alert_id, "recommendations": recommendations}
    except Exception as e:
        logger.error(f"Error fetching recommendations: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/enrich")
async def enrich_iocs(iocs: List[str]):
    """Enrich IOCs with threat intelligence"""
    try:
        threat_data = dashboard_service.enrich_with_threat_intelligence(iocs)
        return {"enriched_data": threat_data}
    except Exception as e:
        logger.error(f"Error enriching IOCs: {e}")
        raise HTTPException(status_code=500, detail=str(e))