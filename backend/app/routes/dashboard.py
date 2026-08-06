from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Optional
from ..services.dashboard_service import dashboard_service
from ..schemas import DashboardStats, Investigation
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