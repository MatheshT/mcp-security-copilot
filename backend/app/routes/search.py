from fastapi import APIRouter, HTTPException, Query, Body
from typing import List, Optional
from ..services.dashboard_service import dashboard_service
from ..schemas import SearchResult, SearchRequest, SearchResponse
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/search", tags=["search"])

@router.get("/")
async def search_investigations(
    q: str = Query(..., min_length=1, max_length=100, description="Search query"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=100, description="Maximum results to return")
):
    """Search investigations by query with optional severity filter"""
    try:
        results = dashboard_service.search_investigations(q, severity, limit)
        return SearchResponse(total=len(results), results=results)
    except Exception as e:
        logger.error(f"Error searching investigations: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/advanced")
async def advanced_search(request: SearchRequest):
    """Advanced search with multiple filters"""
    try:
        filters = {
            "alert_id": request.alert_id,
            "hostname": request.hostname,
            "attack_type": request.attack_type,
            "ioc": request.ioc,
            "severity": request.severity,
            "limit": request.limit
        }
        results = dashboard_service.advanced_search(**filters)
        return SearchResponse(total=len(results), results=results)
    except Exception as e:
        logger.error(f"Error in advanced search: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/suggestions")
async def get_search_suggestions(
    q: str = Query(..., min_length=1, description="Partial search query"),
    limit: int = Query(5, ge=1, le=10)
):
    """Get search suggestions based on partial query"""
    try:
        # Simple suggestion generation
        suggestions = [
            f"Alert ID: {q.upper()}",
            f"Host: {q.lower()}",
            f"IOC: {q}",
            f"Attack Type: {q}",
        ]
        return {"suggestions": suggestions[:limit]}
    except Exception as e:
        logger.error(f"Error getting suggestions: {e}")
        raise HTTPException(status_code=500, detail=str(e))