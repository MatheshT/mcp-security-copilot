from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional

from ...investigation_service import InvestigationService
from ...auth.dependencies import get_current_user
from ...auth.models import User

router = APIRouter(prefix="/v1", tags=["investigation v1"])

service = InvestigationService()

class InvestigationRequest(BaseModel):
    query: str

@router.post("/investigate")
async def investigate_v1(
    req: InvestigationRequest,
    current_user: User = Depends(get_current_user)
):
    """Investigation endpoint - API v1"""
    result = service.analyze_query(req.query)
    return result