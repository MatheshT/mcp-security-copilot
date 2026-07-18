from fastapi import APIRouter
from pydantic import BaseModel

from app.investigation_service import InvestigationService

router = APIRouter(
    prefix="/api",
    tags=["investigation"]
)

service = InvestigationService()


class InvestigationRequest(BaseModel):
    query: str


@router.post("/investigate")
async def investigate(req: InvestigationRequest):
    result = service.analyze_query(req.query)
    return result