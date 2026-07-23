from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from app.investigation_service import InvestigationService
from app.schemas import ChatRequest

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


@router.post("/chat")
async def chat(req: ChatRequest):
    user_query = req.query or req.message or ""
    result = service.analyze_query(user_query)
    return result