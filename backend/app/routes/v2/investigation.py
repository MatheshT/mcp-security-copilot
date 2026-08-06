from fastapi import APIRouter, Depends, UploadFile, File
from pydantic import BaseModel
from typing import Optional

from ...investigation_service import InvestigationService
from ...auth.dependencies import get_current_user
from ...auth.models import User

router = APIRouter(prefix="/v2", tags=["investigation v2"])

service = InvestigationService()

class InvestigationRequest(BaseModel):
    query: str
    use_cache: Optional[bool] = True
    include_correlation: Optional[bool] = True

@router.post("/investigate")
async def investigate_v2(
    req: InvestigationRequest,
    current_user: User = Depends(get_current_user)
):
    """Enhanced investigation endpoint - API v2 with caching and correlation"""
    result = service.analyze_query(req.query)
    return result

@router.post("/upload")
async def upload_file_v2(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """Enhanced file upload endpoint - API v2"""
    content = await file.read()
    result = service.analyze_file_upload(file.filename, content)
    return result