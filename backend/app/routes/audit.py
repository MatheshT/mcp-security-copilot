from fastapi import APIRouter, Query, Depends
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from ..database import get_db
from ..auth.models import AuditLog

router = APIRouter(prefix="/audit", tags=["audit logging"])

class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    action: str
    resource: str
    resource_id: Optional[str]
    details: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    timestamp: datetime

@router.get("/", response_model=List[AuditLogResponse])
async def get_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    action: Optional[str] = None,
    resource: Optional[str] = None,
    user_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """Get audit logs with filtering and pagination (demo mode - no auth required)"""
    query = db.query(AuditLog)
    
    if action:
        query = query.filter(AuditLog.action == action)
    if resource:
        query = query.filter(AuditLog.resource == resource)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    
    query = query.order_by(AuditLog.timestamp.desc())
    query = query.offset(skip).limit(limit)
    
    logs = query.all()
    
    return [
        AuditLogResponse(
            id=log.id,
            user_id=log.user_id,
            action=log.action,
            resource=log.resource,
            resource_id=log.resource_id,
            details=log.details,
            ip_address=log.ip_address,
            user_agent=log.user_agent,
            timestamp=log.timestamp
        )
        for log in logs
    ]

@router.get("/actions")
async def get_audit_actions(
    db: Session = Depends(get_db)
):
    """Get list of unique audit actions (demo mode - no auth required)"""
    actions = db.query(AuditLog.action).distinct().all()
    return {"actions": [action[0] for action in actions]}

@router.get("/resources")
async def get_audit_resources(
    db: Session = Depends(get_db)
):
    """Get list of unique audit resources (demo mode - no auth required)"""
    resources = db.query(AuditLog.resource).distinct().all()
    return {"resources": [resource[0] for resource in resources]}