from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import List
from datetime import datetime

router = APIRouter(prefix="/backup", tags=["backup management"])

class BackupInfo(BaseModel):
    name: str
    type: str
    path: str
    created_at: str
    size: int

class BackupResponse(BaseModel):
    message: str
    backup: BackupInfo

@router.post("/create", response_model=BackupResponse)
async def create_backup(
    backup_name: str = None
):
    """Create a database backup (demo mode - mock implementation)"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = backup_name or f"db_backup_{timestamp}"
    
    # Mock backup creation
    return BackupResponse(
        message="Backup created successfully (demo mode)",
        backup=BackupInfo(
            name=name,
            type="sqlite",
            path=f"/backups/{name}.db.gz",
            created_at=datetime.now().isoformat(),
            size=1024000  # Mock size
        )
    )

@router.get("/list", response_model=List[BackupInfo])
async def list_backups():
    """List all available backups (demo mode - mock implementation)"""
    # Mock backup list
    return [
        BackupInfo(
            name="db_backup_20260801_090000",
            type="sqlite",
            path="/backups/db_backup_20260801_090000.db.gz",
            created_at="2026-08-01T09:00:00",
            size=1024000
        ),
        BackupInfo(
            name="db_backup_20260731_180000",
            type="sqlite",
            path="/backups/db_backup_20260731_180000.db.gz",
            created_at="2026-07-31T18:00:00",
            size=980000
        )
    ]

@router.post("/restore/{backup_name}")
async def restore_backup(
    backup_name: str
):
    """Restore database from backup (demo mode - mock implementation)"""
    return {"message": f"Backup {backup_name} restored successfully (demo mode)"}

@router.delete("/{backup_name}")
async def delete_backup(
    backup_name: str
):
    """Delete a backup (demo mode - mock implementation)"""
    return {"message": f"Backup {backup_name} deleted successfully (demo mode)"}

@router.post("/cleanup")
async def cleanup_backups(
    keep_count: int = 10
):
    """Clean up old backups (demo mode - mock implementation)"""
    return {
        "message": f"Cleaned up old backups (demo mode)",
        "deleted_count": 2
    }