from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import Dict, Any, Optional

from ..utils.feature_flags import feature_flag_manager

router = APIRouter(prefix="/feature-flags", tags=["feature flags"])

class FeatureFlagUpdate(BaseModel):
    enabled: bool
    rollout_percentage: int = 100
    description: Optional[str] = None

class FeatureFlagResponse(BaseModel):
    name: str
    enabled: bool
    description: str
    rollout_percentage: int

@router.get("/", response_model=Dict[str, Any])
async def list_feature_flags():
    """List all feature flags (demo mode - no auth required)"""
    return feature_flag_manager.list_flags()

@router.get("/{flag_name}", response_model=Dict[str, Any])
async def get_feature_flag(
    flag_name: str
):
    """Get specific feature flag configuration (demo mode - no auth required)"""
    flag = feature_flag_manager.get_flag(flag_name)
    
    if not flag:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feature flag '{flag_name}' not found"
        )
    
    return flag

@router.put("/{flag_name}")
async def update_feature_flag(
    flag_name: str,
    flag_data: FeatureFlagUpdate
):
    """Update feature flag configuration (demo mode - no auth required)"""
    if flag_name not in feature_flag_manager.list_flags():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feature flag '{flag_name}' not found"
        )
    
    feature_flag_manager.set_flag(
        flag_name,
        flag_data.enabled,
        flag_data.rollout_percentage
    )
    
    if flag_data.description:
        feature_flag_manager.update_flag_description(flag_name, flag_data.description)
    
    return {"message": f"Feature flag '{flag_name}' updated successfully"}

@router.get("/{flag_name}/status")
async def check_feature_flag_status(
    flag_name: str,
    user_id: Optional[int] = None
):
    """Check if a feature flag is enabled for a specific user (demo mode - no auth required)"""
    enabled = feature_flag_manager.is_enabled(flag_name, user_id)
    
    return {
        "flag_name": flag_name,
        "enabled": enabled,
        "user_id": user_id
    }