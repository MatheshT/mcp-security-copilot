from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import List, Optional

from .service import AuthService
from .models import User
from ..database import get_db

security = HTTPBearer()

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Dependency to get current authenticated user"""
    auth_service = AuthService(db)
    try:
        return auth_service.get_current_user(credentials)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def require_permission(resource: str, action: str):
    """Dependency factory to require specific permission"""
    def permission_checker(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ) -> User:
        auth_service = AuthService(db)
        
        if not auth_service.check_permission(current_user, resource, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {action} on {resource}"
            )
        
        return current_user
    
    return permission_checker

def require_roles(roles: List[str]):
    """Dependency factory to require specific roles"""
    def role_checker(
        current_user: User = Depends(get_current_user)
    ) -> User:
        user_roles = [role.name for role in current_user.roles]
        
        if not any(role in user_roles for role in roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {', '.join(roles)}"
            )
        
        return current_user
    
    return role_checker

def require_superuser(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to require superuser access"""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required"
        )
    return current_user