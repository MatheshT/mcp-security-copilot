from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, EmailStr
from typing import Optional
from sqlalchemy.orm import Session

from .service import AuthService
from .models import User, Role, Permission
from ..database import get_db
from .dependencies import get_current_user

router = APIRouter(prefix="/api/auth", tags=["authentication"])

class UserLogin(BaseModel):
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: dict

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    is_active: bool
    is_superuser: bool
    roles: list

@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin, request: Request, db: Session = Depends(get_db)):
    """Authenticate user and return tokens"""
    auth_service = AuthService(db)
    
    user = auth_service.authenticate_user(credentials.username, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )
    
    # Create session
    session = auth_service.create_user_session(
        user=user,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    # Log audit event
    auth_service.log_audit_event(
        user_id=user.id,
        action="login",
        resource="auth",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return TokenResponse(
        access_token=session.token,
        refresh_token=session.refresh_token,
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "is_active": user.is_active,
            "is_superuser": user.is_superuser,
            "roles": [role.name for role in user.roles]
        }
    )

@router.post("/register", response_model=UserResponse)
async def register(user_data: UserRegister, request: Request, db: Session = Depends(get_db)):
    """Register a new user"""
    auth_service = AuthService(db)
    
    user = auth_service.create_user(
        username=user_data.username,
        email=user_data.email,
        password=user_data.password,
        full_name=user_data.full_name
    )
    
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        roles=[role.name for role in user.roles]
    )

@router.post("/refresh")
async def refresh_token(token_data: RefreshTokenRequest, db: Session = Depends(get_db)):
    """Refresh access token using refresh token"""
    auth_service = AuthService(db)
    
    new_access_token = auth_service.refresh_access_token(token_data.refresh_token)
    if not new_access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    return {"access_token": new_access_token, "token_type": "bearer"}

@router.post("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    """Logout user and revoke session"""
    auth_service = AuthService(db)
    
    # Get token from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header"
        )
    
    token = auth_header.split(" ")[1]
    user = auth_service.get_current_user()
    
    # Revoke session
    auth_service.revoke_session(token)
    
    # Log audit event
    auth_service.log_audit_event(
        user_id=user.id,
        action="logout",
        resource="auth",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return {"message": "Successfully logged out"}

@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get current user information"""
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        is_active=current_user.is_active,
        is_superuser=current_user.is_superuser,
        roles=[role.name for role in current_user.roles]
    )

@router.get("/permissions")
async def get_user_permissions(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get current user's permissions"""
    auth_service = AuthService(db)
    
    if user.is_superuser:
        # Superusers have all permissions
        permissions = db.query(Permission).all()
    else:
        # Get permissions through roles
        permissions = db.query(Permission).join(
            Permission.roles
        ).join(
            Role.users
        ).filter(User.id == user.id).all()
    
    return {
        "permissions": [
            {
                "id": perm.id,
                "name": perm.name,
                "resource": perm.resource,
                "action": perm.action,
                "description": perm.description
            }
            for perm in permissions
        ]
    }