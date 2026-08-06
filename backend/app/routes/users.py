from fastapi import APIRouter, HTTPException, status, Query, Depends
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from sqlalchemy.orm import Session

from ..database import get_db
from ..auth.models import User, Role
from ..auth.service import AuthService

router = APIRouter(prefix="/users", tags=["user management"])

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    role_ids: Optional[List[int]] = []

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    role_ids: Optional[List[int]] = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    is_active: bool
    is_superuser: bool
    created_at: str
    last_login: Optional[str]
    roles: List[dict]

class RoleCreate(BaseModel):
    name: str
    description: Optional[str] = None

class RoleUpdate(BaseModel):
    description: Optional[str] = None
    permission_ids: Optional[List[int]] = None

class RoleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    is_system: bool
    permissions: List[dict]

class PermissionResponse(BaseModel):
    id: int
    name: str
    resource: str
    action: str
    description: Optional[str]

@router.get("/", response_model=List[UserResponse])
async def get_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Get all users with pagination (demo mode - no auth required)"""
    users = db.query(User).offset(skip).limit(limit).all()
    
    result = []
    for user in users:
        result.append(UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            is_active=user.is_active,
            is_superuser=user.is_superuser,
            created_at=user.created_at.isoformat() if user.created_at else None,
            last_login=user.last_login.isoformat() if user.last_login else None,
            roles=[{"id": role.id, "name": role.name} for role in user.roles]
        ))
    
    return result

@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    db: Session = Depends(get_db)
):
    """Get user by ID (demo mode - no auth required)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        created_at=user.created_at.isoformat() if user.created_at else None,
        last_login=user.last_login.isoformat() if user.last_login else None,
        roles=[{"id": role.id, "name": role.name} for role in user.roles]
    )

@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    """Create a new user (demo mode - no auth required)"""
    auth_service = AuthService(db)
    
    # Check if username exists
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Check if email exists
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    
    # Create user
    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=auth_service.get_password_hash(user_data.password),
        full_name=user_data.full_name,
        is_active=True
    )
    
    # Assign roles
    if user_data.role_ids:
        roles = db.query(Role).filter(Role.id.in_(user_data.role_ids)).all()
        user.roles = roles
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        created_at=user.created_at.isoformat() if user.created_at else None,
        last_login=user.last_login.isoformat() if user.last_login else None,
        roles=[{"id": role.id, "name": role.name} for role in user.roles]
    )

@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    db: Session = Depends(get_db)
):
    """Update user (demo mode - no auth required)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update fields
    if user_data.email is not None:
        user.email = user_data.email
    if user_data.full_name is not None:
        user.full_name = user_data.full_name
    if user_data.is_active is not None:
        user.is_active = user_data.is_active
    if user_data.role_ids is not None:
        roles = db.query(Role).filter(Role.id.in_(user_data.role_ids)).all()
        user.roles = roles
    
    db.commit()
    db.refresh(user)
    
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        created_at=user.created_at.isoformat() if user.created_at else None,
        last_login=user.last_login.isoformat() if user.last_login else None,
        roles=[{"id": role.id, "name": role.name} for role in user.roles]
    )

@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    db: Session = Depends(get_db)
):
    """Delete user (demo mode - no auth required)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    username = user.username
    db.delete(user)
    db.commit()
    
    return {"message": f"User {username} deleted successfully"}

# Role management endpoints
@router.get("/roles/", response_model=List[RoleResponse])
async def get_roles(
    db: Session = Depends(get_db)
):
    """Get all roles (demo mode - no auth required)"""
    roles = db.query(Role).all()
    
    return [
        RoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            is_system=role.is_system,
            permissions=[{"id": perm.id, "name": perm.name} for perm in role.permissions]
        )
        for role in roles
    ]

@router.post("/roles/", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    role_data: RoleCreate,
    db: Session = Depends(get_db)
):
    """Create a new role (demo mode - no auth required)"""
    if db.query(Role).filter(Role.name == role_data.name).first():
        raise HTTPException(status_code=400, detail="Role name already exists")
    
    role = Role(
        name=role_data.name,
        description=role_data.description,
        is_system=False
    )
    
    db.add(role)
    db.commit()
    db.refresh(role)
    
    return RoleResponse(
        id=role.id,
        name=role.name,
        description=role.description,
        is_system=role.is_system,
        permissions=[]
    )