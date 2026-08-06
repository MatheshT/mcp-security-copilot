from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import secrets

from .models import User, Role, Permission, UserSession, AuditLog

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Configuration
SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

security = HTTPBearer()

class AuthService:
    """Authentication and authorization service"""
    
    def __init__(self, db: Session):
        self.db = db
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        """Hash a password"""
        return pwd_context.hash(password)
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire, "type": "access"})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    
    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """Create a JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    
    def decode_token(self, token: str) -> Dict[str, Any]:
        """Decode and validate a JWT token"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate a user with username and password"""
        user = self.db.query(User).filter(User.username == username).first()
        if not user:
            return None
        if not self.verify_password(password, user.hashed_password):
            return None
        return user
    
    def create_user_session(self, user: User, ip_address: str, user_agent: str) -> UserSession:
        """Create a new user session with tokens"""
        access_token = self.create_access_token(data={"sub": user.username, "user_id": user.id})
        refresh_token = self.create_refresh_token(data={"sub": user.username, "user_id": user.id})
        
        session = UserSession(
            user_id=user.id,
            token=access_token,
            refresh_token=refresh_token,
            expires_at=datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        
        # Update user last login
        user.last_login = datetime.utcnow()
        self.db.commit()
        
        return session
    
    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """Refresh an access token using a refresh token"""
        try:
            payload = self.decode_token(refresh_token)
            if payload.get("type") != "refresh":
                return None
            
            session = self.db.query(UserSession).filter(
                UserSession.refresh_token == refresh_token,
                UserSession.is_active == True
            ).first()
            
            if not session or session.expires_at < datetime.utcnow():
                return None
            
            # Create new access token
            new_access_token = self.create_access_token(
                data={"sub": payload.get("sub"), "user_id": payload.get("user_id")}
            )
            
            # Update session
            session.token = new_access_token
            session.expires_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            self.db.commit()
            
            return new_access_token
        except JWTError:
            return None
    
    def revoke_session(self, token: str) -> bool:
        """Revoke a user session"""
        session = self.db.query(UserSession).filter(
            UserSession.token == token,
            UserSession.is_active == True
        ).first()
        
        if session:
            session.is_active = False
            self.db.commit()
            return True
        return False
    
    def get_current_user(self, credentials: HTTPAuthorizationCredentials) -> User:
        """Get the current authenticated user from JWT token"""
        token = credentials.credentials
        payload = self.decode_token(token)
        
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user = self.db.query(User).filter(User.username == username).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive"
            )
        
        return user
    
    def check_permission(self, user: User, resource: str, action: str) -> bool:
        """Check if a user has permission to perform an action on a resource"""
        if user.is_superuser:
            return True
        
        # Get all permissions for the user's roles
        permissions = self.db.query(Permission).join(
            Permission.roles
        ).join(
            Role.users
        ).filter(
            User.id == user.id,
            Permission.resource == resource,
            Permission.action == action
        ).all()
        
        return len(permissions) > 0
    
    def log_audit_event(self, user_id: int, action: str, resource: str, 
                       resource_id: str = None, details: str = None,
                       ip_address: str = None, user_agent: str = None):
        """Log an audit event"""
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        self.db.add(audit_log)
        self.db.commit()
    
    def create_user(self, username: str, email: str, password: str, 
                   full_name: str = None, is_superuser: bool = False) -> User:
        """Create a new user"""
        # Check if user already exists
        if self.db.query(User).filter(User.username == username).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered"
            )
        
        if self.db.query(User).filter(User.email == email).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        user = User(
            username=username,
            email=email,
            hashed_password=self.get_password_hash(password),
            full_name=full_name,
            is_superuser=is_superuser
        )
        
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        
        # Assign default role if not superuser
        if not is_superuser:
            default_role = self.db.query(Role).filter(Role.name == "analyst").first()
            if default_role:
                user.roles.append(default_role)
                self.db.commit()
        
        self.log_audit_event(
            user_id=user.id,
            action="user_created",
            resource="users",
            resource_id=str(user.id),
            details=f"User {username} created"
        )
        
        return user