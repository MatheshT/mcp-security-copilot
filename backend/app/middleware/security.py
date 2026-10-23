from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from typing import Callable, Optional
import re
import os
from dotenv import load_dotenv

load_dotenv()

security = HTTPBearer()

class InputSanitizationMiddleware(BaseHTTPMiddleware):
    """Middleware to sanitize and validate input data"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        
        # Common SQL injection patterns
        self.sql_injection_patterns = [
            r"(\bunion\b.*\bselect\b)",
            r"(\bselect\b.*\bfrom\b)",
            r"(\binsert\b.*\binto\b)",
            r"(\bdelete\b.*\bfrom\b)",
            r"(\bdrop\b.*\btable\b)",
            r"(\bupdate\b.*\bset\b)",
            r"(\bexec\b\()",
            r"(\bor\b.*=.*\bor\b)",
            r"(\band\b.*=.*\band\b)",
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe.*?>",
            r"<object.*?>",
            r"<embed.*?>",
        ]
    
    async def dispatch(self, request: Request, call_next: Callable):
        # Exempt SOC investigation & security endpoints so analysts can query threat signatures & SQLi/XSS logs
        exempt_prefixes = (
            '/api/investigate',
            '/api/chat',
            '/api/v1/investigation',
            '/api/v2/investigation',
            '/api/log_analysis',
            '/api/detection',
            '/api/windows_logs',
            '/api/mcp',
            '/api/report',
            '/api/ml',
            '/api/upload',
        )
        if request.url.path.startswith(exempt_prefixes):
            return await call_next(request)

        # Only sanitize POST, PUT, PATCH requests
        if request.method in ["POST", "PUT", "PATCH"]:
            # Read request body
            body = await request.body()
            
            # Convert to string for analysis
            body_str = body.decode('utf-8', errors='ignore')
            
            # Check for SQL injection
            for pattern in self.sql_injection_patterns:
                if re.search(pattern, body_str, re.IGNORECASE):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Potentially malicious input detected"
                    )
            
            # Check for XSS
            for pattern in self.xss_patterns:
                if re.search(pattern, body_str, re.IGNORECASE):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Potentially malicious input detected"
                    )
        
        return await call_next(request)

class IPWhitelistMiddleware(BaseHTTPMiddleware):
    """Middleware to whitelist/blacklist IP addresses"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.whitelist = os.getenv("IP_WHITELIST", "").split(",") if os.getenv("IP_WHITELIST") else []
        self.blacklist = os.getenv("IP_BLACKLIST", "").split(",") if os.getenv("IP_BLACKLIST") else []
    
    async def dispatch(self, request: Request, call_next: Callable):
        client_ip = request.client.host if request.client else None
        
        if client_ip:
            # Check blacklist first
            if self.blacklist and client_ip in self.blacklist:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied from this IP"
                )
            
            # Check whitelist if configured
            if self.whitelist and client_ip not in self.whitelist:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied. IP not whitelisted"
                )
        
        return await call_next(request)

class RequestSizeMiddleware(BaseHTTPMiddleware):
    """Middleware to limit request size"""
    
    def __init__(self, app: ASGIApp, max_size: int = 10 * 1024 * 1024):  # 10MB default
        super().__init__(app)
        self.max_size = max_size
    
    async def dispatch(self, request: Request, call_next: Callable):
        content_length = request.headers.get("content-length")
        
        if content_length:
            if int(content_length) > self.max_size:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Request too large. Maximum size is {self.max_size} bytes"
                )
        
        return await call_next(request)