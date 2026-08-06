from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import logging
from typing import Callable
from ..utils.exceptions import handle_exception

logger = logging.getLogger(__name__)

class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    """Global error handling middleware"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> JSONResponse:
        try:
            response = await call_next(request)
            return response
        except Exception as exc:
            # Log the exception
            logger.error(
                f"Unhandled exception: {str(exc)}",
                extra={
                    "extra_fields": {
                        "path": request.url.path,
                        "method": request.method,
                        "exception_type": type(exc).__name__
                    }
                }
            )
            
            # Handle the exception
            error_response = handle_exception(exc)
            
            return JSONResponse(
                status_code=error_response["error"]["status_code"],
                content=error_response
            )

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable):
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        return response

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all incoming requests"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable):
        # Log request
        logger.info(
            f"Incoming request: {request.method} {request.url.path}",
            extra={
                "extra_fields": {
                    "method": request.method,
                    "path": request.url.path,
                    "query_params": str(request.query_params),
                    "client_host": request.client.host if request.client else None
                }
            }
        )
        
        # Process request
        response = await call_next(request)
        
        # Log response
        logger.info(
            f"Request completed: {request.method} {request.url.path} - Status: {response.status_code}",
            extra={
                "extra_fields": {
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code
                }
            }
        )
        
        return response