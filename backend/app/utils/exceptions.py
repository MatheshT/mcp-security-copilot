from typing import Optional, Any, Dict
from datetime import datetime

# HTTP Status Codes
HTTP_400_BAD_REQUEST = 400
HTTP_401_UNAUTHORIZED = 401
HTTP_403_FORBIDDEN = 403
HTTP_404_NOT_FOUND = 404
HTTP_409_CONFLICT = 409
HTTP_422_UNPROCESSABLE_ENTITY = 422
HTTP_429_TOO_MANY_REQUESTS = 429
HTTP_500_INTERNAL_SERVER_ERROR = 500
HTTP_502_BAD_GATEWAY = 502
HTTP_503_SERVICE_UNAVAILABLE = 503

class SecurityCopilotException(Exception):
    """Base exception for Security Copilot application"""
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        status_code: int = HTTP_500_INTERNAL_SERVER_ERROR
    ):
        self.message = message
        self.details = details or {}
        self.status_code = status_code
        super().__init__(self.message)

class AuthenticationError(SecurityCopilotException):
    """Authentication related errors"""
    
    def __init__(self, message: str = "Authentication failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            details=details,
            status_code=HTTP_401_UNAUTHORIZED
        )

class AuthorizationError(SecurityCopilotException):
    """Authorization related errors"""
    
    def __init__(self, message: str = "Permission denied", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            details=details,
            status_code=HTTP_403_FORBIDDEN
        )

class ValidationError(SecurityCopilotException):
    """Validation related errors"""
    
    def __init__(self, message: str = "Validation failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            details=details,
            status_code=HTTP_422_UNPROCESSABLE_ENTITY
        )

class NotFoundError(SecurityCopilotException):
    """Resource not found errors"""
    
    def __init__(self, message: str = "Resource not found", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            details=details,
            status_code=HTTP_404_NOT_FOUND
        )

class ConflictError(SecurityCopilotException):
    """Conflict errors (duplicate resources, etc.)"""
    
    def __init__(self, message: str = "Resource conflict", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            details=details,
            status_code=HTTP_409_CONFLICT
        )

class RateLimitError(SecurityCopilotException):
    """Rate limiting errors"""
    
    def __init__(self, message: str = "Rate limit exceeded", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            details=details,
            status_code=HTTP_429_TOO_MANY_REQUESTS
        )

class ServiceUnavailableError(SecurityCopilotException):
    """Service unavailable errors"""
    
    def __init__(self, message: str = "Service temporarily unavailable", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            details=details,
            status_code=HTTP_503_SERVICE_UNAVAILABLE
        )

class InvestigationError(SecurityCopilotException):
    """Investigation related errors"""
    
    def __init__(self, message: str = "Investigation failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            details=details,
            status_code=HTTP_500_INTERNAL_SERVER_ERROR
        )

class ToolIntegrationError(SecurityCopilotException):
    """Security tool integration errors"""
    
    def __init__(self, tool_name: str, message: str = "Tool integration failed", details: Optional[Dict[str, Any]] = None):
        error_details = details or {}
        error_details["tool_name"] = tool_name
        super().__init__(
            message=message,
            details=error_details,
            status_code=HTTP_502_BAD_GATEWAY
        )

class LLMError(SecurityCopilotException):
    """LLM related errors"""
    
    def __init__(self, message: str = "LLM processing failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            details=details,
            status_code=HTTP_500_INTERNAL_SERVER_ERROR
        )

def handle_exception(exc: Exception) -> Dict[str, Any]:
    """Convert exception to standardized error response"""
    if isinstance(exc, SecurityCopilotException):
        return {
            "error": {
                "message": exc.message,
                "details": exc.details,
                "status_code": exc.status_code,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
    else:
        # Unknown exception
        return {
            "error": {
                "message": "An unexpected error occurred",
                "details": {"exception_type": type(exc).__name__},
                "status_code": HTTP_500_INTERNAL_SERVER_ERROR,
                "timestamp": datetime.utcnow().isoformat()
            }
        }