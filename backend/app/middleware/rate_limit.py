from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, HTTPException, status
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv()

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[os.getenv("RATE_LIMIT_PER_MINUTE", "60/minute")]
)

class RateLimitError(HTTPException):
    """Custom rate limit error"""
    def __init__(self, detail: str = "Rate limit exceeded"):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail
        )

def check_rate_limit():
    """Dependency to check rate limit"""
    async def rate_limit_dependency(request: Request):
        # Rate limiting is handled by SlowAPI middleware
        pass
    return rate_limit_dependency