import json
import hashlib
from typing import Optional, Any, Callable
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv()

# Simple in-memory cache fallback
class SimpleCache:
    """Simple in-memory cache for development/testing"""
    
    def __init__(self):
        self._cache = {}
    
    def get(self, key: str) -> Optional[Any]:
        return self._cache.get(key)
    
    def set(self, key: str, value: Any, ttl: int = 3600):
        self._cache[key] = value
    
    def delete(self, key: str):
        if key in self._cache:
            del self._cache[key]
    
    def clear(self):
        self._cache.clear()

# Try to use Redis if available
try:
    import redis
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    redis_client.ping()
    cache_enabled = True
except (ImportError, Exception):
    redis_client = None
    cache_enabled = False
    cache = SimpleCache()

def get_cache():
    """Get cache instance (Redis or fallback)"""
    if cache_enabled and redis_client:
        return redis_client
    return cache

def cache_key(*args, **kwargs) -> str:
    """Generate a cache key from function arguments"""
    key_data = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True)
    return hashlib.md5(key_data.encode()).hexdigest()

def cached(ttl: int = 3600, key_prefix: str = ""):
    """Decorator to cache function results"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            key = f"{key_prefix}:{cache_key(*args, **kwargs)}"
            
            # Try to get from cache
            cache_instance = get_cache()
            cached_result = cache_instance.get(key)
            
            if cached_result is not None:
                return cached_result
            
            # Execute function
            result = await func(*args, **kwargs)
            
            # Cache the result
            cache_instance.set(key, result, ttl)
            
            return result
        
        return wrapper
    return decorator

def invalidate_cache(pattern: str):
    """Invalidate cache keys matching a pattern"""
    cache_instance = get_cache()
    
    if cache_enabled and redis_client:
        # Redis pattern matching
        keys = redis_client.keys(f"*{pattern}*")
        if keys:
            redis_client.delete(*keys)
    else:
        # Simple cache - clear all (not efficient but works for fallback)
        cache_instance.clear()