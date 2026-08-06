from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv

load_dotenv()

from .api import router as api_router
from .auth.routes import router as auth_router
from .routes.v1.investigation import router as v1_router
from .routes.v2.investigation import router as v2_router
from .routes.log_analysis.api import router as log_analysis_router
from .routes.detection import router as detection_router
from .database import init_db
from .middleware.error_handler import ErrorHandlerMiddleware, SecurityHeadersMiddleware, RequestLoggingMiddleware
from .middleware.security import InputSanitizationMiddleware, RequestSizeMiddleware
from .utils.logger import get_logger
import os
from dotenv import load_dotenv

load_dotenv()

# Import monitoring conditionally
def get_metrics():
    try:
        from .monitoring.metrics import get_metrics as _get_metrics
        return _get_metrics()
    except (ImportError, Exception):
        return {"error": "Prometheus metrics not available"}

logger = get_logger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events"""
    # Startup
    logger.info("Starting Security Copilot API v2.0.0")
    init_db()
    logger.info("Database initialized")
    yield
    # Shutdown
    logger.info("Shutting down Security Copilot API")

app = FastAPI(
    title='Security Copilot API',
    version='2.0.0',
    description='Enterprise-grade AI-powered security investigation and SOC reporting platform.',
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Add middleware
app.add_middleware(ErrorHandlerMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(InputSanitizationMiddleware)
app.add_middleware(RequestSizeMiddleware, max_size=10 * 1024 * 1024)  # 10MB

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],  # Configure properly for production
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

# Include routers
app.include_router(api_router, prefix="/api")
app.include_router(auth_router, prefix="/api")
app.include_router(v1_router, prefix="/api")
app.include_router(v2_router, prefix="/api")
app.include_router(log_analysis_router, prefix="/api")
app.include_router(detection_router, prefix="/api")


@app.get('/health', summary='Health check endpoint')
def health():
    return {'status': 'ok', 'version': '2.0.0'}

@app.get('/metrics', summary='Prometheus metrics endpoint')
def metrics():
    """Prometheus metrics endpoint for monitoring"""
    return get_metrics()
