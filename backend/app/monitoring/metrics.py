from prometheus_client import Counter, Histogram, Gauge, Info
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response
import os
from dotenv import load_dotenv

load_dotenv()

# Application info
app_info = Info('security_copilot', 'Security Copilot Application Info')
app_info.info({
    'version': '2.0.0',
    'environment': os.getenv('ENVIRONMENT', 'development')
})

# HTTP request metrics
http_requests_total = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration_seconds = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint']
)

# Authentication metrics
auth_logins_total = Counter(
    'auth_logins_total',
    'Total login attempts',
    ['status']  # success, failure
)

auth_active_sessions = Gauge(
    'auth_active_sessions',
    'Number of active user sessions'
)

# Investigation metrics
investigations_total = Counter(
    'investigations_total',
    'Total investigations created',
    ['severity']
)

investigations_duration_seconds = Histogram(
    'investigations_duration_seconds',
    'Investigation processing duration in seconds'
)

# Security tool metrics
tool_requests_total = Counter(
    'tool_requests_total',
    'Total tool API requests',
    ['tool_name', 'status']
)

tool_response_time_seconds = Histogram(
    'tool_response_time_seconds',
    'Tool API response time in seconds',
    ['tool_name']
)

# LLM metrics
llm_requests_total = Counter(
    'llm_requests_total',
    'Total LLM API requests',
    ['provider', 'status']
)

llm_tokens_total = Counter(
    'llm_tokens_total',
    'Total LLM tokens processed',
    ['provider', 'type']  # type: prompt, completion
)

# Database metrics
db_connections_active = Gauge(
    'db_connections_active',
    'Active database connections'
)

db_query_duration_seconds = Histogram(
    'db_query_duration_seconds',
    'Database query duration in seconds',
    ['operation']
)

# Error metrics
errors_total = Counter(
    'errors_total',
    'Total errors',
    ['type', 'severity']
)

# Business metrics
security_alerts_total = Counter(
    'security_alerts_total',
    'Total security alerts',
    ['severity', 'type']
)

threat_iocs_total = Gauge(
    'threat_iocs_total',
    'Total indicators of compromise tracked'
)

def get_metrics():
    """Generate Prometheus metrics"""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )