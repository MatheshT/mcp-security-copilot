from pydantic_settings import BaseSettings
from typing import Optional, List
import secrets
from functools import lru_cache
import os
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    """Application settings using Pydantic for validation"""
    
    # Application
    APP_NAME: str = "Security Copilot"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = True
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    BCRYPT_ROUNDS: int = 12
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./security_copilot.db")
    DATABASE_POOL_SIZE: int = 5
    DATABASE_MAX_OVERFLOW: int = 10
    
    # Redis
    REDIS_URL: Optional[str] = os.getenv("REDIS_URL")
    REDIS_CACHE_TTL: int = 3600  # 1 hour default
    
    # LLM Configuration
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "free")  # free, ollama, openai
    OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL: str = "gpt-4"
    OPENAI_TEMPERATURE: float = 0.7
    OPENAI_MAX_TOKENS: int = 2000
    
    # Security Tools
    WAZUH_URL: Optional[str] = os.getenv("WAZUH_URL")
    WAZUH_API_URL: Optional[str] = os.getenv("WAZUH_API_URL")
    WAZUH_API_KEY: Optional[str] = os.getenv("WAZUH_API_KEY")
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")
    MISP_API_URL: Optional[str] = os.getenv("MISP_API_URL")
    MISP_API_KEY: Optional[str] = os.getenv("MISP_API_KEY")
    SHODAN_API_KEY: Optional[str] = os.getenv("SHODAN_API_KEY")
    DEFAULT_SECURITY_TOOLS: str = os.getenv("DEFAULT_SECURITY_TOOLS", "Wazuh,VirusTotal,MISP,Shodan")
    
    # API Configuration
    API_V1_PREFIX: str = "/api"
    MAX_UPLOAD_SIZE: int = 10 * 1024 * 1024  # 10MB
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = 60
    
    # CORS
    CORS_ORIGINS: List[str] = ["*"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["*"]
    CORS_ALLOW_HEADERS: List[str] = ["*"]
    
    # Monitoring
    PROMETHEUS_ENABLED: bool = os.getenv("PROMETHEUS_ENABLED", "false").lower() == "true"
    PROMETHEUS_PORT: int = int(os.getenv("PROMETHEUS_PORT", "9090"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    # Email Configuration (for notifications)
    SMTP_ENABLED: bool = False
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM_EMAIL: Optional[str] = None
    
    # Slack Integration
    SLACK_ENABLED: bool = False
    SLACK_WEBHOOK_URL: Optional[str] = None
    
    # Webhook Configuration
    WEBHOOK_ENABLED: bool = False
    WEBHOOK_SECRET: Optional[str] = None
    WEBHOOK_TIMEOUT: int = 30
    
    # Feature Flags
    ENABLE_PREDICTIVE_ANALYTICS: bool = True
    ENABLE_COLLABORATIVE_INVESTIGATION: bool = True
    ENABLE_BLOCKCHAIN_EVIDENCE: bool = True
    ENABLE_NEURAL_ANOMALY_DETECTION: bool = True
    ENABLE_THREAT_ACTOR_PERSONA: bool = True
    ENABLE_AUTOMATED_RESPONSE: bool = True
    
    # Data Retention
    AUDIT_LOG_RETENTION_DAYS: int = 90
    INVESTIGATION_RETENTION_DAYS: int = 365
    SESSION_RETENTION_DAYS: int = 30
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"
    
    @property
    def security_tools_list(self) -> List[str]:
        """Parse security tools from comma-separated string"""
        return [tool.strip() for tool in self.DEFAULT_SECURITY_TOOLS.split(",") if tool.strip()]

@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()

# Global settings instance
settings = get_settings()