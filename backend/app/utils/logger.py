import logging
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime
import json
import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

settings = Settings()

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record):
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)
        
        return json.dumps(log_data)

class SecurityCopilotLogger:
    """Centralized logging configuration for the application"""
    
    def __init__(self):
        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        
        # Configure root logger
        self.root_logger = logging.getLogger()
        self.root_logger.setLevel(getattr(logging, settings.LOG_LEVEL))
        
        # Remove existing handlers
        self.root_logger.handlers.clear()
        
        # Create formatters
        json_formatter = JSONFormatter()
        text_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler (text format for development)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(text_formatter)
        self.root_logger.addHandler(console_handler)
        
        # File handler (JSON format for production)
        file_handler = logging.FileHandler(
            self.log_dir / "security_copilot.log",
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(json_formatter)
        self.root_logger.addHandler(file_handler)
        
        # Error file handler
        error_handler = logging.FileHandler(
            self.log_dir / "errors.log",
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(json_formatter)
        self.root_logger.addHandler(error_handler)
        
        # Security audit log (separate file for security events)
        self.audit_logger = logging.getLogger("audit")
        self.audit_logger.setLevel(logging.INFO)
        audit_handler = logging.FileHandler(
            self.log_dir / "audit.log",
            encoding='utf-8'
        )
        audit_handler.setFormatter(json_formatter)
        self.audit_logger.addHandler(audit_handler)
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger with the specified name"""
        return logging.getLogger(name)
    
    def log_security_event(self, event_type: str, details: dict, user_id: Optional[int] = None):
        """Log security events to the audit log"""
        log_data = {
            "event_type": event_type,
            "user_id": user_id,
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.audit_logger.info(json.dumps(log_data), extra={'extra_fields': log_data})

# Global logger instance
logger_config = SecurityCopilotLogger()

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance"""
    return logger_config.get_logger(name)

def log_security_event(event_type: str, details: dict, user_id: Optional[int] = None):
    """Log a security event"""
    logger_config.log_security_event(event_type, details, user_id)