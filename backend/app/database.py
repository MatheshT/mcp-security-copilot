from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./security_copilot.db")

# Create engine
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},  # Required for SQLite
        pool_pre_ping=True
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True
    )

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()

def get_db():
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initialize database tables"""
    try:
        from .auth.models import Base as AuthBase
        AuthBase.metadata.create_all(bind=engine)
        print("Auth tables created")
    except Exception as e:
        print(f"Error creating auth tables: {e}")
    
    try:
        from .log_collector.models import Base as LogBase
        LogBase.metadata.create_all(bind=engine)
        print("Log collector tables created")
    except Exception as e:
        print(f"Error creating log collector tables: {e}")
    
    # Create default roles and permissions
    try:
        from .auth.seed import seed_default_data
        seed_default_data(next(get_db()))
        print("Default data seeded")
    except Exception as e:
        print(f"Error seeding default data: {e}")