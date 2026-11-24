from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings
import logging

logger = logging.getLogger("secureexplain.database")

def create_resilient_engine():
    db_url = settings.DATABASE_URL
    connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}
    
    try:
        eng = create_engine(db_url, connect_args=connect_args, pool_pre_ping=True)
        # Test engine with a lightweight query/connect
        with eng.connect() as conn:
            pass
        return eng
    except Exception as e:
        logger.warning(f"Failed to initialize database at '{db_url}': {e}. Falling back to /tmp/secureexplain.db")
        try:
            fallback_url = "sqlite:////tmp/secureexplain.db"
            eng = create_engine(fallback_url, connect_args={"check_same_thread": False}, pool_pre_ping=True)
            with eng.connect() as conn:
                pass
            return eng
        except Exception as e2:
            logger.warning(f"Failed /tmp database fallback: {e2}. Falling back to in-memory SQLite.")
            return create_engine("sqlite:///:memory:?check_same_thread=False", pool_pre_ping=True)

engine = create_resilient_engine()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
