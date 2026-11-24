from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from app.database import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(64), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    target_url = Column(Text, nullable=False)
    target_domain = Column(String(512), nullable=False, index=True)
    target_ip = Column(String(64), nullable=True)
    scan_mode = Column(String(32), default="quick")  # quick, full, passive
    status = Column(String(32), default="pending")   # pending, scanning, completed, failed
    security_score = Column(Integer, default=100)
    risk_level = Column(String(32), default="LOW")    # CRITICAL, HIGH, MEDIUM, LOW, SECURE
    total_checks = Column(Integer, default=0)
    scan_duration_seconds = Column(Float, default=0.0)
    overall_ai_assessment = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
