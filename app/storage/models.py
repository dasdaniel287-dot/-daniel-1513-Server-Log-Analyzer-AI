"""
SQLAlchemy Models for Persistent Storage of Analysis Runs & Alerts
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from app.storage.database import Base


class AnalysisSessionRecord(Base):
    __tablename__ = "analysis_sessions"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    total_lines = Column(Integer, default=0)
    parsed_records = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    summary_json = Column(JSON, nullable=True)


class SecurityAlertRecord(Base):
    __tablename__ = "security_alerts"

    id = Column(String(64), primary_key=True, index=True)
    session_id = Column(Integer, index=True, nullable=True)
    timestamp = Column(String(64), nullable=True)
    severity = Column(String(32), index=True)
    category = Column(String(64), index=True)
    title = Column(String(255))
    status = Column(String(32), default="New", index=True)
    evidence_json = Column(JSON, nullable=True)
