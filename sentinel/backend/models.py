import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey, Integer, String, Text
)
from sqlalchemy.orm import relationship

from database import Base


def _uuid():
    return str(uuid.uuid4())


def _now():
    return datetime.utcnow()


# ── Threat Intelligence ──────────────────────────────────────────────────────

class TICache(Base):
    __tablename__ = "ti_cache"

    id = Column(String, primary_key=True, default=_uuid)
    indicator = Column(String, nullable=False, index=True)
    indicator_type = Column(Enum("ip", "domain", "url", "hash", "email", name="ind_type"), nullable=False)
    results_json = Column(Text, nullable=False)
    verdict = Column(Enum("malicious", "suspicious", "clean", "unknown", name="verdict_enum"), nullable=False)
    ai_summary = Column(Text)
    ai_action = Column(Text)
    confidence = Column(String)
    flagged_by = Column(Text)
    created_at = Column(DateTime, default=_now)
    expires_at = Column(DateTime)


# ── IOCs ─────────────────────────────────────────────────────────────────────

class IOC(Base):
    __tablename__ = "iocs"

    id = Column(String, primary_key=True, default=_uuid)
    indicator = Column(String, nullable=False, index=True)
    indicator_type = Column(String, nullable=False)
    verdict = Column(String, default="unknown")
    severity = Column(
        Enum("critical", "high", "medium", "low", "info", name="ioc_severity"),
        default="info",
    )
    source = Column(String, default="manual")
    status = Column(
        Enum("active", "blocked", "investigating", "resolved", "false_positive", name="ioc_status"),
        default="active",
    )
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=_now)


# ── Incidents ─────────────────────────────────────────────────────────────────

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=_uuid)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    incident_type = Column(String, default="other")
    severity = Column(
        Enum("critical", "high", "medium", "low", name="inc_severity"),
        default="medium",
    )
    status = Column(
        Enum("new", "investigating", "contained", "recovering", "closed", name="inc_status"),
        default="new",
    )
    affected_systems = Column(Text)
    reporter_name = Column(String, nullable=False)
    reporter_email = Column(String, nullable=False)
    ai_playbook = Column(Text)
    ai_classification = Column(Text)
    mitre_techniques = Column(Text)
    peca_required = Column(Boolean, default=False)
    peca_reason = Column(Text)
    created_at = Column(DateTime, default=_now)
    updated_at = Column(DateTime, default=_now, onupdate=_now)
    closed_at = Column(DateTime, nullable=True)

    timeline = relationship("IncidentTimeline", back_populates="incident", cascade="all, delete-orphan")
    evidence = relationship("Evidence", back_populates="incident", cascade="all, delete-orphan")
    iocs = relationship("IOC", backref="incident", foreign_keys=[IOC.incident_id])


class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"

    id = Column(String, primary_key=True, default=_uuid)
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=False)
    action = Column(String, nullable=False)
    detail = Column(Text)
    created_by = Column(String, nullable=False)
    created_at = Column(DateTime, default=_now)

    incident = relationship("Incident", back_populates="timeline")


# ── Evidence ──────────────────────────────────────────────────────────────────

class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String, primary_key=True, default=_uuid)
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=False)
    file_name = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    file_hash_sha256 = Column(String, nullable=False)
    file_size = Column(Integer)
    description = Column(Text)
    uploaded_by = Column(String, nullable=False)
    created_at = Column(DateTime, default=_now)

    incident = relationship("Incident", back_populates="evidence")
    custody_logs = relationship("CustodyLog", back_populates="evidence", cascade="all, delete-orphan")


class CustodyLog(Base):
    __tablename__ = "custody_log"

    id = Column(String, primary_key=True, default=_uuid)
    evidence_id = Column(String, ForeignKey("evidence.id"), nullable=False)
    action = Column(
        Enum("uploaded", "accessed", "exported", "deleted", name="custody_action"),
        nullable=False,
    )
    performed_by = Column(String, nullable=False)
    timestamp = Column(DateTime, default=_now)
    notes = Column(Text, nullable=True)

    evidence = relationship("Evidence", back_populates="custody_logs")


# ── Playbooks ─────────────────────────────────────────────────────────────────

class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    incident_type = Column(String, nullable=False)
    description = Column(String)
    content_json = Column(Text, nullable=False)
    is_builtin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_now)
