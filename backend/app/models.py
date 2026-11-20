from sqlalchemy import (JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer,
                        String, Text, UniqueConstraint)

from .db import Base, utcnow


class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    slug = Column(String, unique=True, nullable=False)
    plan = Column(String, default="Business")
    region = Column(String, default="eu-west-1")
    status = Column(String, default="active")
    egress_quota_mb = Column(Integer, default=100)
    created_at = Column(DateTime, default=utcnow)


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), index=True, nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, default="")
    password_hash = Column(String, nullable=False)
    role = Column(String, default="analyst")
    created_at = Column(DateTime, default=utcnow)
    last_login = Column(DateTime)


class Collector(Base):
    __tablename__ = "collectors"
    id = Column(String, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), index=True, nullable=False)
    name = Column(String, nullable=False)
    host = Column(String, nullable=False)
    region = Column(String, default="eu-west-1")
    version = Column(String, default="2.4.1")
    status = Column(String, default="online")  # online | degraded | offline
    mode = Column(String, default="filter-redact-aggregate")
    secret = Column(String, default="collector-secret")
    last_seen = Column(DateTime, default=utcnow)
    buffer_depth = Column(Integer, default=0)
    events_sent = Column(Integer, default=0)
    services = Column(JSON, default=list)


class MetricSample(Base):
    __tablename__ = "metric_samples"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String, index=True, nullable=False)
    collector_id = Column(String, index=True, nullable=False)
    metric = Column(String, index=True, nullable=False)
    value = Column(Float, nullable=False)
    ts = Column(DateTime, index=True, default=utcnow)


class TelemetryEvent(Base):
    __tablename__ = "telemetry_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, index=True, nullable=False)
    collector_id = Column(String, index=True, nullable=False)
    metric = Column(String, index=True, nullable=False)
    value = Column(Float, nullable=False)
    unit = Column(String, default="")
    sequence = Column(Integer, default=0)
    observed_at = Column(DateTime, default=utcnow)
    received_at = Column(DateTime, default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String, primary_key=True)
    tenant_id = Column(String, index=True, nullable=False)
    fingerprint = Column(String, index=True, nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, default="warning")  # critical | warning | info
    state = Column(String, default="open")  # open | acknowledged | resolved
    metric = Column(String, default="")
    host = Column(String, default="")
    service = Column(String, default="")
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
    occurrences = Column(Integer, default=1)
    suppressed = Column(Integer, default=0)
    explanation = Column(JSON, default=dict)
    incident_id = Column(String, index=True)
    acknowledged_by = Column(String)
    notes = Column(Text, default="")


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(String, primary_key=True)
    tenant_id = Column(String, index=True, nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, default="warning")
    status = Column(String, default="open")  # open | investigating | mitigated | closed
    opened_at = Column(DateTime, default=utcnow)
    closed_at = Column(DateTime)
    root_cause = Column(Text, default="")
    confidence = Column(Float, default=0.0)
    summary = Column(Text, default="")
    alert_ids = Column(JSON, default=list)
    owner = Column(String, default="unassigned")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String, index=True, nullable=False)
    actor = Column(String, default="system")
    action = Column(String, nullable=False)
    resource = Column(String, default="")
    detail = Column(JSON, default=dict)
    ts = Column(DateTime, default=utcnow, index=True)
    prev_hash = Column(String, default="")
    hash = Column(String, default="")


class EgressRecord(Base):
    __tablename__ = "egress_records"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String, index=True, nullable=False)
    collector_id = Column(String, nullable=False)
    destination = Column(String, nullable=False)
    payload = Column(JSON, default=dict)
    approved_fields = Column(JSON, default=list)
    dropped_fields = Column(JSON, default=list)
    redaction_report = Column(JSON, default=list)
    checksum = Column(String, default="")
    status = Column(String, default="delivered")  # delivered | retrying | buffered | blocked
    bytes = Column(Integer, default=0)
    attempts = Column(Integer, default=1)
    ts = Column(DateTime, default=utcnow, index=True)
    ack = Column(String, default="")


class Scenario(Base):
    __tablename__ = "scenarios"
    __table_args__ = (UniqueConstraint("tenant_id", "key", name="uq_scenario_tenant_key"),)
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String, index=True, nullable=False)
    key = Column(String, nullable=False)
    active = Column(Boolean, default=True)
    activated_at = Column(DateTime, default=utcnow)
    activated_by = Column(String, default="")


class Recommendation(Base):
    __tablename__ = "recommendations"
    id = Column(String, primary_key=True)
    tenant_id = Column(String, index=True, nullable=False)
    title = Column(String, nullable=False)
    detail = Column(Text, default="")
    category = Column(String, default="reliability")
    impact = Column(String, default="medium")
    confidence = Column(Float, default=0.8)
    status = Column(String, default="proposed")  # proposed | approved | executed | dismissed
    evidence = Column(JSON, default=list)
    created_at = Column(DateTime, default=utcnow)
