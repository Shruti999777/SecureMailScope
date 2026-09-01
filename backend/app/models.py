"""
SecureMailScope - SQLAlchemy ORM Models
"""

import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(String(64), primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    file_size_bytes = Column(Integer, default=0)
    status = Column(String(32), default="queued", index=True)  # queued, processing, completed, failed
    progress = Column(Integer, default=0)
    current_step = Column(String(255), default="Initialized")
    
    # Global posture results
    overall_score = Column(Integer, nullable=True)
    overall_risk_level = Column(String(32), nullable=True)
    security_grade = Column(String(8), nullable=True)
    total_sessions = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    
    error_message = Column(Text, nullable=True)
    summary_data = Column(JSON, nullable=True)
    
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    sessions = relationship("EmailSession", back_populates="job", cascade="all, delete-orphan")
    findings = relationship("SecurityFinding", back_populates="job", cascade="all, delete-orphan")
    certificates = relationship("CertificateRecord", back_populates="job", cascade="all, delete-orphan")


class EmailSession(Base):
    __tablename__ = "email_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(64), ForeignKey("analysis_jobs.id"), index=True, nullable=False)
    stream_id = Column(String(64), nullable=False, index=True)
    
    protocol = Column(String(32), nullable=False)
    is_implicit_tls = Column(Boolean, default=False)
    starttls_offered = Column(Boolean, default=False)
    starttls_upgraded = Column(Boolean, default=False)
    
    client_ip = Column(String(64), nullable=False)
    server_ip = Column(String(64), nullable=False)
    client_port = Column(Integer, nullable=False)
    server_port = Column(Integer, nullable=False)
    
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    duration = Column(Float, default=0.0)
    
    tls_version = Column(String(32), default="None")
    cipher_suite = Column(String(128), default="Unknown")
    key_exchange = Column(String(64), default="Unknown")
    forward_secrecy = Column(Boolean, default=False)
    cipher_strength = Column(String(32), default="UNKNOWN")
    sni = Column(String(255), nullable=True)
    
    risk_level = Column(String(32), default="SECURE")
    risk_score = Column(Integer, default=0)
    
    # ML features
    rf_predicted_risk = Column(String(32), default="UNKNOWN")
    rf_confidence = Column(Float, default=0.0)
    is_anomalous = Column(Boolean, default=False)
    anomaly_score = Column(Float, default=0.0)
    
    job = relationship("AnalysisJob", back_populates="sessions")


class CertificateRecord(Base):
    __tablename__ = "certificate_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(64), ForeignKey("analysis_jobs.id"), index=True, nullable=False)
    stream_id = Column(String(64), nullable=False)
    
    subject_cn = Column(String(255), nullable=True)
    subject_org = Column(String(255), nullable=True)
    issuer_cn = Column(String(255), nullable=True)
    issuer_org = Column(String(255), nullable=True)
    serial_number = Column(String(128), nullable=True)
    
    not_before = Column(String(64), nullable=True)
    not_after = Column(String(64), nullable=True)
    is_expired = Column(Boolean, default=False)
    days_to_expiry = Column(Integer, default=0)
    
    key_type = Column(String(64), default="Unknown")
    key_size = Column(Integer, default=0)
    is_weak_key = Column(Boolean, default=False)
    
    signature_algorithm = Column(String(128), default="Unknown")
    is_weak_signature = Column(Boolean, default=False)
    
    chain_length = Column(Integer, default=1)
    chain_status = Column(String(64), default="VALID_CHAIN")
    chain_valid = Column(Boolean, default=True)
    is_self_signed = Column(Boolean, default=False)
    
    hierarchy_json = Column(JSON, nullable=True)

    job = relationship("AnalysisJob", back_populates="certificates")


class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(64), ForeignKey("analysis_jobs.id"), index=True, nullable=False)
    stream_id = Column(String(64), nullable=False)
    protocol = Column(String(32), default="UNKNOWN")
    
    rule_id = Column(String(64), nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score = Column(Float, default=0.0)
    description = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)

    job = relationship("AnalysisJob", back_populates="findings")


class MLMetricLog(Base):
    __tablename__ = "ml_metric_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    evaluation_date = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    model_name = Column(String(64), nullable=False)
    accuracy = Column(Float, default=0.0)
    precision_score = Column(Float, default=0.0)
    recall_score = Column(Float, default=0.0)
    f1_score = Column(Float, default=0.0)
    confusion_matrix_json = Column(JSON, nullable=True)
    total_samples = Column(Integer, default=0)
    anomaly_rate = Column(Float, default=0.0)
