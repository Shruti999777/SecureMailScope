"""
SecureMailScope - Pydantic Request & Response Schemas
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import datetime


class UploadResponse(BaseModel):
    analysis_id: str
    filename: str
    status: str
    message: str


class FindingResponse(BaseModel):
    id: Optional[int] = None
    stream_id: str
    protocol: str
    rule_id: str
    title: str
    severity: str
    cvss_score: float
    description: str
    recommendation: str


class CertificateResponse(BaseModel):
    stream_id: str
    subject_cn: Optional[str] = None
    subject_org: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    serial_number: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    is_expired: bool
    days_to_expiry: int
    key_type: str
    key_size: int
    is_weak_key: bool
    signature_algorithm: str
    is_weak_signature: bool
    chain_length: int
    chain_status: str
    chain_valid: bool
    is_self_signed: bool
    hierarchy_json: Optional[List[Dict[str, Any]]] = None


class SessionResponse(BaseModel):
    stream_id: str
    protocol: str
    is_implicit_tls: bool
    starttls_offered: bool
    starttls_upgraded: bool
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    packet_count: int
    byte_count: int
    duration: float
    tls_version: str
    cipher_suite: str
    key_exchange: str
    forward_secrecy: bool
    cipher_strength: str
    sni: Optional[str] = None
    risk_level: str
    risk_score: int
    rf_predicted_risk: str
    rf_confidence: float
    is_anomalous: bool
    anomaly_score: float


class AssessmentSummary(BaseModel):
    overall_score: int
    overall_risk_level: str
    security_grade: str
    total_sessions: int
    total_findings: int
    findings_summary: Dict[str, int]
    protocol_counts: Dict[str, int]
    tls_version_counts: Dict[str, int]
    cipher_counts: Dict[str, int]
    forward_secrecy_ratio: float


class AnalysisDetailResponse(BaseModel):
    analysis_id: str
    filename: str
    status: str
    progress: int
    current_step: str
    overall_score: Optional[int] = None
    overall_risk_level: Optional[str] = None
    security_grade: Optional[str] = None
    total_sessions: int = 0
    total_findings: int = 0
    created_at: Optional[datetime.datetime] = None
    completed_at: Optional[datetime.datetime] = None
    error_message: Optional[str] = None
    summary: Optional[Dict[str, Any]] = None
    ml_summary: Optional[Dict[str, Any]] = None


class MLMetricsResponse(BaseModel):
    model_name: str
    accuracy: float
    precision_score: float
    recall_score: float
    f1_score: float
    confusion_matrix: Dict[str, Any]
    anomaly_rate: float
    total_samples: int
    evaluation_date: str
