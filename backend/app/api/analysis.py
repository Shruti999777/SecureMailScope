"""
SecureMailScope - Analysis & Query API Endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import AnalysisJob, EmailSession, SecurityFinding, CertificateRecord
from app.schemas import (
    AnalysisDetailResponse, SessionResponse, FindingResponse, CertificateResponse
)

router = APIRouter(prefix="/api", tags=["Analysis"])


@router.get("/analyses", response_model=List[AnalysisDetailResponse])
def list_analyses(limit: int = 50, db: Session = Depends(get_db)):
    """Lists all past analysis jobs."""
    jobs = db.query(AnalysisJob).order_by(AnalysisJob.created_at.desc()).limit(limit).all()
    results = []
    for j in jobs:
        results.append(AnalysisDetailResponse(
            analysis_id=j.id,
            filename=j.filename,
            status=j.status,
            progress=j.progress,
            current_step=j.current_step,
            overall_score=j.overall_score,
            overall_risk_level=j.overall_risk_level,
            security_grade=j.security_grade,
            total_sessions=j.total_sessions,
            total_findings=j.total_findings,
            created_at=j.created_at,
            completed_at=j.completed_at,
            error_message=j.error_message,
            summary=j.summary_data.get("assessment") if j.summary_data else None,
            ml_summary=j.summary_data.get("ml_summary") if j.summary_data else None
        ))
    return results


@router.get("/analysis/{job_id}", response_model=AnalysisDetailResponse)
def get_analysis_detail(job_id: str, db: Session = Depends(get_db)):
    """Retrieves high-level summary and real-time status of an analysis job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found.")
    
    return AnalysisDetailResponse(
        analysis_id=job.id,
        filename=job.filename,
        status=job.status,
        progress=job.progress,
        current_step=job.current_step,
        overall_score=job.overall_score,
        overall_risk_level=job.overall_risk_level,
        security_grade=job.security_grade,
        total_sessions=job.total_sessions,
        total_findings=job.total_findings,
        created_at=job.created_at,
        completed_at=job.completed_at,
        error_message=job.error_message,
        summary=job.summary_data.get("assessment") if job.summary_data else None,
        ml_summary=job.summary_data.get("ml_summary") if job.summary_data else None
    )


@router.get("/analysis/{job_id}/sessions", response_model=List[SessionResponse])
def get_analysis_sessions(
    job_id: str,
    protocol: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    anomalous_only: bool = Query(False),
    db: Session = Depends(get_db)
):
    """Retrieves detailed email session streams with optional filters."""
    query = db.query(EmailSession).filter(EmailSession.analysis_id == job_id)
    if protocol:
        query = query.filter(EmailSession.protocol == protocol)
    if risk_level:
        query = query.filter(EmailSession.risk_level == risk_level)
    if anomalous_only:
        query = query.filter(EmailSession.is_anomalous == True)

    sessions = query.all()
    return [
        SessionResponse(
            stream_id=s.stream_id,
            protocol=s.protocol,
            is_implicit_tls=s.is_implicit_tls,
            starttls_offered=s.starttls_offered,
            starttls_upgraded=s.starttls_upgraded,
            client_ip=s.client_ip,
            server_ip=s.server_ip,
            client_port=s.client_port,
            server_port=s.server_port,
            packet_count=s.packet_count,
            byte_count=s.byte_count,
            duration=s.duration,
            tls_version=s.tls_version,
            cipher_suite=s.cipher_suite,
            key_exchange=s.key_exchange,
            forward_secrecy=s.forward_secrecy,
            cipher_strength=s.cipher_strength,
            sni=s.sni,
            risk_level=s.risk_level,
            risk_score=s.risk_score,
            rf_predicted_risk=s.rf_predicted_risk,
            rf_confidence=s.rf_confidence,
            is_anomalous=s.is_anomalous,
            anomaly_score=s.anomaly_score,
        )
        for s in sessions
    ]


@router.get("/analysis/{job_id}/findings", response_model=List[FindingResponse])
def get_analysis_findings(
    job_id: str,
    severity: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Retrieves categorized security vulnerability findings."""
    query = db.query(SecurityFinding).filter(SecurityFinding.analysis_id == job_id)
    if severity:
        query = query.filter(SecurityFinding.severity == severity)
    
    findings = query.all()
    return [
        FindingResponse(
            id=f.id,
            stream_id=f.stream_id,
            protocol=f.protocol,
            rule_id=f.rule_id,
            title=f.title,
            severity=f.severity,
            cvss_score=f.cvss_score,
            description=f.description,
            recommendation=f.recommendation
        )
        for f in findings
    ]


@router.get("/analysis/{job_id}/certificates", response_model=List[CertificateResponse])
def get_analysis_certificates(job_id: str, db: Session = Depends(get_db)):
    """Retrieves X.509 certificates and Chain-of-Trust hierarchy."""
    certs = db.query(CertificateRecord).filter(CertificateRecord.analysis_id == job_id).all()
    return [
        CertificateResponse(
            stream_id=c.stream_id,
            subject_cn=c.subject_cn,
            subject_org=c.subject_org,
            issuer_cn=c.issuer_cn,
            issuer_org=c.issuer_org,
            serial_number=c.serial_number,
            not_before=c.not_before,
            not_after=c.not_after,
            is_expired=c.is_expired,
            days_to_expiry=c.days_to_expiry,
            key_type=c.key_type,
            key_size=c.key_size,
            is_weak_key=c.is_weak_key,
            signature_algorithm=c.signature_algorithm,
            is_weak_signature=c.is_weak_signature,
            chain_length=c.chain_length,
            chain_status=c.chain_status,
            chain_valid=c.chain_valid,
            is_self_signed=c.is_self_signed,
            hierarchy_json=c.hierarchy_json
        )
        for c in certs
    ]


@router.get("/analysis/{job_id}/risk")
def get_analysis_risk_breakdown(job_id: str, db: Session = Depends(get_db)):
    """Retrieves comparative risk intelligence (Deterministic Rules vs RF Classifier vs Isolation Forest)."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found.")
    
    sessions = db.query(EmailSession).filter(EmailSession.analysis_id == job_id).all()
    findings = db.query(SecurityFinding).filter(SecurityFinding.analysis_id == job_id).all()

    rule_risk_dist = {}
    rf_risk_dist = {}
    anomalous_count = 0

    for s in sessions:
        rule_risk_dist[s.risk_level] = rule_risk_dist.get(s.risk_level, 0) + 1
        rf_risk_dist[s.rf_predicted_risk] = rf_risk_dist.get(s.rf_predicted_risk, 0) + 1
        if s.is_anomalous:
            anomalous_count += 1

    return {
        "analysis_id": job_id,
        "overall_score": job.overall_score,
        "overall_risk_level": job.overall_risk_level,
        "security_grade": job.security_grade,
        "total_sessions": len(sessions),
        "total_findings": len(findings),
        "rule_risk_distribution": rule_risk_dist,
        "rf_risk_distribution": rf_risk_dist,
        "isolation_forest_anomalies": {
            "total_anomalous": anomalous_count,
            "anomaly_rate": round(anomalous_count / len(sessions), 4) if sessions else 0.0
        },
        "deterministic_override_principle": "Security Ground Truth is established by deterministic cryptographic rules. ML assists in anomaly detection and posture classification."
    }


@router.delete("/analysis/{job_id}")
def delete_analysis(job_id: str, db: Session = Depends(get_db)):
    """Deletes an analysis job and its associated records."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found.")
    db.delete(job)
    db.commit()
    return {"message": f"Analysis job '{job_id}' deleted successfully."}
