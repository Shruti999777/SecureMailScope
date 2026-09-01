"""
SecureMailScope - Export API Endpoints (PDF, HTML, JSON)
"""

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import AnalysisJob, EmailSession, SecurityFinding, CertificateRecord
from app.reports.pdf_generator import PDFReportGenerator
from app.reports.html_generator import HTMLReportGenerator
from app.reports.json_generator import JSONReportGenerator

router = APIRouter(prefix="/api/analysis", tags=["Export"])


def _fetch_full_job_data(job_id: str, db: Session):
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found.")

    sessions = [
        {
            "stream_id": s.stream_id,
            "protocol": s.protocol,
            "is_implicit_tls": s.is_implicit_tls,
            "starttls_offered": s.starttls_offered,
            "starttls_upgraded": s.starttls_upgraded,
            "client_ip": s.client_ip,
            "server_ip": s.server_ip,
            "client_port": s.client_port,
            "server_port": s.server_port,
            "packet_count": s.packet_count,
            "byte_count": s.byte_count,
            "duration": s.duration,
            "tls_version": s.tls_version,
            "cipher_suite": s.cipher_suite,
            "key_exchange": s.key_exchange,
            "forward_secrecy": s.forward_secrecy,
            "cipher_strength": s.cipher_strength,
            "sni": s.sni,
            "risk_level": s.risk_level,
            "risk_score": s.risk_score,
            "rf_predicted_risk": s.rf_predicted_risk,
            "rf_confidence": s.rf_confidence,
            "is_anomalous": s.is_anomalous,
            "anomaly_score": s.anomaly_score
        }
        for s in db.query(EmailSession).filter(EmailSession.analysis_id == job_id).all()
    ]

    findings = [
        {
            "id": f.id,
            "stream_id": f.stream_id,
            "protocol": f.protocol,
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "description": f.description,
            "recommendation": f.recommendation
        }
        for f in db.query(SecurityFinding).filter(SecurityFinding.analysis_id == job_id).all()
    ]

    certificates = [
        {
            "stream_id": c.stream_id,
            "subject_cn": c.subject_cn,
            "subject_org": c.subject_org,
            "issuer_cn": c.issuer_cn,
            "issuer_org": c.issuer_org,
            "serial_number": c.serial_number,
            "not_before": c.not_before,
            "not_after": c.not_after,
            "is_expired": c.is_expired,
            "days_to_expiry": c.days_to_expiry,
            "key_type": c.key_type,
            "key_size": c.key_size,
            "is_weak_key": c.is_weak_key,
            "signature_algorithm": c.signature_algorithm,
            "is_weak_signature": c.is_weak_signature,
            "chain_length": c.chain_length,
            "chain_status": c.chain_status,
            "chain_valid": c.chain_valid,
            "is_self_signed": c.is_self_signed,
            "hierarchy_json": c.hierarchy_json
        }
        for c in db.query(CertificateRecord).filter(CertificateRecord.analysis_id == job_id).all()
    ]

    job_dict = {
        "id": job.id,
        "filename": job.filename,
        "overall_score": job.overall_score,
        "overall_risk_level": job.overall_risk_level,
        "security_grade": job.security_grade,
        "created_at": job.created_at,
        "completed_at": job.completed_at,
        "summary_data": job.summary_data,
    }

    return job_dict, sessions, findings, certificates


@router.get("/{job_id}/export/pdf")
def export_pdf(job_id: str, db: Session = Depends(get_db)):
    """Exports an executive cybersecurity audit PDF report."""
    job_dict, sessions, findings, certificates = _fetch_full_job_data(job_id, db)
    pdf_bytes = PDFReportGenerator.generate_report_bytes(job_dict, sessions, findings, certificates)
    
    filename = f"SecureMailScope_Assessment_{job_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/{job_id}/export/html")
def export_html(job_id: str, db: Session = Depends(get_db)):
    """Exports a self-contained responsive HTML audit report."""
    job_dict, sessions, findings, certificates = _fetch_full_job_data(job_id, db)
    html_content = HTMLReportGenerator.generate_report_html(job_dict, sessions, findings, certificates)
    
    filename = f"SecureMailScope_Assessment_{job_id}.html"
    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/{job_id}/export/json")
def export_json(job_id: str, db: Session = Depends(get_db)):
    """Exports structured machine-readable JSON data."""
    job_dict, sessions, findings, certificates = _fetch_full_job_data(job_id, db)
    json_data = JSONReportGenerator.generate_report_dict(job_dict, sessions, findings, certificates)
    return json_data
