"""
SecureMailScope - Asynchronous Background Job Processor
Orchestrates the analysis pipeline, updates progress, and saves findings into SQLite/PostgreSQL.
"""

import datetime
from pathlib import Path
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import AnalysisJob, EmailSession, CertificateRecord, SecurityFinding
from app.core.pcap_analyzer import PCAPAnalyzer
from app.core.security_hardening import SecurityHardening


def run_analysis_job(job_id: str, pcap_path: Path):
    """Executes full PCAP inspection in background thread."""
    db: Session = SessionLocal()
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        db.close()
        return

    def update_progress(percent: int, step_desc: str):
        try:
            job.progress = percent
            job.current_step = step_desc
            db.commit()
        except Exception:
            db.rollback()

    try:
        job.status = "processing"
        job.progress = 5
        job.current_step = "Starting capture parsing"
        db.commit()

        analyzer = PCAPAnalyzer()
        results = analyzer.analyze_pcap(
            pcap_path=str(pcap_path),
            progress_callback=update_progress
        )

        assessment = results["assessment"]
        sessions = results["sessions"]
        findings = results["findings"]
        certs = results["certificates"]
        ml_summary = results["ml_summary"]

        # Persist Sessions
        for s in sessions:
            sess_obj = EmailSession(
                analysis_id=job_id,
                stream_id=s.get("stream_id", "stream-0"),
                protocol=s.get("protocol", "UNKNOWN"),
                is_implicit_tls=s.get("is_implicit_tls", False),
                starttls_offered=s.get("starttls_offered", False),
                starttls_upgraded=s.get("starttls_upgraded", False),
                client_ip=s.get("client_ip", "0.0.0.0"),
                server_ip=s.get("server_ip", "0.0.0.0"),
                client_port=s.get("client_port", 0),
                server_port=s.get("server_port", 0),
                packet_count=s.get("packet_count", 0),
                byte_count=s.get("byte_count", 0),
                duration=s.get("duration", 0.0),
                tls_version=s.get("tls_version", "None"),
                cipher_suite=s.get("cipher_suite", "Unknown"),
                key_exchange=s.get("key_exchange", "Unknown"),
                forward_secrecy=s.get("forward_secrecy", False),
                cipher_strength=s.get("cipher_strength", "UNKNOWN"),
                sni=s.get("sni"),
                risk_level=s.get("risk_level", "SECURE"),
                risk_score=s.get("risk_score", 0),
                rf_predicted_risk=s.get("rf_predicted_risk", "UNKNOWN"),
                rf_confidence=s.get("rf_confidence", 0.0),
                is_anomalous=s.get("is_anomalous", False),
                anomaly_score=s.get("anomaly_score", 0.0),
            )
            db.add(sess_obj)

        # Persist Findings
        for f in findings:
            find_obj = SecurityFinding(
                analysis_id=job_id,
                stream_id=f.get("stream_id", "stream-0"),
                protocol=f.get("protocol", "UNKNOWN"),
                rule_id=f.get("rule_id", "RULE-000"),
                title=f.get("title", "Finding"),
                severity=f.get("severity", "LOW"),
                cvss_score=f.get("cvss_score", 0.0),
                description=f.get("description", ""),
                recommendation=f.get("recommendation", "")
            )
            db.add(find_obj)

        # Persist Certificates
        for c in certs:
            cert_obj = CertificateRecord(
                analysis_id=job_id,
                stream_id=c.get("session_id", "stream-0"),
                subject_cn=c.get("subject_cn"),
                subject_org=c.get("subject_org"),
                issuer_cn=c.get("issuer_cn"),
                issuer_org=c.get("issuer_org"),
                serial_number=c.get("serial_number"),
                not_before=c.get("not_before"),
                not_after=c.get("not_after"),
                is_expired=c.get("is_expired", False),
                days_to_expiry=c.get("days_to_expiry", 0),
                key_type=c.get("key_type", "Unknown"),
                key_size=c.get("key_size", 0),
                is_weak_key=c.get("is_weak_key", False),
                signature_algorithm=c.get("signature_algorithm", "Unknown"),
                is_weak_signature=c.get("is_weak_signature", False),
                chain_length=len(c.get("chain_hierarchy", [])) or 1,
                chain_status=c.get("chain_status", "VALID_CHAIN"),
                chain_valid=c.get("chain_valid", True),
                is_self_signed=c.get("is_self_signed", False),
                hierarchy_json=c.get("chain_hierarchy")
            )
            db.add(cert_obj)

        # Update Job summary
        job.status = "completed"
        job.progress = 100
        job.current_step = "Analysis completed successfully"
        job.overall_score = assessment.get("overall_score", 100)
        job.overall_risk_level = assessment.get("overall_risk_level", "SECURE")
        job.security_grade = assessment.get("security_grade", "A+")
        job.total_sessions = len(sessions)
        job.total_findings = len(findings)
        job.completed_at = datetime.datetime.now(datetime.timezone.utc)
        job.summary_data = {
            "assessment": assessment,
            "ml_summary": ml_summary
        }

        db.commit()

    except Exception as e:
        db.rollback()
        job.status = "failed"
        job.progress = 100
        job.current_step = "Failed with error"
        job.error_message = str(e)
        db.commit()
    finally:
        db.close()
        # Clean up temporary uploaded PCAP file
        SecurityHardening.cleanup_workspace(job_id)
