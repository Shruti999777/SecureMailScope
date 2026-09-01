"""
SecureMailScope - Upload API Endpoint
"""

from fastapi import APIRouter, UploadFile, File, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import AnalysisJob
from app.schemas import UploadResponse
from app.core.security_hardening import SecurityHardening
from app.core.worker import run_analysis_job

router = APIRouter(prefix="/api", tags=["Upload"])


@router.post("/upload", response_model=UploadResponse)
async def upload_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Hardened PCAP upload endpoint:
    - Validates file extension (.pcap, .pcapng, .cap)
    - Validates magic bytes against PCAP signatures
    - Limits file size to 100MB
    - Enqueues asynchronous analysis background task
    """
    job_id, saved_path = await SecurityHardening.validate_and_save_upload(file)
    
    # Create DB entry
    file_size = saved_path.stat().st_size if saved_path.exists() else 0
    job = AnalysisJob(
        id=job_id,
        filename=file.filename or "upload.pcap",
        file_size_bytes=file_size,
        status="queued",
        progress=0,
        current_step="Queued for analysis"
    )
    db.add(job)
    db.commit()

    # Enqueue background processing
    background_tasks.add_task(run_analysis_job, job_id, saved_path)

    return UploadResponse(
        analysis_id=job_id,
        filename=file.filename or "upload.pcap",
        status="queued",
        message="PCAP uploaded successfully. Cryptographic analysis started."
    )
