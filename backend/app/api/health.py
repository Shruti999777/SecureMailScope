"""
SecureMailScope - Health & Status Endpoint
"""

import os
from fastapi import APIRouter
from app.config import settings

router = APIRouter(tags=["Health"])


@router.get("/api/health")
def health_check():
    """Returns application health and environment capabilities."""
    sample_files = [f.name for f in settings.SAMPLES_DIR.glob("*.pcap*")]
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "database": "connected",
        "sample_pcaps_available": len(sample_files),
        "sample_files": sample_files,
        "upload_limits": {
            "max_size_mb": settings.MAX_UPLOAD_SIZE_MB,
            "allowed_extensions": list(settings.ALLOWED_EXTENSIONS)
        }
    }
