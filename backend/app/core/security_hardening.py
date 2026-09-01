"""
SecureMailScope - Security Hardening & Upload Sanitization Module
Protects backend against malicious uploads, path traversal, resource exhaustion, and invalid file formats.
"""

import os
import re
import uuid
import shutil
from pathlib import Path
from typing import Tuple
from fastapi import UploadFile, HTTPException

from app.config import settings


# Recognized PCAP/PCAPNG Magic Bytes
PCAP_MAGIC_BYTES = [
    b"\xa1\xb2\xc3\xd4",  # Standard PCAP (microsecond, identical endian)
    b"\xd4\xc3\xb2\xa1",  # Standard PCAP (microsecond, swapped endian)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond PCAP (identical endian)
    b"\x4d\x3c\xb2\xa1",  # Nanosecond PCAP (swapped endian)
    b"\x0a\x0d\x0d\x0a",  # PCAPNG Section Header Block
]


class SecurityHardening:
    """Hardened file validation and temporary workspace isolation."""

    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """Removes dangerous characters and path traversal sequences."""
        basename = os.path.basename(filename)
        # Keep only alphanumeric, dots, underscores, dashes
        cleaned = re.sub(r"[^a-zA-Z0-9._-]", "_", basename)
        return cleaned or "capture.pcap"

    @classmethod
    async def validate_and_save_upload(
        cls,
        upload_file: UploadFile
    ) -> Tuple[str, Path]:
        """
        Performs thorough validation:
        1. Checks extension against whitelist
        2. Validates magic bytes against known PCAP/PCAPNG signatures
        3. Enforces file size limits
        4. Saves into an isolated UUID subdirectory
        """
        orig_name = upload_file.filename or "upload.pcap"
        sanitized_name = cls.sanitize_filename(orig_name)
        
        # 1. Extension validation
        ext = os.path.splitext(sanitized_name)[1].lower()
        if ext not in settings.ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid file extension '{ext}'. Allowed: {', '.join(settings.ALLOWED_EXTENSIONS)}"
            )

        # 2. Magic byte check
        header = await upload_file.read(4)
        await upload_file.seek(0)

        is_valid_magic = any(header.startswith(magic) for magic in PCAP_MAGIC_BYTES)
        if not is_valid_magic:
            raise HTTPException(
                status_code=400,
                detail="File rejected: Content header does not match valid PCAP or PCAPNG magic bytes."
            )

        # 3. Create isolated UUID analysis directory
        job_id = f"job-{uuid.uuid4().hex[:10]}"
        job_dir = settings.UPLOAD_DIR / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        dest_path = job_dir / sanitized_name

        # 4. Stream copy with size limit
        max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
        bytes_written = 0

        with open(dest_path, "wb") as buffer:
            while chunk := await upload_file.read(1024 * 1024):  # 1MB chunks
                bytes_written += len(chunk)
                if bytes_written > max_bytes:
                    # Clean up
                    buffer.close()
                    shutil.rmtree(job_dir, ignore_errors=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB} MB."
                    )
                buffer.write(chunk)

        return job_id, dest_path

    @classmethod
    def cleanup_workspace(cls, job_id: str):
        """Safely removes temporary files for an analysis job."""
        job_dir = settings.UPLOAD_DIR / job_id
        if job_dir.exists():
            try:
                shutil.rmtree(job_dir, ignore_errors=True)
            except Exception:
                pass
