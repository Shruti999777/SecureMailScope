"""
SecureMailScope - X.509 Certificate Chain-of-Trust Unit Tests
"""

import pytest
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from app.core.cert_analyzer import CertificateDissector, CertChainValidator, CertChainStatus
from app.config import settings


def load_cert_file(filename: str):
    p = settings.CA_STORE_DIR / filename
    if not p.exists():
        pytest.skip(f"Test cert file {filename} not generated yet.")
    return x509.load_der_x509_certificate(p.read_bytes(), default_backend())


def test_valid_leaf_certificate_dissection():
    leaf = load_cert_file("server_valid.der")
    info = CertificateDissector.dissect_cert(leaf, host_to_match="mail.securemail.org")
    assert info["subject_cn"] == "mail.securemail.org"
    assert info["is_expired"] is False
    assert info["key_size"] == 2048
    assert info["host_match"] is True


def test_expired_certificate_detection():
    expired = load_cert_file("server_expired.der")
    info = CertificateDissector.dissect_cert(expired)
    assert info["is_expired"] is True
    assert info["days_to_expiry"] < 0


def test_self_signed_certificate_detection():
    self_signed = load_cert_file("server_self_signed.der")
    info = CertificateDissector.dissect_cert(self_signed)
    assert info["is_self_signed"] is True


def test_full_chain_validation_success():
    leaf = load_cert_file("server_valid.der")
    inter = load_cert_file("intermediate_ca.der")
    root = load_cert_file("root_ca.der")

    validator = CertChainValidator(trusted_roots=[root])
    result = validator.validate_chain([leaf, inter, root])

    assert result["is_valid"] is True
    assert result["status"] == CertChainStatus.VALID
    assert result["chain_length"] == 3
    assert result["root_trusted"] is True


def test_broken_chain_signature_mismatch():
    leaf = load_cert_file("server_valid.der")
    root = load_cert_file("root_ca.der")

    validator = CertChainValidator(trusted_roots=[root])
    # Skipping intermediate CA creates signature mismatch
    result = validator.validate_chain([leaf, root])

    assert result["is_valid"] is False
    assert result["status"] == CertChainStatus.BROKEN_CHAIN
