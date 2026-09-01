"""
SecureMailScope - Deterministic Security Rules Engine Unit Tests
"""

import pytest
from app.core.rules_engine import RulesEngine, RiskLevel


def test_plaintext_credentials_finding():
    engine = RulesEngine()
    session = {
        "stream_id": "stream-001",
        "protocol": "IMAP",
        "has_plaintext_credentials": True,
        "is_implicit_tls": False,
        "starttls_upgraded": False,
        "tls_version": "None"
    }
    result = engine.evaluate_session(session)
    assert result["risk_level"] == RiskLevel.CRITICAL
    assert any(f["rule_id"] == "RULE-SEC-001" for f in result["findings"])


def test_deprecated_tls10_finding():
    engine = RulesEngine()
    session = {
        "stream_id": "stream-002",
        "protocol": "SMTPS",
        "is_implicit_tls": True,
        "tls_version": "TLS 1.0",
        "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "cipher_strength": "MEDIUM",
        "forward_secrecy": False,
        "key_exchange": "RSA_STATIC",
    }
    result = engine.evaluate_session(session)
    assert result["risk_level"] in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert any(f["rule_id"] == "RULE-SEC-002" for f in result["findings"])


def test_secure_tls13_session():
    engine = RulesEngine()
    session = {
        "stream_id": "stream-003",
        "protocol": "SMTPS",
        "is_implicit_tls": True,
        "tls_version": "TLS 1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "cipher_strength": "SECURE",
        "forward_secrecy": True,
        "key_exchange": "ECDHE",
        "certificate_chain": {"status": "VALID_CHAIN", "is_valid": True},
        "leaf_certificate": {"is_expired": False, "is_weak_key": False, "is_weak_signature": False}
    }
    result = engine.evaluate_session(session)
    assert result["risk_level"] == RiskLevel.SECURE
    assert len(result["findings"]) == 0
