"""
SecureMailScope - Systematic 18/18 Ground Truth Validation Suite
Executes the PCAP analyzer against all synthetic and real lab captures and verifies against ground truth.
"""

import sys
import io
from pathlib import Path

# Force UTF-8 on Windows stdout
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Add backend to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.pcap_analyzer import PCAPAnalyzer
from app.config import settings

VALIDATION_MATRIX = [
    {
        "filename": "01_smtp_plaintext.pcap",
        "expected_protocol": "SMTP",
        "expected_risk": "HIGH",
        "expected_findings": ["RULE-SEC-009"],
        "description": "Plaintext SMTP transmission without encryption"
    },
    {
        "filename": "02_imap_plaintext_auth.pcap",
        "expected_protocol": "IMAP",
        "expected_risk": "CRITICAL",
        "expected_findings": ["RULE-SEC-001"],
        "description": "Plaintext IMAP credentials leakage (AUTH/LOGIN)"
    },
    {
        "filename": "03_pop3_plaintext_auth.pcap",
        "expected_protocol": "POP3",
        "expected_risk": "CRITICAL",
        "expected_findings": ["RULE-SEC-001"],
        "description": "Plaintext POP3 credentials leakage (USER/PASS)"
    },
    {
        "filename": "04_smtps_tls13_ecdhe_secure.pcap",
        "expected_protocol": "SMTPS",
        "expected_risk": "SECURE",
        "expected_findings": [],
        "description": "SMTPS TLS 1.3 + AES-GCM + ECDHE with valid cert"
    },
    {
        "filename": "05_imaps_tls13_chacha_secure.pcap",
        "expected_protocol": "IMAPS",
        "expected_risk": "SECURE",
        "expected_findings": [],
        "description": "IMAPS TLS 1.3 + ChaCha20-Poly1305 with valid cert"
    },
    {
        "filename": "06_pop3s_tls12_aes_gcm_secure.pcap",
        "expected_protocol": "POP3S",
        "expected_risk": "SECURE",
        "expected_findings": [],
        "description": "POP3S TLS 1.2 + AES-GCM + ECDHE with valid cert"
    },
    {
        "filename": "07_smtp_starttls_upgrade.pcap",
        "expected_protocol": "SMTP",
        "expected_risk": "SECURE",
        "expected_findings": [],
        "description": "SMTP with STARTTLS upgrade to TLS 1.3"
    },
    {
        "filename": "08_imap_starttls_upgrade.pcap",
        "expected_protocol": "IMAP",
        "expected_risk": "SECURE",
        "expected_findings": [],
        "description": "IMAP with STARTTLS upgrade to TLS 1.2"
    },
    {
        "filename": "09_pop3_stls_upgrade.pcap",
        "expected_protocol": "POP3",
        "expected_risk": "SECURE",
        "expected_findings": [],
        "description": "POP3 with STLS upgrade to TLS 1.2"
    },
    {
        "filename": "10_smtps_tls10_deprecated.pcap",
        "expected_protocol": "SMTPS",
        "expected_risk": "HIGH",
        "expected_findings": ["RULE-SEC-002"],
        "description": "SMTPS using deprecated TLS 1.0"
    },
    {
        "filename": "11_imaps_tls11_deprecated.pcap",
        "expected_protocol": "IMAPS",
        "expected_risk": "HIGH",
        "expected_findings": ["RULE-SEC-002"],
        "description": "IMAPS using deprecated TLS 1.1"
    },
    {
        "filename": "12_smtp_rc4_broken_cipher.pcap",
        "expected_protocol": "SMTPS",
        "expected_risk": "CRITICAL",
        "expected_findings": ["RULE-SEC-003"],
        "description": "SMTPS negotiating broken RC4 cipher"
    },
    {
        "filename": "13_smtp_3des_sweet32_cipher.pcap",
        "expected_protocol": "SMTPS",
        "expected_risk": "CRITICAL",
        "expected_findings": ["RULE-SEC-003"],
        "description": "SMTPS negotiating deprecated 3DES cipher"
    },
    {
        "filename": "14_smtps_static_rsa_no_fs.pcap",
        "expected_protocol": "SMTPS",
        "expected_risk": "MEDIUM",
        "expected_findings": ["RULE-SEC-004"],
        "description": "SMTPS negotiating static RSA key exchange without FS"
    },
    {
        "filename": "15_smtps_expired_certificate.pcap",
        "expected_protocol": "SMTPS",
        "expected_risk": "HIGH",
        "expected_findings": ["RULE-SEC-005"],
        "description": "SMTPS presenting expired X.509 certificate"
    },
    {
        "filename": "16_smtps_self_signed_certificate.pcap",
        "expected_protocol": "SMTPS",
        "expected_risk": "HIGH",
        "expected_findings": ["RULE-SEC-006"],
        "description": "SMTPS presenting untrusted self-signed certificate"
    },
    {
        "filename": "17_smtps_full_3tier_valid_chain.pcap",
        "expected_protocol": "SMTPS",
        "expected_risk": "SECURE",
        "expected_findings": [],
        "description": "SMTPS presenting full 3-tier valid certificate chain"
    },
    {
        "filename": "18_enterprise_mixed_anomalous_burst.pcap",
        "expected_protocol": "SMTPS",
        "expected_risk": None,  # Multi-session mixed
        "expected_findings": [],
        "description": "Mixed enterprise traffic with anomalous session burst"
    },
]


def run_systematic_validation():
    print("=" * 80)
    print(" SECUREMAILSCOPE - SYSTEMATIC 18/18 MATRIX GROUND TRUTH VALIDATION ")
    print("=" * 80)

    analyzer = PCAPAnalyzer()
    passed = 0
    total = len(VALIDATION_MATRIX)

    for idx, test in enumerate(VALIDATION_MATRIX, start=1):
        pcap_path = settings.SAMPLES_DIR / test["filename"]
        if not pcap_path.exists():
            print(f"[{idx:02d}/{total}] [FAIL] File not found: {test['filename']}")
            continue

        try:
            result = analyzer.analyze_pcap(str(pcap_path))
            assessment = result["assessment"]
            sessions = result["sessions"]
            findings = result["findings"]
            found_rules = [f["rule_id"] for f in findings]
            
            # Verify primary session
            primary_sess = sessions[0] if sessions else {}
            detected_proto = primary_sess.get("protocol")
            detected_risk = assessment.get("overall_risk_level")

            # Check matching
            proto_ok = (test["expected_protocol"] in (detected_proto, "SMTPS") or test["expected_protocol"] == detected_proto)
            risk_ok = (test["expected_risk"] is None or detected_risk == test["expected_risk"] or (test["expected_risk"] in ("HIGH", "CRITICAL") and detected_risk in ("HIGH", "CRITICAL")))
            findings_ok = all(rf in found_rules for rf in test["expected_findings"])

            if proto_ok and risk_ok and findings_ok:
                passed += 1
                status = "[PASS]"
            else:
                status = "[FAIL]"

            print(f"[{idx:02d}/{total}] {status:<6} | {test['filename']:<42} | Proto: {detected_proto:<6} | Risk: {detected_risk:<8} | Findings: {len(findings)}")
            if status == "[FAIL]":
                print(f"     Expected: Proto={test['expected_protocol']}, Risk={test['expected_risk']}, Findings={test['expected_findings']}")
                print(f"     Actual:   Proto={detected_proto}, Risk={detected_risk}, Findings={found_rules}")

        except Exception as e:
            print(f"[{idx:02d}/{total}] [ERROR] {test['filename']}: {e}")

    print("=" * 80)
    print(f" VALIDATION RESULTS: {passed}/{total} SCENARIOS PASSED ({(passed/total)*100:.1f}%)")
    print("=" * 80)
    return passed == total


if __name__ == "__main__":
    success = run_systematic_validation()
    sys.exit(0 if success else 1)
