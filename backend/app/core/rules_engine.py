"""
SecureMailScope - Deterministic Cryptographic Security Rules Engine
Evaluates ground-truth security rules, CVSS-aligned scores, and actionable remediations.
"""

from typing import List, Dict, Any, Tuple


class RiskLevel:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SECURE = "SECURE"


class SecurityRule:
    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: str,
        cvss_score: float,
        description: str,
        recommendation: str
    ):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.cvss_score = cvss_score
        self.description = description
        self.recommendation = recommendation


RULES = {
    "RULE-SEC-001": SecurityRule(
        rule_id="RULE-SEC-001",
        title="Plaintext Credentials Transmitted Unencrypted",
        severity=RiskLevel.CRITICAL,
        cvss_score=9.8,
        description="Plaintext authentication commands (e.g. AUTH LOGIN, PASS, USER) were observed in an unencrypted TCP stream, exposing passwords to passive wiretapping.",
        recommendation="Enforce mandatory TLS encryption before authentication. Enable 'smtpd_tls_auth_only = yes' in Postfix or 'disable_plaintext_auth = yes' in Dovecot."
    ),
    "RULE-SEC-002": SecurityRule(
        rule_id="RULE-SEC-002",
        title="Deprecated and Insecure TLS Version in Use",
        severity=RiskLevel.HIGH,
        cvss_score=7.5,
        description="The email server accepted connections using deprecated protocol versions (SSL 3.0, TLS 1.0, or TLS 1.1) which are vulnerable to POODLE, BEAST, and cryptographic downgrades.",
        recommendation="Disable SSLv3, TLSv1.0, and TLSv1.1. Configure 'smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1' (minimum TLS 1.2, recommended TLS 1.3)."
    ),
    "RULE-SEC-003": SecurityRule(
        rule_id="RULE-SEC-003",
        title="Weak or Insecure Cipher Suite Negotiated",
        severity=RiskLevel.CRITICAL,
        cvss_score=8.5,
        description="Negotiated cipher suite relies on broken or obsolete primitives (RC4, 3DES, NULL, or EXPORT ciphers), vulnerable to Sweet32 or key recovery attacks.",
        recommendation="Restrict cipher suites to modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305). Set 'smtpd_tls_ciphers = high' and remove 3DES/RC4."
    ),
    "RULE-SEC-004": SecurityRule(
        rule_id="RULE-SEC-004",
        title="Non-Forward Secret Key Exchange (Static RSA)",
        severity=RiskLevel.MEDIUM,
        cvss_score=5.9,
        description="Session negotiated static RSA key exchange without Ephemeral Diffie-Hellman (ECDHE/DHE). If the server's private key is compromised in the future, past recorded traffic can be decrypted.",
        recommendation="Require Ephemeral Diffie-Hellman (ECDHE) for all TLS handshakes to ensure Perfect Forward Secrecy (PFS)."
    ),
    "RULE-SEC-005": SecurityRule(
        rule_id="RULE-SEC-005",
        title="Expired or Not-Yet-Valid X.509 Certificate",
        severity=RiskLevel.HIGH,
        cvss_score=7.4,
        description="The presented server certificate has passed its expiration date or is not yet valid, causing TLS clients to abort or ignore authentication.",
        recommendation="Renew the X.509 certificate immediately and implement automated certificate lifecycle management (e.g. ACME / Let's Encrypt / certbot)."
    ),
    "RULE-SEC-006": SecurityRule(
        rule_id="RULE-SEC-006",
        title="Untrusted or Broken X.509 Certificate Chain",
        severity=RiskLevel.HIGH,
        cvss_score=7.5,
        description="The certificate chain is incomplete, self-signed, or contains signature verification failures against standard root authorities, making it vulnerable to Man-in-the-Middle (MitM) attacks.",
        recommendation="Install the complete intermediate CA chain bundle on the server and use certificates issued by a trusted public or enterprise PKI Root CA."
    ),
    "RULE-SEC-007": SecurityRule(
        rule_id="RULE-SEC-007",
        title="Weak Public Key Length (< 2048 bits)",
        severity=RiskLevel.HIGH,
        cvss_score=7.3,
        description="The certificate public key size (e.g. RSA 1024 bits) is below the minimum recommended cryptographic security threshold and susceptible to factorization attacks.",
        recommendation="Reissue certificates with at least 2048-bit RSA keys (preferably RSA 3072/4096-bit or NIST P-256 / P-384 ECDSA keys)."
    ),
    "RULE-SEC-008": SecurityRule(
        rule_id="RULE-SEC-008",
        title="Weak Certificate Signature Algorithm (MD5/SHA-1)",
        severity=RiskLevel.HIGH,
        cvss_score=7.1,
        description="The certificate or intermediate CA is signed with a collision-compromised hash function (MD5 or SHA-1).",
        recommendation="Reissue certificates signed using SHA-256 or SHA-384 signature algorithms."
    ),
    "RULE-SEC-009": SecurityRule(
        rule_id="RULE-SEC-009",
        title="Unencrypted Email Transmission (No TLS/STARTTLS)",
        severity=RiskLevel.HIGH,
        cvss_score=7.5,
        description="Email traffic was transmitted completely in cleartext without TLS encryption or STARTTLS negotiation.",
        recommendation="Configure mandatory STARTTLS for submission and MTA hops ('smtpd_tls_security_level = encrypt' or 'may' with MTA-STS/DANE enforcement)."
    ),
    "RULE-SEC-010": SecurityRule(
        rule_id="RULE-SEC-010",
        title="STARTTLS Offered But Downgraded or Stripped",
        severity=RiskLevel.CRITICAL,
        cvss_score=8.8,
        description="STARTTLS capability was advertised by the server or requested by the client, but the session continued in plaintext without completing the cryptographic handshake (indicative of STRIPTLS active tampering).",
        recommendation="Enforce strict STARTTLS requirement, deploy MTA-STS (RFC 8461) and DANE TLSA (RFC 7672) to prevent downgrade attacks."
    ),
}


class RulesEngine:
    """Evaluates security rules for email sessions and calculates security posture."""

    def evaluate_session(self, session_meta: Dict[str, Any]) -> Dict[str, Any]:
        findings = []
        stream_id = session_meta.get("stream_id", "unknown")
        proto = session_meta.get("protocol", "UNKNOWN")
        tls_ver = session_meta.get("tls_version", "None")
        cipher = session_meta.get("cipher_suite", "Unknown")
        cipher_strength = session_meta.get("cipher_strength", "UNKNOWN")
        fs = session_meta.get("forward_secrecy", False)
        kex = session_meta.get("key_exchange", "Unknown")
        cert_chain = session_meta.get("certificate_chain", {})
        leaf = session_meta.get("leaf_certificate")
        is_implicit = session_meta.get("is_implicit_tls", False)
        starttls_upgraded = session_meta.get("starttls_upgraded", False)
        starttls_offered = session_meta.get("starttls_offered", False)
        starttls_requested = session_meta.get("starttls_requested", False)
        has_creds = session_meta.get("has_plaintext_credentials", False)

        def add_finding(rule_id: str, extra_detail: str = ""):
            rule = RULES[rule_id]
            desc = rule.description
            if extra_detail:
                desc += f" [Details: {extra_detail}]"
            findings.append({
                "rule_id": rule.rule_id,
                "title": rule.title,
                "severity": rule.severity,
                "cvss_score": rule.cvss_score,
                "description": desc,
                "recommendation": rule.recommendation,
                "stream_id": stream_id,
                "protocol": proto
            })

        # 1. Plaintext credentials
        if has_creds:
            add_finding("RULE-SEC-001", "Detected plaintext authentication commands in cleartext stream.")

        # 2. Plaintext session without STARTTLS or implicit TLS
        is_encrypted = is_implicit or starttls_upgraded or (tls_ver not in ("None", None))
        if not is_encrypted:
            if starttls_offered and not starttls_upgraded:
                add_finding("RULE-SEC-010", "STARTTLS offered in banner but connection proceeded in cleartext.")
            else:
                add_finding("RULE-SEC-009", f"Plaintext {proto} session with no TLS encryption.")
        else:
            # 3. TLS Protocol version checks
            if tls_ver in ("SSL 3.0", "0x0300"):
                add_finding("RULE-SEC-002", f"SSL 3.0 negotiated.")
            elif tls_ver in ("TLS 1.0", "0x0301"):
                add_finding("RULE-SEC-002", f"TLS 1.0 negotiated.")
            elif tls_ver in ("TLS 1.1", "0x0302"):
                add_finding("RULE-SEC-002", f"TLS 1.1 negotiated.")

            # 4. Cipher suite checks
            if cipher_strength == "CRITICAL" or any(w in cipher.upper() for w in ["RC4", "NULL", "EXPORT"]):
                add_finding("RULE-SEC-003", f"Broken cipher suite '{cipher}' negotiated.")
            elif cipher_strength == "INSECURE" or "3DES" in cipher.upper():
                add_finding("RULE-SEC-003", f"Deprecated cipher '{cipher}' (Sweet32 vulnerable) negotiated.")

            # 5. Forward Secrecy & Key Exchange
            if tls_ver in ("TLS 1.2", "TLS 1.1", "TLS 1.0") and not fs:
                if kex == "RSA_STATIC" or "RSA_WITH" in cipher:
                    add_finding("RULE-SEC-004", f"Static RSA key exchange negotiated (Cipher: {cipher}).")

            # 6. Certificate & Chain-of-Trust checks
            if leaf:
                if leaf.get("is_expired"):
                    add_finding("RULE-SEC-005", f"Certificate expired on {leaf.get('not_after')}.")
                if leaf.get("is_not_yet_valid"):
                    add_finding("RULE-SEC-005", f"Certificate not valid until {leaf.get('not_before')}.")
                if leaf.get("is_weak_key"):
                    add_finding("RULE-SEC-007", f"Weak key size: {leaf.get('key_type')} {leaf.get('key_size')} bits.")
                if leaf.get("is_weak_signature"):
                    add_finding("RULE-SEC-008", f"Weak signature hash: {leaf.get('signature_algorithm')}.")
                if cert_chain.get("status") in ("SELF_SIGNED", "UNTRUSTED_ROOT", "BROKEN_CHAIN", "INCOMPLETE_CHAIN"):
                    add_finding("RULE-SEC-006", f"Chain status: {cert_chain.get('status')}. Errors: {', '.join(cert_chain.get('errors', []))}")

        # Compute Session Risk Level & Score
        if any(f["severity"] == RiskLevel.CRITICAL for f in findings):
            risk_level = RiskLevel.CRITICAL
            risk_score = 90
        elif any(f["severity"] == RiskLevel.HIGH for f in findings):
            risk_level = RiskLevel.HIGH
            risk_score = 70
        elif any(f["severity"] == RiskLevel.MEDIUM for f in findings):
            risk_level = RiskLevel.MEDIUM
            risk_score = 45
        elif any(f["severity"] == RiskLevel.LOW for f in findings):
            risk_level = RiskLevel.LOW
            risk_score = 20
        else:
            risk_level = RiskLevel.SECURE
            risk_score = 5

        return {
            "findings": findings,
            "risk_level": risk_level,
            "risk_score": risk_score
        }

    def calculate_overall_posture(
        self,
        sessions: List[Dict[str, Any]],
        all_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculates global posture score (0-100), distributions, and summary."""
        total = len(sessions)
        if total == 0:
            return {
                "overall_score": 100,
                "overall_risk_level": RiskLevel.SECURE,
                "protocol_counts": {},
                "tls_version_counts": {},
                "cipher_counts": {},
                "findings_summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "security_grade": "A+",
                "recommendation_summary": "No active sessions detected."
            }

        crit_count = sum(1 for f in all_findings if f["severity"] == RiskLevel.CRITICAL)
        high_count = sum(1 for f in all_findings if f["severity"] == RiskLevel.HIGH)
        med_count = sum(1 for f in all_findings if f["severity"] == RiskLevel.MEDIUM)
        low_count = sum(1 for f in all_findings if f["severity"] == RiskLevel.LOW)

        # Baseline score = 100. Deduct based on findings
        penalty = (crit_count * 25) + (high_count * 15) + (med_count * 5) + (low_count * 2)
        overall_score = max(0, min(100, 100 - penalty))

        if crit_count > 0 or overall_score < 40:
            overall_risk = RiskLevel.CRITICAL
            grade = "F"
        elif high_count > 0 or overall_score < 65:
            overall_risk = RiskLevel.HIGH
            grade = "D"
        elif med_count > 0 or overall_score < 80:
            overall_risk = RiskLevel.MEDIUM
            grade = "C"
        elif low_count > 0 or overall_score < 95:
            overall_risk = RiskLevel.LOW
            grade = "B"
        else:
            overall_risk = RiskLevel.SECURE
            grade = "A+"

        # Aggregate distributions
        proto_counts = {}
        tls_counts = {}
        cipher_counts = {}

        for s in sessions:
            p = s.get("protocol", "UNKNOWN")
            proto_counts[p] = proto_counts.get(p, 0) + 1
            
            t = s.get("tls_version", "None") or "None"
            tls_counts[t] = tls_counts.get(t, 0) + 1
            
            c = s.get("cipher_suite", "Unknown") or "Unknown"
            cipher_counts[c] = cipher_counts.get(c, 0) + 1

        return {
            "overall_score": overall_score,
            "overall_risk_level": overall_risk,
            "security_grade": grade,
            "total_sessions": total,
            "total_findings": len(all_findings),
            "findings_summary": {
                "CRITICAL": crit_count,
                "HIGH": high_count,
                "MEDIUM": med_count,
                "LOW": low_count
            },
            "protocol_counts": proto_counts,
            "tls_version_counts": tls_counts,
            "cipher_counts": cipher_counts,
            "forward_secrecy_ratio": round(sum(1 for s in sessions if s.get("forward_secrecy")) / total, 2) if total else 0.0,
        }
