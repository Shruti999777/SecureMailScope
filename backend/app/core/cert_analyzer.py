"""
SecureMailScope - X.509 Certificate & Chain-of-Trust Analyzer
Performs deep certificate dissection and full chain verification:
Leaf (Server) -> Intermediate CA(s) -> Root CA (Trust Anchor).
"""

import datetime
from typing import List, Dict, Any, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519, dsa
from cryptography.x509.oid import ExtensionOID, NameOID


class CertChainStatus:
    VALID = "VALID_CHAIN"
    SELF_SIGNED = "SELF_SIGNED"
    UNTRUSTED_ROOT = "UNTRUSTED_ROOT"
    EXPIRED = "EXPIRED"
    EXPIRED_IN_CHAIN = "EXPIRED_IN_CHAIN"
    NOT_YET_VALID = "NOT_YET_VALID"
    BROKEN_CHAIN = "BROKEN_CHAIN"
    INCOMPLETE_CHAIN = "INCOMPLETE_CHAIN"
    WEAK_KEY_IN_CHAIN = "WEAK_KEY_IN_CHAIN"
    WEAK_SIG_IN_CHAIN = "WEAK_SIG_IN_CHAIN"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


class CertificateDissector:
    """Dissects single X.509 certificate into structured attributes."""

    @staticmethod
    def parse_der_or_pem(raw_bytes: bytes) -> Optional[x509.Certificate]:
        try:
            return x509.load_der_x509_certificate(raw_bytes, default_backend())
        except Exception:
            try:
                return x509.load_pem_x509_certificate(raw_bytes, default_backend())
            except Exception:
                return None

    @classmethod
    def dissect_cert(cls, cert: x509.Certificate, host_to_match: Optional[str] = None) -> Dict[str, Any]:
        now = datetime.datetime.now(datetime.timezone.utc)
        
        # Subject & Issuer formatting
        def format_name(name: x509.Name) -> Tuple[str, str]:
            cn_list = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            org_list = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            cn = cn_list[0].value if cn_list else "Unknown CN"
            org = org_list[0].value if org_list else ""
            return cn, org

        subject_cn, subject_org = format_name(cert.subject)
        issuer_cn, issuer_org = format_name(cert.issuer)
        
        # Expiry & validity
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        is_expired = now > not_after
        is_not_yet_valid = now < not_before
        days_to_expiry = (not_after - now).days

        # Public Key Analysis
        pub_key = cert.public_key()
        key_type = "Unknown"
        key_size = 0
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_type = f"ECC ({pub_key.curve.name})"
            key_size = pub_key.curve.key_size
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            key_type = "Ed25519"
            key_size = 256
        elif isinstance(pub_key, dsa.DSAPublicKey):
            key_type = "DSA"
            key_size = pub_key.key_size

        # Signature Algorithm
        sig_alg = cert.signature_algorithm_oid._name if hasattr(cert, "signature_algorithm_oid") else cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown"
        is_weak_sig = any(w in sig_alg.lower() for w in ["md5", "sha1", "md2"])
        is_weak_key = (key_type == "RSA" and key_size < 2048) or (key_type.startswith("ECC") and key_size < 224)

        # SANs (Subject Alternative Names)
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = [str(name.value) for name in san_ext.value]
        except x509.ExtensionNotFound:
            pass

        # Basic Constraints (CA flag)
        is_ca = False
        path_length = None
        try:
            bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            is_ca = bc_ext.value.ca
            path_length = bc_ext.value.path_length
        except x509.ExtensionNotFound:
            pass

        # Is Self-Signed?
        is_self_signed = (cert.subject == cert.issuer)

        # Hostname match check
        host_match = True
        if host_to_match:
            valid_names = set(sans)
            if subject_cn:
                valid_names.add(subject_cn)
            host_match = False
            for v in valid_names:
                if v.startswith("*.") and host_to_match.endswith(v[2:]):
                    host_match = True
                    break
                if v.lower() == host_to_match.lower():
                    host_match = True
                    break

        return {
            "subject_cn": subject_cn,
            "subject_org": subject_org,
            "issuer_cn": issuer_cn,
            "issuer_org": issuer_org,
            "serial_number": hex(cert.serial_number),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "is_expired": is_expired,
            "is_not_yet_valid": is_not_yet_valid,
            "days_to_expiry": days_to_expiry,
            "key_type": key_type,
            "key_size": key_size,
            "is_weak_key": is_weak_key,
            "signature_algorithm": sig_alg,
            "is_weak_signature": is_weak_sig,
            "sans": sans,
            "is_ca": is_ca,
            "path_length": path_length,
            "is_self_signed": is_self_signed,
            "host_match": host_match,
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        }


class CertChainValidator:
    """
    Validates full certificate chains:
    [Leaf / Server Cert, Intermediate CA 1, Intermediate CA 2, ..., Root CA]
    """

    def __init__(self, trusted_roots: Optional[List[x509.Certificate]] = None):
        self.trusted_roots = trusted_roots or []

    def add_trusted_root(self, root_cert: x509.Certificate):
        self.trusted_roots.append(root_cert)

    @staticmethod
    def verify_signature(child: x509.Certificate, issuer: x509.Certificate) -> bool:
        """Verifies child certificate cryptographic signature with issuer public key."""
        try:
            issuer_pub_key = issuer.public_key()
            if isinstance(issuer_pub_key, rsa.RSAPublicKey):
                issuer_pub_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    child.signature_hash_algorithm
                )
                return True
            elif isinstance(issuer_pub_key, ec.EllipticCurvePublicKey):
                issuer_pub_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    ec.ECDSA(child.signature_hash_algorithm)
                )
                return True
            elif isinstance(issuer_pub_key, ed25519.Ed25519PublicKey):
                issuer_pub_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes
                )
                return True
            return False
        except Exception:
            return False

    def validate_chain(
        self,
        cert_list: List[x509.Certificate],
        expected_host: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validates the certificate chain structure, cryptography, expiry, and trust anchors.
        cert_list[0] is expected to be the Leaf (Server) certificate.
        """
        if not cert_list:
            return {
                "status": CertChainStatus.INCOMPLETE_CHAIN,
                "is_valid": False,
                "chain_length": 0,
                "hierarchy": [],
                "errors": ["No certificates provided in TLS handshake."],
                "root_trusted": False,
                "leaf_details": None
            }

        dissected_chain = []
        errors = []
        now = datetime.datetime.now(datetime.timezone.utc)

        # Dissect each certificate in the received chain
        for idx, cert in enumerate(cert_list):
            host_check = expected_host if idx == 0 else None
            details = CertificateDissector.dissect_cert(cert, host_check)
            details["level"] = "Leaf (Server)" if idx == 0 else ("Root CA" if details["is_self_signed"] else f"Intermediate CA {idx}")
            dissected_chain.append(details)

        leaf_details = dissected_chain[0]
        chain_len = len(cert_list)

        # Single self-signed certificate case
        if chain_len == 1 and leaf_details["is_self_signed"]:
            is_trusted = any(r.fingerprint(hashes.SHA256()) == cert_list[0].fingerprint(hashes.SHA256()) for r in self.trusted_roots)
            if leaf_details["is_expired"]:
                errors.append(f"Leaf certificate expired on {leaf_details['not_after']}.")
            if leaf_details["is_weak_key"]:
                errors.append(f"Weak public key size: {leaf_details['key_type']} {leaf_details['key_size']} bits.")
            if leaf_details["is_weak_signature"]:
                errors.append(f"Weak signature algorithm: {leaf_details['signature_algorithm']}.")
            if not is_trusted:
                errors.append("Self-signed certificate is not in the trusted root CA store.")
                return {
                    "status": CertChainStatus.SELF_SIGNED,
                    "is_valid": False,
                    "chain_length": 1,
                    "hierarchy": dissected_chain,
                    "errors": errors,
                    "root_trusted": False,
                    "leaf_details": leaf_details
                }

        # Multi-node chain validation
        # Verify sequential signature chain from 0 to N-1
        signature_broken = False
        for i in range(chain_len - 1):
            child = cert_list[i]
            parent = cert_list[i + 1]
            if child.issuer != parent.subject:
                errors.append(f"Chain break: '{dissected_chain[i]['subject_cn']}' issuer does not match '{dissected_chain[i+1]['subject_cn']}'.")
                signature_broken = True
                break
            if not self.verify_signature(child, parent):
                errors.append(f"Cryptographic signature verification failed between '{dissected_chain[i]['subject_cn']}' and issuer '{dissected_chain[i+1]['subject_cn']}'.")
                signature_broken = True
                break

        if signature_broken:
            return {
                "status": CertChainStatus.BROKEN_CHAIN,
                "is_valid": False,
                "chain_length": chain_len,
                "hierarchy": dissected_chain,
                "errors": errors,
                "root_trusted": False,
                "leaf_details": leaf_details
            }

        # Expiry checks across chain
        for idx, item in enumerate(dissected_chain):
            if item["is_expired"]:
                errors.append(f"Node {idx} ({item['subject_cn']}) expired on {item['not_after']}.")
            if item["is_not_yet_valid"]:
                errors.append(f"Node {idx} ({item['subject_cn']}) is not yet valid until {item['not_before']}.")
            if item["is_weak_key"]:
                errors.append(f"Node {idx} ({item['subject_cn']}) has weak key size ({item['key_size']} bits).")
            if item["is_weak_signature"]:
                errors.append(f"Node {idx} ({item['subject_cn']}) uses weak signature ({item['signature_algorithm']}).")

        # Root CA trust anchor check
        root_cert = cert_list[-1]
        root_fp = root_cert.fingerprint(hashes.SHA256())
        is_root_trusted = (
            any(r.fingerprint(hashes.SHA256()) == root_fp for r in self.trusted_roots) or
            (not self.trusted_roots and root_cert.subject == root_cert.issuer) # Fallback if standard self-signed root chain
        )

        if not is_root_trusted and self.trusted_roots:
            errors.append(f"Root CA '{dissected_chain[-1]['subject_cn']}' is not trusted by the root store.")

        # Determine overall status
        status = CertChainStatus.VALID
        if any(d["is_expired"] for d in dissected_chain):
            status = CertChainStatus.EXPIRED if leaf_details["is_expired"] else CertChainStatus.EXPIRED_IN_CHAIN
        elif any(d["is_weak_key"] for d in dissected_chain):
            status = CertChainStatus.WEAK_KEY_IN_CHAIN
        elif any(d["is_weak_signature"] for d in dissected_chain):
            status = CertChainStatus.WEAK_SIG_IN_CHAIN
        elif not is_root_trusted:
            status = CertChainStatus.UNTRUSTED_ROOT
        elif leaf_details["is_self_signed"]:
            status = CertChainStatus.SELF_SIGNED

        is_valid = (len(errors) == 0 and is_root_trusted and status == CertChainStatus.VALID)

        return {
            "status": status,
            "is_valid": is_valid,
            "chain_length": chain_len,
            "hierarchy": dissected_chain,
            "errors": errors,
            "root_trusted": is_root_trusted,
            "leaf_details": leaf_details
        }
