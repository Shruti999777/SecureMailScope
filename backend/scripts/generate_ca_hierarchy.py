"""
SecureMailScope - CA Hierarchy & Test Certificates Generator
Generates full 3-tier PKI (Root CA -> Intermediate CA -> Server Cert),
plus expired, self-signed, weak-key, and custom certificates for testing.
"""

import os
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

BASE_DIR = Path(__file__).resolve().parent.parent
CA_DIR = BASE_DIR / "data" / "ca_store"
CA_DIR.mkdir(parents=True, exist_ok=True)


def generate_all_ca_and_certs():
    now = datetime.datetime.now(datetime.timezone.utc)
    one_day = datetime.timedelta(days=1)
    ten_years = datetime.timedelta(days=3650)
    one_year = datetime.timedelta(days=365)

    print("[*] Generating PKI Certificate Hierarchy...")

    # 1. Root CA (RSA 4096, SHA256)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    root_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope Trust Network"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureMailScope Root CA G1"),
    ])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - one_day)
        .not_valid_after(now + ten_years)
        .add_extension(x509.BasicConstraints(ca=True, path_length=2), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(root_key, hashes.SHA256(), default_backend())
    )

    # 2. Intermediate CA (RSA 3072, SHA256) signed by Root CA
    inter_key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
    inter_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope Trust Network"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureMailScope Mail Intermediate CA R1"),
    ])
    inter_cert = (
        x509.CertificateBuilder()
        .subject_name(inter_subject)
        .issuer_name(root_subject)
        .public_key(inter_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - one_day)
        .not_valid_after(now + datetime.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(root_key, hashes.SHA256(), default_backend())
    )

    # 3. Valid Server Certificate (mail.securemail.org) signed by Intermediate CA
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise Mail Services"),
        x509.NameAttribute(NameOID.COMMON_NAME, "mail.securemail.org"),
    ])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(inter_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - one_day)
        .not_valid_after(now + one_year)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("mail.securemail.org"),
            x509.DNSName("smtp.securemail.org"),
            x509.DNSName("imap.securemail.org"),
        ]), critical=False)
        .sign(inter_key, hashes.SHA256(), default_backend())
    )

    # 4. Expired Certificate (Expired 90 days ago)
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    expired_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Legacy Mail Systems"),
        x509.NameAttribute(NameOID.COMMON_NAME, "expired.mailcorp.com"),
    ])
    expired_cert = (
        x509.CertificateBuilder()
        .subject_name(expired_subject)
        .issuer_name(inter_subject)
        .public_key(expired_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=400))
        .not_valid_after(now - datetime.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(inter_key, hashes.SHA256(), default_backend())
    )

    # 5. Self-Signed Certificate
    self_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    self_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Untrusted SelfSigned Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, "untrusted-mail.local"),
    ])
    self_signed_cert = (
        x509.CertificateBuilder()
        .subject_name(self_subject)
        .issuer_name(self_subject)
        .public_key(self_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - one_day)
        .not_valid_after(now + one_year)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(self_key, hashes.SHA256(), default_backend())
    )

    # 6. Weak Key Certificate (RSA 1024-bit)
    weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
    weak_subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Weak Crypto Host"),
        x509.NameAttribute(NameOID.COMMON_NAME, "weak-1024.mail.org"),
    ])
    weak_key_cert = (
        x509.CertificateBuilder()
        .subject_name(weak_subject)
        .issuer_name(inter_subject)
        .public_key(weak_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - one_day)
        .not_valid_after(now + one_year)
        .sign(inter_key, hashes.SHA256(), default_backend())
    )

    # 7. ECDSA P-256 Modern Certificate
    ec_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ec_subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Modern ECC Mail"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ecc.securemail.org"),
    ])
    ec_cert = (
        x509.CertificateBuilder()
        .subject_name(ec_subject)
        .issuer_name(inter_subject)
        .public_key(ec_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - one_day)
        .not_valid_after(now + one_year)
        .sign(inter_key, hashes.SHA256(), default_backend())
    )

    # Save all certs and keys
    cert_map = {
        "root_ca.crt": root_cert,
        "intermediate_ca.crt": inter_cert,
        "server_valid.crt": server_cert,
        "server_expired.crt": expired_cert,
        "server_self_signed.crt": self_signed_cert,
        "server_weak_1024.crt": weak_key_cert,
        "server_ecc.crt": ec_cert,
    }

    for fname, cert_obj in cert_map.items():
        with open(CA_DIR / fname, "wb") as f:
            f.write(cert_obj.public_bytes(serialization.Encoding.PEM))
        # Also save DER
        der_name = fname.replace(".crt", ".der")
        with open(CA_DIR / der_name, "wb") as f:
            f.write(cert_obj.public_bytes(serialization.Encoding.DER))

    print(f"[+] All CA and test certificates generated successfully in: {CA_DIR}")
    return cert_map


if __name__ == "__main__":
    generate_all_ca_and_certs()
