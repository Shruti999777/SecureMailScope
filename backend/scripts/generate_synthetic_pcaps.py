"""
SecureMailScope - Synthetic PCAP Generator for Systematic 18/18 Test Matrix
Constructs realistic packet captures covering all email protocols, TLS versions, cipher suites,
certificate chain permutations, and behavioral traffic shapes.
"""

import os
import struct
import time
from pathlib import Path
from scapy.all import IP, TCP, Raw, wrpcap

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = BASE_DIR / "data" / "sample_pcaps"
CA_DIR = BASE_DIR / "data" / "ca_store"
SAMPLES_DIR.mkdir(parents=True, exist_ok=True)


def build_tls_record(content_type: int, version: int, fragment: bytes) -> bytes:
    """Builds a standard TLS record header + payload."""
    header = struct.pack("!BHH", content_type, version, len(fragment))
    return header + fragment


def build_client_hello(tls_version_hex: int, ciphers: list, sni: str = "mail.example.org") -> bytes:
    """Builds a TLS ClientHello handshake packet."""
    client_random = os.urandom(32)
    
    # Ciphers
    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    ciphers_block = struct.pack("!H", len(cipher_bytes)) + cipher_bytes
    
    # Compression (0 = None)
    comp_block = b"\x01\x00"
    
    # Extensions: SNI + Supported Versions
    extensions = bytearray()
    
    # SNI extension (type 0)
    sni_bytes = sni.encode("latin-1")
    sni_data = struct.pack("!H", len(sni_bytes) + 3) + b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
    extensions.extend(struct.pack("!HH", 0, len(sni_data)) + sni_data)
    
    # Supported versions extension (type 43) if TLS 1.3
    if tls_version_hex == 0x0304:
        supp_data = b"\x02\x03\x04"
        extensions.extend(struct.pack("!HH", 43, len(supp_data)) + supp_data)
        client_ver = 0x0303  # TLS 1.3 ClientHello legacy version is 0x0303
    else:
        client_ver = tls_version_hex

    ext_block = struct.pack("!H", len(extensions)) + bytes(extensions)
    
    body = struct.pack("!H", client_ver) + client_random + b"\x00" + ciphers_block + comp_block + ext_block
    hs_msg = struct.pack("!B", 1) + struct.pack("!I", len(body))[1:] + body
    return build_tls_record(22, 0x0301 if tls_version_hex in (0x0301, 0x0302) else 0x0303, hs_msg)


def build_server_hello(tls_version_hex: int, selected_cipher: int) -> bytes:
    """Builds a TLS ServerHello handshake packet."""
    server_random = os.urandom(32)
    
    extensions = bytearray()
    if tls_version_hex == 0x0304:
        supp_data = b"\x03\x04"
        extensions.extend(struct.pack("!HH", 43, len(supp_data)) + supp_data)
        server_ver = 0x0303
    else:
        server_ver = tls_version_hex

    ext_block = struct.pack("!H", len(extensions)) + bytes(extensions) if extensions else b""
    body = struct.pack("!H", server_ver) + server_random + b"\x00" + struct.pack("!H", selected_cipher) + b"\x00" + ext_block
    hs_msg = struct.pack("!B", 2) + struct.pack("!I", len(body))[1:] + body
    return build_tls_record(22, 0x0301 if tls_version_hex in (0x0301, 0x0302) else 0x0303, hs_msg)


def build_certificate_msg(cert_der_list: list) -> bytes:
    """Builds a TLS Certificate handshake message."""
    all_certs_bytes = bytearray()
    for c_der in cert_der_list:
        if c_der:
            all_certs_bytes.extend(struct.pack("!I", len(c_der))[1:] + c_der)
    
    body = struct.pack("!I", len(all_certs_bytes))[1:] + bytes(all_certs_bytes)
    hs_msg = struct.pack("!B", 11) + struct.pack("!I", len(body))[1:] + body
    return build_tls_record(22, 0x0303, hs_msg)


def make_tcp_flow(src_ip: str, dst_ip: str, src_port: int, dst_port: int, client_chunks: list, server_chunks: list, base_time: float = 1700000000.0) -> list:
    """Generates a complete TCP 3-way handshake, payload exchange, and teardown packet list."""
    pkts = []
    t = base_time

    # SYN
    c_seq = 1000
    s_seq = 5000
    p1 = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S", seq=c_seq)
    p1.time = t
    pkts.append(p1)
    t += 0.005

    # SYN-ACK
    p2 = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="SA", seq=s_seq, ack=c_seq + 1)
    p2.time = t
    pkts.append(p2)
    t += 0.005
    c_seq += 1
    s_seq += 1

    # ACK
    p3 = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", seq=c_seq, ack=s_seq)
    p3.time = t
    pkts.append(p3)
    t += 0.005

    # Interleave chunks
    max_turns = max(len(client_chunks), len(server_chunks))
    for i in range(max_turns):
        if i < len(server_chunks) and server_chunks[i]:
            s_data = server_chunks[i]
            p_s = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="PA", seq=s_seq, ack=c_seq) / Raw(load=s_data)
            p_s.time = t
            pkts.append(p_s)
            s_seq += len(s_data)
            t += 0.01

        if i < len(client_chunks) and client_chunks[i]:
            c_data = client_chunks[i]
            p_c = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="PA", seq=c_seq, ack=s_seq) / Raw(load=c_data)
            p_c.time = t
            pkts.append(p_c)
            c_seq += len(c_data)
            t += 0.01

    # FIN-ACK Teardown
    p_fin1 = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="FA", seq=c_seq, ack=s_seq)
    p_fin1.time = t
    pkts.append(p_fin1)
    t += 0.005

    p_fin2 = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="FA", seq=s_seq, ack=c_seq + 1)
    p_fin2.time = t
    pkts.append(p_fin2)
    t += 0.005

    return pkts


def load_der(filename: str) -> bytes:
    p = CA_DIR / filename
    if p.exists():
        return p.read_bytes()
    return b""


def generate_18_scenarios():
    print("[*] Generating Systematic 18/18 Synthetic Test PCAPs...")

    # Load DER certs
    server_valid_der = load_der("server_valid.der")
    inter_ca_der = load_der("intermediate_ca.der")
    root_ca_der = load_der("root_ca.der")
    expired_der = load_der("server_expired.der")
    self_signed_der = load_der("server_self_signed.der")
    weak_1024_der = load_der("server_weak_1024.der")
    ecc_der = load_der("server_ecc.der")

    # 1. Plaintext SMTP (Port 25)
    p1 = make_tcp_flow(
        "192.168.1.50", "10.0.0.25", 49152, 25,
        client_chunks=[b"EHLO client.example.com\r\n", b"MAIL FROM:<alice@example.com>\r\n", b"RCPT TO:<bob@example.com>\r\n", b"DATA\r\n", b"Subject: Quarterly Plan\r\n\r\nConfidential quarterly review details.\r\n.\r\n", b"QUIT\r\n"],
        server_chunks=[b"220 mail.example.com ESMTP Postfix\r\n", b"250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 8BITMIME\r\n", b"250 2.1.0 Ok\r\n", b"250 2.1.5 Ok\r\n", b"354 End data with <CR><LF>.<CR><LF>\r\n", b"250 2.0.0 Ok: queued as A48F190\r\n", b"221 2.0.0 Bye\r\n"]
    )
    wrpcap(str(SAMPLES_DIR / "01_smtp_plaintext.pcap"), p1)

    # 2. Plaintext IMAP Auth (Port 143)
    p2 = make_tcp_flow(
        "192.168.1.51", "10.0.0.14", 49153, 143,
        client_chunks=[b"a001 CAPABILITY\r\n", b"a002 LOGIN john_doe MySecretPassword99!\r\n", b"a003 SELECT INBOX\r\n", b"a004 LOGOUT\r\n"],
        server_chunks=[b"* OK Dovecot ready.\r\n", b"* CAPABILITY IMAP4rev1 SASL-IR LITERAL+ LOGIN-REFERRALS ID ENABLE IDLE\r\na001 OK Pre-login capability completed.\r\n", b"a002 OK [CAPABILITY IMAP4rev1] Logged in\r\n", b"* 24 EXISTS\r\n* 0 RECENT\r\na003 OK [READ-WRITE] Select completed\r\n", b"* BYE Logging out\r\na004 OK Logout completed.\r\n"]
    )
    wrpcap(str(SAMPLES_DIR / "02_imap_plaintext_auth.pcap"), p2)

    # 3. Plaintext POP3 Auth (Port 110)
    p3 = make_tcp_flow(
        "192.168.1.52", "10.0.0.11", 49154, 110,
        client_chunks=[b"USER admin@corporate.com\r\n", b"PASS AdminPass2026$\r\n", b"STAT\r\n", b"QUIT\r\n"],
        server_chunks=[b"+OK Dovecot POP3 server ready.\r\n", b"+OK User accepted\r\n", b"+OK Pass accepted\r\n", b"+OK 12 458902\r\n", b"+OK Logging out.\r\n"]
    )
    wrpcap(str(SAMPLES_DIR / "03_pop3_plaintext_auth.pcap"), p3)

    # 4. SMTPS TLS 1.3 ECDHE (Port 465) - Secure
    c_hello = build_client_hello(0x0304, [0x1302, 0x1301, 0xC02F, 0xC030], "mail.securemail.org")
    s_hello = build_server_hello(0x0304, 0x1302)  # TLS_AES_256_GCM_SHA384
    s_cert = build_certificate_msg([server_valid_der, inter_ca_der])
    app_data = build_tls_record(23, 0x0303, os.urandom(256))
    p4 = make_tcp_flow(
        "192.168.1.60", "10.0.0.46", 49160, 465,
        client_chunks=[c_hello, app_data],
        server_chunks=[b"", s_hello + s_cert, app_data]
    )
    wrpcap(str(SAMPLES_DIR / "04_smtps_tls13_ecdhe_secure.pcap"), p4)

    # 5. IMAPS TLS 1.3 ChaCha20 (Port 993) - Secure
    c_hello5 = build_client_hello(0x0304, [0x1303, 0x1302], "imap.securemail.org")
    s_hello5 = build_server_hello(0x0304, 0x1303)  # TLS_CHACHA20_POLY1305_SHA256
    s_cert5 = build_certificate_msg([ecc_der, inter_ca_der])
    p5 = make_tcp_flow(
        "192.168.1.61", "10.0.0.93", 49161, 993,
        client_chunks=[c_hello5, app_data],
        server_chunks=[b"", s_hello5 + s_cert5, app_data]
    )
    wrpcap(str(SAMPLES_DIR / "05_imaps_tls13_chacha_secure.pcap"), p5)

    # 6. POP3S TLS 1.2 AES-GCM (Port 995) - Secure
    c_hello6 = build_client_hello(0x0303, [0xC030, 0xC02F], "pop3.securemail.org")
    s_hello6 = build_server_hello(0x0303, 0xC030)  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    s_cert6 = build_certificate_msg([server_valid_der, inter_ca_der])
    p6 = make_tcp_flow(
        "192.168.1.62", "10.0.0.95", 49162, 995,
        client_chunks=[c_hello6, app_data],
        server_chunks=[b"", s_hello6 + s_cert6, app_data]
    )
    wrpcap(str(SAMPLES_DIR / "06_pop3s_tls12_aes_gcm_secure.pcap"), p6)

    # 7. SMTP STARTTLS Upgrade (Port 25)
    p7 = make_tcp_flow(
        "192.168.1.70", "10.0.0.25", 49170, 25,
        client_chunks=[b"EHLO client.domain.com\r\n", b"STARTTLS\r\n", c_hello, app_data],
        server_chunks=[b"220 mail.domain.com ESMTP Postfix\r\n", b"250-mail.domain.com\r\n250-PIPELINING\r\n250-SIZE 20480000\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n", b"220 2.0.0 Ready to start TLS\r\n", s_hello + s_cert, app_data]
    )
    wrpcap(str(SAMPLES_DIR / "07_smtp_starttls_upgrade.pcap"), p7)

    # 8. IMAP STARTTLS Upgrade (Port 143)
    p8 = make_tcp_flow(
        "192.168.1.71", "10.0.0.14", 49171, 143,
        client_chunks=[b"a001 CAPABILITY\r\n", b"a002 STARTTLS\r\n", c_hello6, app_data],
        server_chunks=[b"* OK IMAP4rev1 Server Ready\r\n", b"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\na001 OK Capability completed.\r\n", b"a002 OK Begin TLS negotiation now\r\n", s_hello6 + s_cert6, app_data]
    )
    wrpcap(str(SAMPLES_DIR / "08_imap_starttls_upgrade.pcap"), p8)

    # 9. POP3 STLS Upgrade (Port 110)
    p9 = make_tcp_flow(
        "192.168.1.72", "10.0.0.11", 49172, 110,
        client_chunks=[b"CAPA\r\n", b"STLS\r\n", c_hello6, app_data],
        server_chunks=[b"+OK POP3 Ready\r\n", b"+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n", b"+OK Begin TLS negotiation\r\n", s_hello6 + s_cert6, app_data]
    )
    wrpcap(str(SAMPLES_DIR / "09_pop3_stls_upgrade.pcap"), p9)

    # 10. SMTPS TLS 1.0 Deprecated (Port 465) - High Risk
    c_hello10 = build_client_hello(0x0301, [0x002F, 0x0035], "legacy.mail.org")
    s_hello10 = build_server_hello(0x0301, 0x002F)  # TLS 1.0 + TLS_RSA_WITH_AES_128_CBC_SHA
    p10 = make_tcp_flow(
        "192.168.1.80", "10.0.0.46", 49180, 465,
        client_chunks=[c_hello10, app_data],
        server_chunks=[b"", s_hello10 + s_cert, app_data]
    )
    wrpcap(str(SAMPLES_DIR / "10_smtps_tls10_deprecated.pcap"), p10)

    # 11. IMAPS TLS 1.1 Deprecated (Port 993) - Medium Risk
    c_hello11 = build_client_hello(0x0302, [0x0035, 0xC014], "legacy-imap.mail.org")
    s_hello11 = build_server_hello(0x0302, 0x0035)  # TLS 1.1 + TLS_RSA_WITH_AES_256_CBC_SHA
    p11 = make_tcp_flow(
        "192.168.1.81", "10.0.0.93", 49181, 993,
        client_chunks=[c_hello11, app_data],
        server_chunks=[b"", s_hello11 + s_cert, app_data]
    )
    wrpcap(str(SAMPLES_DIR / "11_imaps_tls11_deprecated.pcap"), p11)

    # 12. SMTPS RC4 Broken Cipher (Port 465) - Critical Risk
    c_hello12 = build_client_hello(0x0303, [0x0005, 0x0004], "rc4.mail.org")
    s_hello12 = build_server_hello(0x0303, 0x0005)  # TLS_RSA_WITH_RC4_128_SHA
    p12 = make_tcp_flow(
        "192.168.1.82", "10.0.0.46", 49182, 465,
        client_chunks=[c_hello12, app_data],
        server_chunks=[b"", s_hello12 + s_cert, app_data]
    )
    wrpcap(str(SAMPLES_DIR / "12_smtp_rc4_broken_cipher.pcap"), p12)

    # 13. SMTPS 3DES Sweet32 Cipher (Port 465) - Insecure / High Risk
    c_hello13 = build_client_hello(0x0303, [0x000A], "3des.mail.org")
    s_hello13 = build_server_hello(0x0303, 0x000A)  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    p13 = make_tcp_flow(
        "192.168.1.83", "10.0.0.46", 49183, 465,
        client_chunks=[c_hello13, app_data],
        server_chunks=[b"", s_hello13 + s_cert, app_data]
    )
    wrpcap(str(SAMPLES_DIR / "13_smtp_3des_sweet32_cipher.pcap"), p13)

    # 14. SMTPS Static RSA (No Forward Secrecy) (Port 465) - Medium Risk
    c_hello14 = build_client_hello(0x0303, [0x009D, 0x009C], "static-rsa.mail.org")
    s_hello14 = build_server_hello(0x0303, 0x009D)  # TLS_RSA_WITH_AES_256_GCM_SHA384 (Static RSA)
    p14 = make_tcp_flow(
        "192.168.1.84", "10.0.0.46", 49184, 465,
        client_chunks=[c_hello14, app_data],
        server_chunks=[b"", s_hello14 + s_cert, app_data]
    )
    wrpcap(str(SAMPLES_DIR / "14_smtps_static_rsa_no_fs.pcap"), p14)

    # 15. SMTPS Expired Certificate (Port 465) - High Risk
    s_cert15 = build_certificate_msg([expired_der, inter_ca_der])
    p15 = make_tcp_flow(
        "192.168.1.85", "10.0.0.46", 49185, 465,
        client_chunks=[c_hello6, app_data],
        server_chunks=[b"", s_hello6 + s_cert15, app_data]
    )
    wrpcap(str(SAMPLES_DIR / "15_smtps_expired_certificate.pcap"), p15)

    # 16. SMTPS Self-Signed Certificate (Port 465) - High Risk
    s_cert16 = build_certificate_msg([self_signed_der])
    p16 = make_tcp_flow(
        "192.168.1.86", "10.0.0.46", 49186, 465,
        client_chunks=[c_hello6, app_data],
        server_chunks=[b"", s_hello6 + s_cert16, app_data]
    )
    wrpcap(str(SAMPLES_DIR / "16_smtps_self_signed_certificate.pcap"), p16)

    # 17. SMTPS Full 3-Tier Valid Chain (Port 465) - Secure
    s_cert17 = build_certificate_msg([server_valid_der, inter_ca_der, root_ca_der])
    p17 = make_tcp_flow(
        "192.168.1.87", "10.0.0.46", 49187, 465,
        client_chunks=[c_hello, app_data],
        server_chunks=[b"", s_hello + s_cert17, app_data]
    )
    wrpcap(str(SAMPLES_DIR / "17_smtps_full_3tier_valid_chain.pcap"), p17)

    # 18. Mixed Enterprise Traffic with Behavioral Anomaly Burst
    mixed_pkts = []
    mixed_pkts.extend(p4)
    mixed_pkts.extend(p5)
    mixed_pkts.extend(p6)
    
    # Add an anomalous high-burst brute-force session
    burst_chunks = [f"a{i:04d} LOGIN admin guess_pass_{i}\r\n".encode("latin-1") for i in range(120)]
    p18_anom = make_tcp_flow(
        "192.168.1.99", "10.0.0.14", 59999, 143,
        client_chunks=burst_chunks,
        server_chunks=[b"* OK IMAP Ready\r\n"] + [b"NO [AUTHENTICATIONFAILED] Invalid credentials\r\n" for _ in range(120)],
        base_time=1700000500.0
    )
    mixed_pkts.extend(p18_anom)
    wrpcap(str(SAMPLES_DIR / "18_enterprise_mixed_anomalous_burst.pcap"), mixed_pkts)

    print(f"[+] Successfully generated all 18 test matrix PCAP files in: {SAMPLES_DIR}")


if __name__ == "__main__":
    generate_18_scenarios()
