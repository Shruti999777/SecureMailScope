"""
SecureMailScope - Master All-In-One Enterprise Audit PCAP Generator
Combines all protocol, TLS, cryptographic, certificate chain, and behavioral anomaly conditions
into a single, comprehensive PCAP capture file.
"""

import os
import struct
import time
from pathlib import Path
from scapy.all import IP, TCP, Raw, wrpcap

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = BASE_DIR / "data" / "sample_pcaps"
CA_DIR = BASE_DIR / "data" / "ca_store"
OUTPUT_PCAP = SAMPLES_DIR / "master_enterprise_audit.pcap"
ROOT_COPY = BASE_DIR.parent / "master_enterprise_audit.pcap"

SAMPLES_DIR.mkdir(parents=True, exist_ok=True)


def build_tls_record(content_type: int, version: int, fragment: bytes) -> bytes:
    header = struct.pack("!BHH", content_type, version, len(fragment))
    return header + fragment


def build_client_hello(tls_version_hex: int, ciphers: list, sni: str = "mail.securemail.org") -> bytes:
    client_random = os.urandom(32)
    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    ciphers_block = struct.pack("!H", len(cipher_bytes)) + cipher_bytes
    comp_block = b"\x01\x00"
    
    extensions = bytearray()
    sni_bytes = sni.encode("latin-1")
    sni_data = struct.pack("!H", len(sni_bytes) + 3) + b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
    extensions.extend(struct.pack("!HH", 0, len(sni_data)) + sni_data)
    
    if tls_version_hex == 0x0304:
        supp_data = b"\x02\x03\x04"
        extensions.extend(struct.pack("!HH", 43, len(supp_data)) + supp_data)
        client_ver = 0x0303
    else:
        client_ver = tls_version_hex

    ext_block = struct.pack("!H", len(extensions)) + bytes(extensions)
    body = struct.pack("!H", client_ver) + client_random + b"\x00" + ciphers_block + comp_block + ext_block
    hs_msg = struct.pack("!B", 1) + struct.pack("!I", len(body))[1:] + body
    return build_tls_record(22, 0x0301 if tls_version_hex in (0x0301, 0x0302) else 0x0303, hs_msg)


def build_server_hello(tls_version_hex: int, selected_cipher: int) -> bytes:
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
    all_certs_bytes = bytearray()
    for c_der in cert_der_list:
        if c_der:
            all_certs_bytes.extend(struct.pack("!I", len(c_der))[1:] + c_der)
    body = struct.pack("!I", len(all_certs_bytes))[1:] + bytes(all_certs_bytes)
    hs_msg = struct.pack("!B", 11) + struct.pack("!I", len(body))[1:] + body
    return build_tls_record(22, 0x0303, hs_msg)


def make_tcp_flow(src_ip: str, dst_ip: str, src_port: int, dst_port: int, client_chunks: list, server_chunks: list, base_time: float = 1700000000.0) -> list:
    pkts = []
    t = base_time
    c_seq = 1000 + int(src_port * 10)
    s_seq = 5000 + int(dst_port * 10)

    # SYN
    p1 = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S", seq=c_seq)
    p1.time = t
    pkts.append(p1)
    t += 0.003

    # SYN-ACK
    p2 = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="SA", seq=s_seq, ack=c_seq + 1)
    p2.time = t
    pkts.append(p2)
    t += 0.003
    c_seq += 1
    s_seq += 1

    # ACK
    p3 = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", seq=c_seq, ack=s_seq)
    p3.time = t
    pkts.append(p3)
    t += 0.003

    # Interleaved Data
    max_turns = max(len(client_chunks), len(server_chunks))
    for i in range(max_turns):
        if i < len(server_chunks) and server_chunks[i]:
            s_data = server_chunks[i]
            p_s = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="PA", seq=s_seq, ack=c_seq) / Raw(load=s_data)
            p_s.time = t
            pkts.append(p_s)
            s_seq += len(s_data)
            t += 0.008

        if i < len(client_chunks) and client_chunks[i]:
            c_data = client_chunks[i]
            p_c = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="PA", seq=c_seq, ack=s_seq) / Raw(load=c_data)
            p_c.time = t
            pkts.append(p_c)
            c_seq += len(c_data)
            t += 0.008

    # FIN-ACK Teardown
    p_fin1 = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="FA", seq=c_seq, ack=s_seq)
    p_fin1.time = t
    pkts.append(p_fin1)
    t += 0.003

    p_fin2 = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="FA", seq=s_seq, ack=c_seq + 1)
    p_fin2.time = t
    pkts.append(p_fin2)
    t += 0.003

    return pkts


def load_der(filename: str) -> bytes:
    p = CA_DIR / filename
    if p.exists():
        return p.read_bytes()
    return b""


def generate_master_pcap():
    print("[*] Generating Master All-in-One Enterprise Audit PCAP...")

    server_valid_der = load_der("server_valid.der")
    inter_ca_der = load_der("intermediate_ca.der")
    root_ca_der = load_der("root_ca.der")
    expired_der = load_der("server_expired.der")
    self_signed_der = load_der("server_self_signed.der")
    weak_1024_der = load_der("server_weak_1024.der")
    ecc_der = load_der("server_ecc.der")

    app_data = build_tls_record(23, 0x0303, os.urandom(320))
    all_packets = []
    base_t = 1700000000.0

    # 1. SMTPS Full 3-Tier Valid Chain (TLS 1.3, ECDHE, AES-256-GCM) -> SECURE
    c1 = build_client_hello(0x0304, [0x1302, 0x1301], "mail.securemail.org")
    s1 = build_server_hello(0x0304, 0x1302)
    cert1 = build_certificate_msg([server_valid_der, inter_ca_der, root_ca_der])
    f1 = make_tcp_flow("192.168.10.101", "10.0.0.25", 50101, 465, [c1, app_data], [b"", s1 + cert1, app_data], base_time=base_t)
    all_packets.extend(f1)
    base_t += 0.5

    # 2. SMTP on Port 25 with STARTTLS Upgrade (TLS 1.3) -> SECURE
    f2 = make_tcp_flow(
        "192.168.10.102", "10.0.0.25", 50102, 25,
        client_chunks=[b"EHLO client.corp.internal\r\n", b"STARTTLS\r\n", c1, app_data],
        server_chunks=[b"220 mail.securemail.org ESMTP Postfix\r\n", b"250-mail.securemail.org\r\n250-STARTTLS\r\n250 8BITMIME\r\n", b"220 2.0.0 Ready to start TLS\r\n", s1 + cert1, app_data],
        base_time=base_t
    )
    all_packets.extend(f2)
    base_t += 0.5

    # 3. IMAPS TLS 1.3 with ECC P-256 + ChaCha20-Poly1305 -> SECURE
    c3 = build_client_hello(0x0304, [0x1303, 0x1302], "imap.securemail.org")
    s3 = build_server_hello(0x0304, 0x1303)
    cert3 = build_certificate_msg([ecc_der, inter_ca_der])
    f3 = make_tcp_flow("192.168.10.103", "10.0.0.93", 50103, 993, [c3, app_data], [b"", s3 + cert3, app_data], base_time=base_t)
    all_packets.extend(f3)
    base_t += 0.5

    # 4. POP3S TLS 1.2 with AES-256-GCM + ECDHE -> SECURE
    c4 = build_client_hello(0x0303, [0xC030, 0xC02F], "pop3.securemail.org")
    s4 = build_server_hello(0x0303, 0xC030)
    cert4 = build_certificate_msg([server_valid_der, inter_ca_der])
    f4 = make_tcp_flow("192.168.10.104", "10.0.0.95", 50104, 995, [c4, app_data], [b"", s4 + cert4, app_data], base_time=base_t)
    all_packets.extend(f4)
    base_t += 0.5

    # 5. Plaintext IMAP with Leaked Password -> CRITICAL (RULE-SEC-001)
    f5 = make_tcp_flow(
        "192.168.10.105", "10.0.0.14", 50105, 143,
        client_chunks=[b"a001 CAPABILITY\r\n", b"a002 LOGIN finance_admin SuperSecretPass2026!\r\n", b"a003 SELECT INBOX\r\n", b"a004 LOGOUT\r\n"],
        server_chunks=[b"* OK Dovecot ready.\r\n", b"* CAPABILITY IMAP4rev1\r\na001 OK Completed.\r\n", b"a002 OK Logged in.\r\n", b"* 54 EXISTS\r\na003 OK Select completed.\r\n", b"* BYE\r\na004 OK Logged out.\r\n"],
        base_time=base_t
    )
    all_packets.extend(f5)
    base_t += 0.5

    # 6. Plaintext POP3 with Leaked Password -> CRITICAL (RULE-SEC-001)
    f6 = make_tcp_flow(
        "192.168.10.106", "10.0.0.11", 50106, 110,
        client_chunks=[b"USER executive@corp.com\r\n", b"PASS ExecutivePassword#9\r\n", b"STAT\r\n", b"QUIT\r\n"],
        server_chunks=[b"+OK Dovecot POP3 Ready\r\n", b"+OK User accepted\r\n", b"+OK Pass accepted\r\n", b"+OK 10 20490\r\n", b"+OK Bye\r\n"],
        base_time=base_t
    )
    all_packets.extend(f6)
    base_t += 0.5

    # 7. Plaintext SMTP Unencrypted Transmission -> HIGH (RULE-SEC-009)
    f7 = make_tcp_flow(
        "192.168.10.107", "10.0.0.25", 50107, 25,
        client_chunks=[b"EHLO legacy.partner.org\r\n", b"MAIL FROM:<sender@partner.org>\r\n", b"RCPT TO:<sales@securemail.org>\r\n", b"DATA\r\n", b"Subject: Invoice #89201\r\n\r\nUnencrypted cleartext invoice details.\r\n.\r\n", b"QUIT\r\n"],
        server_chunks=[b"220 mail.securemail.org ESMTP\r\n", b"250-mail.securemail.org\r\n250 8BITMIME\r\n", b"250 OK\r\n", b"250 OK\r\n", b"354 Enter message\r\n", b"250 Queued\r\n", b"221 Bye\r\n"],
        base_time=base_t
    )
    all_packets.extend(f7)
    base_t += 0.5

    # 8. Deprecated TLS 1.0 SMTPS -> HIGH (RULE-SEC-002)
    c8 = build_client_hello(0x0301, [0x002F, 0x0035], "legacy-tls10.securemail.org")
    s8 = build_server_hello(0x0301, 0x002F)
    f8 = make_tcp_flow("192.168.10.108", "10.0.0.25", 50108, 465, [c8, app_data], [b"", s8 + cert4, app_data], base_time=base_t)
    all_packets.extend(f8)
    base_t += 0.5

    # 9. Broken RC4-SHA Cipher -> CRITICAL (RULE-SEC-003)
    c9 = build_client_hello(0x0303, [0x0005, 0x0004], "rc4-broken.securemail.org")
    s9 = build_server_hello(0x0303, 0x0005)  # TLS_RSA_WITH_RC4_128_SHA
    f9 = make_tcp_flow("192.168.10.109", "10.0.0.25", 50109, 465, [c9, app_data], [b"", s9 + cert4, app_data], base_time=base_t)
    all_packets.extend(f9)
    base_t += 0.5

    # 10. Sweet32 3DES Cipher -> CRITICAL (RULE-SEC-003)
    c10 = build_client_hello(0x0303, [0x000A], "3des.securemail.org")
    s10 = build_server_hello(0x0303, 0x000A)  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    f10 = make_tcp_flow("192.168.10.110", "10.0.0.25", 50110, 465, [c10, app_data], [b"", s10 + cert4, app_data], base_time=base_t)
    all_packets.extend(f10)
    base_t += 0.5

    # 11. Static RSA (No Forward Secrecy) -> MEDIUM (RULE-SEC-004)
    c11 = build_client_hello(0x0303, [0x009D], "static-rsa.securemail.org")
    s11 = build_server_hello(0x0303, 0x009D)  # TLS_RSA_WITH_AES_256_GCM_SHA384
    f11 = make_tcp_flow("192.168.10.111", "10.0.0.25", 50111, 465, [c11, app_data], [b"", s11 + cert4, app_data], base_time=base_t)
    all_packets.extend(f11)
    base_t += 0.5

    # 12. Expired X.509 Certificate -> HIGH (RULE-SEC-005)
    cert12 = build_certificate_msg([expired_der, inter_ca_der])
    f12 = make_tcp_flow("192.168.10.112", "10.0.0.25", 50112, 465, [c4, app_data], [b"", s4 + cert12, app_data], base_time=base_t)
    all_packets.extend(f12)
    base_t += 0.5

    # 13. Self-Signed Untrusted Certificate -> HIGH (RULE-SEC-006)
    cert13 = build_certificate_msg([self_signed_der])
    f13 = make_tcp_flow("192.168.10.113", "10.0.0.25", 50113, 465, [c4, app_data], [b"", s4 + cert13, app_data], base_time=base_t)
    all_packets.extend(f13)
    base_t += 0.5

    # 14. Weak RSA 1024-bit Key -> HIGH (RULE-SEC-007)
    cert14 = build_certificate_msg([weak_1024_der, inter_ca_der])
    f14 = make_tcp_flow("192.168.10.114", "10.0.0.25", 50114, 465, [c4, app_data], [b"", s4 + cert14, app_data], base_time=base_t)
    all_packets.extend(f14)
    base_t += 0.5

    # 15. Behavioral Brute-Force Anomaly Stream -> Flagged by Isolation Forest
    burst_chunks = [f"a{i:04d} LOGIN root pwd_{i}\r\n".encode("latin-1") for i in range(100)]
    f15 = make_tcp_flow(
        "192.168.10.199", "10.0.0.14", 59999, 143,
        client_chunks=burst_chunks,
        server_chunks=[b"* OK Dovecot IMAP Ready\r\n"] + [b"NO Auth Failed\r\n" for _ in range(100)],
        base_time=base_t
    )
    all_packets.extend(f15)

    # Sort all packets strictly by timestamp
    all_packets.sort(key=lambda p: float(p.time))

    # Write PCAP
    wrpcap(str(OUTPUT_PCAP), all_packets)
    wrpcap(str(ROOT_COPY), all_packets)

    print(f"[+] Successfully created master PCAP capture:")
    print(f"    - {OUTPUT_PCAP} ({len(all_packets)} packets, 15 streams)")
    print(f"    - {ROOT_COPY}")
    return OUTPUT_PCAP


if __name__ == "__main__":
    generate_master_pcap()
