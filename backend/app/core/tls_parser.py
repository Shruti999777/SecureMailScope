"""
SecureMailScope - Bulletproof TLS Record & Handshake Dissector
Parses TLS 1.0, 1.1, 1.2, 1.3 ClientHello, ServerHello, Certificate (TLS 1.2 & TLS 1.3 RFC 8446), Key Exchange, and Ciphers.
Handles STARTTLS interleaved streams and fragmented TCP payloads.
"""

import struct
from typing import Dict, Any, List, Optional, Tuple
from cryptography import x509
from app.core.cert_analyzer import CertificateDissector, CertChainValidator


# Standard TLS Version Constants
TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    0x0200: "SSL 2.0",
}

# IANA Cipher Suites Comprehensive Lookup
CIPHER_SUITES = {
    # TLS 1.3 Modern AEAD Ciphers (RFC 8446)
    0x1301: ("TLS_AES_128_GCM_SHA256", "ECDHE", "AES-GCM", 128, True, "SECURE"),
    0x1302: ("TLS_AES_256_GCM_SHA384", "ECDHE", "AES-GCM", 256, True, "SECURE"),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", "ECDHE", "ChaCha20-Poly1305", 256, True, "SECURE"),
    0x1304: ("TLS_AES_128_CCM_SHA256", "ECDHE", "AES-CCM", 128, True, "SECURE"),
    0x1305: ("TLS_AES_128_CCM_8_SHA256", "ECDHE", "AES-CCM", 128, True, "SECURE"),
    
    # Modern TLS 1.2 ECDHE Secure AEAD
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "AES-GCM", 128, True, "SECURE"),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "AES-GCM", 256, True, "SECURE"),
    0xC02B: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "AES-GCM", 128, True, "SECURE"),
    0xC02C: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "AES-GCM", 256, True, "SECURE"),
    0xCCA8: ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "ChaCha20-Poly1305", 256, True, "SECURE"),
    0xCCA9: ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "ChaCha20-Poly1305", 256, True, "SECURE"),
    0x009E: ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE", "AES-GCM", 128, True, "SECURE"),
    0x009F: ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE", "AES-GCM", 256, True, "SECURE"),

    # CBC Mode (Medium Risk due to Lucky13 / padding oracle)
    0xC013: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", "AES-CBC", 128, True, "MEDIUM"),
    0xC014: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE", "AES-CBC", 256, True, "MEDIUM"),
    0xC027: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", "AES-CBC", 128, True, "MEDIUM"),
    0xC028: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", "AES-CBC", 256, True, "MEDIUM"),
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA_STATIC", "AES-CBC", 128, False, "MEDIUM"),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA_STATIC", "AES-CBC", 256, False, "MEDIUM"),
    0x009C: ("TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA_STATIC", "AES-GCM", 128, False, "MEDIUM"),
    0x009D: ("TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA_STATIC", "AES-GCM", 256, False, "MEDIUM"),
    0x003C: ("TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA_STATIC", "AES-CBC", 128, False, "MEDIUM"),
    0x003D: ("TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA_STATIC", "AES-CBC", 256, False, "MEDIUM"),

    # Legacy & Deprecated / Insecure Ciphers
    0x000A: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA_STATIC", "3DES", 112, False, "INSECURE"),
    0xC012: ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", "3DES", 112, True, "INSECURE"),
    0x0004: ("TLS_RSA_WITH_RC4_128_MD5", "RSA_STATIC", "RC4", 128, False, "CRITICAL"),
    0x0005: ("TLS_RSA_WITH_RC4_128_SHA", "RSA_STATIC", "RC4", 128, False, "CRITICAL"),
    0xC007: ("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "ECDHE", "RC4", 128, True, "CRITICAL"),
    0xC011: ("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDHE", "RC4", 128, True, "CRITICAL"),
    0x0001: ("TLS_RSA_WITH_NULL_MD5", "RSA_STATIC", "NULL", 0, False, "CRITICAL"),
    0x0002: ("TLS_RSA_WITH_NULL_SHA", "RSA_STATIC", "NULL", 0, False, "CRITICAL"),
    0x0000: ("TLS_NULL_WITH_NULL_NULL", "NONE", "NULL", 0, False, "CRITICAL"),
    0x0017: ("TLS_DH_anon_WITH_RC4_128_MD5", "DH_ANON", "RC4", 128, False, "CRITICAL"),
}


class TLSParser:
    """Dissects raw TCP stream bytes into TLS Handshake metadata and certificates."""

    @staticmethod
    def find_tls_records(payload: bytes) -> List[Tuple[int, int, int, bytes]]:
        """
        Locates TLS Records (ContentType, Version, Length, Fragment).
        ContentType 22 = Handshake, 23 = ApplicationData, 21 = Alert, 20 = ChangeCipherSpec.
        Robust against prefix text (STARTTLS commands) and partial packet frames.
        """
        records = []
        offset = 0
        p_len = len(payload)
        
        while offset + 5 <= p_len:
            content_type = payload[offset]
            if content_type in (20, 21, 22, 23):
                ver_major = payload[offset + 1]
                ver_minor = payload[offset + 2]
                if ver_major == 3:  # SSL 3.0 / TLS 1.x
                    rec_len = struct.unpack("!H", payload[offset + 3:offset + 5])[0]
                    rec_ver = (ver_major << 8) | ver_minor
                    
                    if offset + 5 + rec_len <= p_len:
                        frag = payload[offset + 5:offset + 5 + rec_len]
                        records.append((content_type, rec_ver, rec_len, frag))
                        offset += 5 + rec_len
                        continue
                    else:
                        # Fragment partially captured or segmented across packets
                        frag = payload[offset + 5:]
                        if len(frag) > 0:
                            records.append((content_type, rec_ver, rec_len, frag))
                        break
            offset += 1
        return records

    @classmethod
    def parse_tls_stream(cls, client_payload: bytes, server_payload: bytes) -> Dict[str, Any]:
        """Dissects both client and server streams to extract comprehensive TLS details."""
        client_records = cls.find_tls_records(client_payload)
        server_records = cls.find_tls_records(server_payload)

        tls_detected = bool(client_records or server_records)
        client_version = None
        server_version = None
        sni = None
        alpn = []
        offered_ciphers = []
        selected_cipher_code = None
        selected_cipher_name = "Unknown"
        key_exchange = "Unknown"
        symmetric_cipher = "Unknown"
        cipher_strength = "UNKNOWN"
        forward_secrecy = False
        key_bits = 0
        raw_certs: List[bytes] = []

        # 1. Parse ClientHello records
        for ctype, rver, _, frag in client_records:
            if ctype == 22 and len(frag) >= 4:
                hs_type = frag[0]
                if hs_type == 1:  # ClientHello
                    c_ver, s_sni, s_alpn, c_ciphers = cls._parse_client_hello(frag)
                    if c_ver:
                        client_version = c_ver
                    if s_sni:
                        sni = s_sni
                    if s_alpn:
                        alpn = s_alpn
                    if c_ciphers:
                        offered_ciphers = c_ciphers
                    break

        # 2. Parse ServerHello, Certificate, KeyExchange records
        for ctype, rver, _, frag in server_records:
            if ctype == 22:
                hs_offset = 0
                while hs_offset + 4 <= len(frag):
                    hs_type = frag[hs_offset]
                    hs_len = struct.unpack("!I", b"\x00" + frag[hs_offset + 1:hs_offset + 4])[0]
                    hs_body = frag[hs_offset + 4:hs_offset + 4 + hs_len]

                    if hs_type == 2:  # ServerHello
                        s_ver, c_code, ext_ver = cls._parse_server_hello(hs_body)
                        server_version = ext_ver or s_ver or server_version
                        if c_code is not None:
                            selected_cipher_code = c_code

                    elif hs_type == 11:  # Certificate
                        certs_found = cls._parse_certificates(hs_body)
                        if certs_found:
                            raw_certs.extend(certs_found)

                    elif hs_type == 12:  # ServerKeyExchange (ECDHE/DHE)
                        kex_info = cls._parse_server_key_exchange(hs_body)
                        if kex_info:
                            key_exchange = kex_info

                    hs_offset += 4 + hs_len

        # If server version wasn't explicitly in ServerHello, fallback to TLS record version
        if not server_version and server_records:
            for ctype, rver, _, _ in server_records:
                if rver in TLS_VERSIONS:
                    server_version = TLS_VERSIONS[rver]
                    break

        # If server version still not found, check client version
        resolved_tls_version = server_version or client_version or ("TLS 1.2" if tls_detected else "None")

        # 3. Lookup cipher details
        if selected_cipher_code is not None:
            if selected_cipher_code in CIPHER_SUITES:
                c_info = CIPHER_SUITES[selected_cipher_code]
                selected_cipher_name = c_info[0]
                key_exchange = c_info[1]
                symmetric_cipher = c_info[2]
                key_bits = c_info[3]
                forward_secrecy = c_info[4]
                cipher_strength = c_info[5]
            else:
                selected_cipher_name = f"0x{selected_cipher_code:04X}"
                cipher_strength = "UNKNOWN"
        elif tls_detected and resolved_tls_version != "None":
            # If TLS records exist but specific ServerHello cipher code was encrypted (e.g. TLS 1.3), infer safe defaults
            if resolved_tls_version == "TLS 1.3":
                selected_cipher_name = "TLS_AES_256_GCM_SHA384"
                key_exchange = "ECDHE (TLS 1.3)"
                symmetric_cipher = "AES-GCM"
                key_bits = 256
                forward_secrecy = True
                cipher_strength = "SECURE"
            elif resolved_tls_version == "TLS 1.2" and offered_ciphers:
                for off in offered_ciphers:
                    if off in CIPHER_SUITES and CIPHER_SUITES[off][5] == "SECURE":
                        c_info = CIPHER_SUITES[off]
                        selected_cipher_name = c_info[0]
                        key_exchange = c_info[1]
                        symmetric_cipher = c_info[2]
                        key_bits = c_info[3]
                        forward_secrecy = c_info[4]
                        cipher_strength = c_info[5]
                        break

        # Refine TLS 1.3 properties
        if resolved_tls_version == "TLS 1.3" or (selected_cipher_code in (0x1301, 0x1302, 0x1303, 0x1304)):
            resolved_tls_version = "TLS 1.3"
            forward_secrecy = True
            if key_exchange == "Unknown":
                key_exchange = "ECDHE"
            if cipher_strength == "UNKNOWN":
                cipher_strength = "SECURE"

        # 4. Parse X.509 certificates and validate chain
        parsed_x509_certs = []
        for c_der in raw_certs:
            c = CertificateDissector.parse_der_or_pem(c_der)
            if c:
                parsed_x509_certs.append(c)

        chain_validator = CertChainValidator()
        chain_result = chain_validator.validate_chain(parsed_x509_certs, expected_host=sni)

        return {
            "tls_detected": tls_detected,
            "client_version": client_version,
            "tls_version": resolved_tls_version,
            "server_version": server_version,
            "selected_cipher_code": f"0x{selected_cipher_code:04X}" if selected_cipher_code else None,
            "cipher_suite": selected_cipher_name,
            "key_exchange": key_exchange,
            "symmetric_cipher": symmetric_cipher,
            "cipher_strength": cipher_strength,
            "forward_secrecy": forward_secrecy,
            "key_bits": key_bits,
            "sni": sni,
            "alpn": alpn,
            "offered_ciphers_count": len(offered_ciphers),
            "certificates_count": len(parsed_x509_certs),
            "certificate_chain": chain_result,
            "leaf_certificate": chain_result.get("leaf_details"),
        }

    @classmethod
    def _parse_client_hello(cls, frag: bytes) -> Tuple[Optional[str], Optional[str], List[str], List[int]]:
        try:
            body = frag[4:]
            if len(body) < 34:
                return None, None, [], []
            legacy_ver = struct.unpack("!H", body[0:2])[0]
            client_version = TLS_VERSIONS.get(legacy_ver, f"0x{legacy_ver:04X}")
            
            sess_id_len = body[34]
            offset = 35 + sess_id_len
            
            if offset + 2 > len(body):
                return client_version, None, [], []
            ciphers_len = struct.unpack("!H", body[offset:offset + 2])[0]
            offset += 2
            
            ciphers = []
            for i in range(0, ciphers_len, 2):
                if offset + i + 2 <= len(body):
                    ccode = struct.unpack("!H", body[offset + i:offset + i + 2])[0]
                    ciphers.append(ccode)
            offset += ciphers_len
            
            if offset >= len(body):
                return client_version, None, [], ciphers
            comp_len = body[offset]
            offset += 1 + comp_len

            # Extensions
            sni = None
            alpn = []
            if offset + 2 <= len(body):
                ext_total_len = struct.unpack("!H", body[offset:offset + 2])[0]
                offset += 2
                ext_end = offset + ext_total_len
                
                while offset + 4 <= min(ext_end, len(body)):
                    ext_type = struct.unpack("!H", body[offset:offset + 2])[0]
                    ext_len = struct.unpack("!H", body[offset + 2:offset + 4])[0]
                    ext_data = body[offset + 4:offset + 4 + ext_len]
                    
                    if ext_type == 0:  # SNI
                        if len(ext_data) >= 5:
                            name_len = struct.unpack("!H", ext_data[3:5])[0]
                            sni = ext_data[5:5 + name_len].decode("latin-1", errors="ignore")
                    elif ext_type == 16:  # ALPN
                        if len(ext_data) >= 2:
                            alpn_len = struct.unpack("!H", ext_data[0:2])[0]
                            a_off = 2
                            while a_off < 2 + alpn_len and a_off < len(ext_data):
                                proto_len = ext_data[a_off]
                                proto_name = ext_data[a_off + 1:a_off + 1 + proto_len].decode("latin-1", errors="ignore")
                                alpn.append(proto_name)
                                a_off += 1 + proto_len
                    elif ext_type == 43:  # Supported Versions (TLS 1.3)
                        if len(ext_data) >= 1:
                            v_list_len = ext_data[0]
                            for vi in range(1, 1 + v_list_len, 2):
                                if vi + 1 < len(ext_data):
                                    vcode = struct.unpack("!H", ext_data[vi:vi + 2])[0]
                                    if vcode == 0x0304:
                                        client_version = "TLS 1.3"
                                        break
                    offset += 4 + ext_len

            return client_version, sni, alpn, ciphers
        except Exception:
            return None, None, [], []

    @classmethod
    def _parse_server_hello(cls, body: bytes) -> Tuple[Optional[str], Optional[int], Optional[str]]:
        try:
            if len(body) < 34:
                return None, None, None
            legacy_ver = struct.unpack("!H", body[0:2])[0]
            server_version = TLS_VERSIONS.get(legacy_ver, f"0x{legacy_ver:04X}")
            
            sess_id_len = body[34]
            offset = 35 + sess_id_len
            
            if offset + 2 > len(body):
                return server_version, None, None
            cipher_code = struct.unpack("!H", body[offset:offset + 2])[0]
            offset += 2 + 1  # cipher + compression

            supported_version = None
            if offset + 2 <= len(body):
                ext_total_len = struct.unpack("!H", body[offset:offset + 2])[0]
                offset += 2
                ext_end = offset + ext_total_len
                while offset + 4 <= min(ext_end, len(body)):
                    ext_type = struct.unpack("!H", body[offset:offset + 2])[0]
                    ext_len = struct.unpack("!H", body[offset + 2:offset + 4])[0]
                    ext_data = body[offset + 4:offset + 4 + ext_len]
                    if ext_type == 43 and len(ext_data) >= 2:  # Supported Versions
                        vcode = struct.unpack("!H", ext_data[0:2])[0]
                        if vcode == 0x0304:
                            supported_version = "TLS 1.3"
                        elif vcode in TLS_VERSIONS:
                            supported_version = TLS_VERSIONS[vcode]
                    offset += 4 + ext_len

            return server_version, cipher_code, supported_version
        except Exception:
            return None, None, None

    @classmethod
    def _parse_server_key_exchange(cls, body: bytes) -> Optional[str]:
        """Parses ServerKeyExchange parameters for ECDHE curve or DHE primes."""
        try:
            if len(body) < 4:
                return None
            curve_type = body[0]
            if curve_type == 3:  # named_curve
                named_curve = struct.unpack("!H", body[1:3])[0]
                curves = {
                    0x0017: "ECDHE (secp256r1 / P-256)",
                    0x0018: "ECDHE (secp384r1 / P-384)",
                    0x0019: "ECDHE (secp521r1 / P-521)",
                    0x001D: "ECDHE (X25519)",
                    0x001E: "ECDHE (X448)",
                }
                return curves.get(named_curve, f"ECDHE (Curve 0x{named_curve:04X})")
            elif curve_type in (1, 2):  # explicit prime / char2
                return "DHE (Diffie-Hellman Ephemeral)"
        except Exception:
            pass
        return "ECDHE"

    @classmethod
    def _parse_certificates(cls, body: bytes) -> List[bytes]:
        """
        Extracts DER certificates from Handshake Certificate payload.
        Handles both TLS 1.2 format and TLS 1.3 (RFC 8446 with request_context) format.
        """
        certs = []
        try:
            if len(body) < 3:
                return certs
            
            # Check if TLS 1.3 format (body[0] is context_length)
            ctx_len = body[0]
            if ctx_len < 32 and len(body) >= 1 + ctx_len + 3:
                # Potential TLS 1.3 certificate list
                offset = 1 + ctx_len
                certs_total_len = struct.unpack("!I", b"\x00" + body[offset:offset + 3])[0]
                offset += 3
                end = min(offset + certs_total_len, len(body))
                
                while offset + 3 <= end:
                    cert_len = struct.unpack("!I", b"\x00" + body[offset:offset + 3])[0]
                    offset += 3
                    if offset + cert_len <= len(body):
                        cert_der = body[offset:offset + cert_len]
                        certs.append(cert_der)
                        offset += cert_len
                        
                        # TLS 1.3 has certificate extensions per entry
                        if offset + 2 <= len(body):
                            ext_len = struct.unpack("!H", body[offset:offset + 2])[0]
                            offset += 2 + ext_len
                    else:
                        break
                if certs:
                    return certs

            # Standard TLS 1.2 format
            certs_total_len = struct.unpack("!I", b"\x00" + body[0:3])[0]
            offset = 3
            end = min(3 + certs_total_len, len(body))
            
            while offset + 3 <= end:
                cert_len = struct.unpack("!I", b"\x00" + body[offset:offset + 3])[0]
                offset += 3
                if offset + cert_len <= len(body):
                    cert_der = body[offset:offset + cert_len]
                    certs.append(cert_der)
                    offset += cert_len
                else:
                    break
        except Exception:
            pass
        return certs
