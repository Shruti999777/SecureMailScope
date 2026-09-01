"""
SecureMailScope - Protocol Identification & Email Flow Dissector
Identifies SMTP, IMAP, POP3, SMTPS, IMAPS, POP3S, and tracks STARTTLS transitions.
"""

import re
from typing import Dict, Any, List, Optional, Tuple


class ProtocolType:
    SMTP = "SMTP"
    SMTPS = "SMTPS"
    IMAP = "IMAP"
    IMAPS = "IMAPS"
    POP3 = "POP3"
    POP3S = "POP3S"
    UNKNOWN = "UNKNOWN"


class ProtocolDetector:
    """Dissects TCP application payloads to identify email protocols and STARTTLS state."""

    PORT_MAP = {
        25: (ProtocolType.SMTP, False),
        587: (ProtocolType.SMTP, False),   # Submission (STARTTLS)
        465: (ProtocolType.SMTPS, True),   # Implicit TLS
        143: (ProtocolType.IMAP, False),   # IMAP STARTTLS
        993: (ProtocolType.IMAPS, True),   # Implicit TLS
        110: (ProtocolType.POP3, False),   # POP3 STLS
        995: (ProtocolType.POP3S, True),   # Implicit TLS
    }

    SMTP_BANNER_REGEX = re.compile(rb"^220[- ].*", re.IGNORECASE)
    SMTP_COMMANDS = [b"EHLO", b"HELO", b"MAIL FROM:", b"RCPT TO:", b"STARTTLS", b"AUTH LOGIN", b"AUTH PLAIN", b"QUIT", b"RSET", b"DATA"]
    
    IMAP_BANNER_REGEX = re.compile(rb"^\* OK .*", re.IGNORECASE)
    IMAP_COMMANDS = [b"CAPABILITY", b"STARTTLS", b"LOGIN", b"AUTHENTICATE", b"SELECT", b"FETCH", b"LOGOUT", b"NAMESPACE"]

    POP3_BANNER_REGEX = re.compile(rb"^\+OK .*", re.IGNORECASE)
    POP3_COMMANDS = [b"USER", b"PASS", b"STLS", b"AUTH", b"STAT", b"LIST", b"RETR", b"DELE", b"QUIT", b"CAPA"]

    @classmethod
    def identify_protocol_and_tls_mode(
        cls,
        client_port: int,
        server_port: int,
        client_payload: bytes,
        server_payload: bytes,
        tls_detected: bool = False
    ) -> Dict[str, Any]:
        """
        Determines protocol, implicit vs STARTTLS, and extracts plaintext commands.
        """
        port = server_port if server_port in cls.PORT_MAP else client_port
        is_implicit_by_port = False
        proto_hint = ProtocolType.UNKNOWN

        if port in cls.PORT_MAP:
            proto_hint, is_implicit_by_port = cls.PORT_MAP[port]

        # Check if first payload byte is TLS Record Header (0x16 0x03 0x01/02/03)
        starts_with_tls_client = len(client_payload) >= 3 and client_payload[0] == 0x16 and client_payload[1] == 0x03
        starts_with_tls_server = len(server_payload) >= 3 and server_payload[0] == 0x16 and server_payload[1] == 0x03

        is_implicit_tls = is_implicit_by_port or (starts_with_tls_client and starts_with_tls_server)

        # Inspect plaintext payloads for banners and commands
        detected_protocol = proto_hint
        starttls_offered = False
        starttls_requested = False
        starttls_accepted = False
        plaintext_credentials_found = False
        extracted_commands = []

        combined_text = (client_payload + b"\n" + server_payload).decode("latin-1", errors="ignore")

        # SMTP heuristics
        if cls.SMTP_BANNER_REGEX.search(server_payload) or any(cmd in client_payload.upper() for cmd in cls.SMTP_COMMANDS):
            if not is_implicit_tls:
                detected_protocol = ProtocolType.SMTP
            if b"STARTTLS" in server_payload.upper() or "STARTTLS" in combined_text.upper():
                starttls_offered = True
            if b"STARTTLS" in client_payload.upper() or "STARTTLS\r\n" in combined_text.upper():
                starttls_requested = True
            if b"220 2.0.0 Ready to start TLS" in server_payload or b"220 2.0.0" in server_payload or (b"220" in server_payload and starttls_requested):
                starttls_accepted = True

        # IMAP heuristics
        elif cls.IMAP_BANNER_REGEX.search(server_payload) or any(cmd in client_payload.upper() for cmd in cls.IMAP_COMMANDS):
            if not is_implicit_tls:
                detected_protocol = ProtocolType.IMAP
            if "STARTTLS" in combined_text.upper():
                starttls_offered = True
                if "STARTTLS" in client_payload.decode("latin-1", errors="ignore").upper():
                    starttls_requested = True
            if "OK Begin TLS" in combined_text or "OK start TLS" in combined_text or ("OK" in combined_text and starttls_requested):
                starttls_accepted = True

        # POP3 heuristics
        elif cls.POP3_BANNER_REGEX.search(server_payload) or any(cmd in client_payload.upper() for cmd in cls.POP3_COMMANDS):
            if not is_implicit_tls:
                detected_protocol = ProtocolType.POP3
            if "STLS" in combined_text.upper():
                starttls_offered = True
                if "STLS" in client_payload.decode("latin-1", errors="ignore").upper():
                    starttls_requested = True
            if "+OK Begin TLS" in combined_text or "+OK" in combined_text and starttls_requested:
                starttls_accepted = True

        # Plaintext credential leaks check in unencrypted session
        if not is_implicit_tls and not (starttls_accepted and tls_detected):
            if re.search(r"(AUTH\s+PLAIN|AUTH\s+LOGIN|USER\s+\S+|PASS\s+\S+|\bLOGIN\s+\S+\s+\S+)", combined_text, re.IGNORECASE):
                plaintext_credentials_found = True

        # Extract commands
        for line in combined_text.splitlines():
            line_str = line.strip()
            if line_str and len(line_str) < 100:
                if any(line_str.upper().startswith(c) for c in ["EHLO", "HELO", "MAIL", "RCPT", "STARTTLS", "STLS", "USER", "PASS", "AUTH", "CAPA", "LOGIN", "SELECT", "FETCH", "QUIT"]):
                    extracted_commands.append(line_str)

        # Refine SMTPS/IMAPS/POP3S names
        if is_implicit_tls:
            if detected_protocol == ProtocolType.SMTP or port in [25, 465, 587]:
                detected_protocol = ProtocolType.SMTPS
            elif detected_protocol == ProtocolType.IMAP or port in [143, 993]:
                detected_protocol = ProtocolType.IMAPS
            elif detected_protocol == ProtocolType.POP3 or port in [110, 995]:
                detected_protocol = ProtocolType.POP3S

        starttls_upgraded = (starttls_accepted or (starttls_requested and b"\x16\x03" in client_payload)) and tls_detected

        return {
            "protocol": detected_protocol,
            "is_implicit_tls": is_implicit_tls,
            "starttls_offered": starttls_offered,
            "starttls_requested": starttls_requested,
            "starttls_accepted": starttls_accepted,
            "starttls_upgraded": starttls_upgraded,
            "has_plaintext_credentials": plaintext_credentials_found,
            "extracted_commands": extracted_commands[:15],
            "server_port": server_port,
            "client_port": client_port,
        }
