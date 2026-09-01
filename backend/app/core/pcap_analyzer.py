"""
SecureMailScope - Core PCAP & TCP Stream Reassembly Engine
Reassembles bidirectional TCP flows with sequence-aware defragmentation,
analyzes email protocols, TLS handshakes, and certificates.
"""

import os
import time
from collections import defaultdict
from typing import List, Dict, Any, Optional
from scapy.all import rdpcap, IP, IPv6, TCP, Raw

from app.core.protocol_detector import ProtocolDetector, ProtocolType
from app.core.tls_parser import TLSParser
from app.core.cert_analyzer import CertificateDissector, CertChainValidator
from app.core.rules_engine import RulesEngine
from app.core.behavioral import BehavioralFeatureExtractor
from app.core.ml_engine import MLEngine


class StreamSession:
    """Represents a single reconstructed bidirectional TCP stream with sequence sorting."""

    def __init__(self, stream_id: str, client_ip: str, client_port: int, server_ip: str, server_port: int):
        self.stream_id = stream_id
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port
        
        self.client_packets = []
        self.server_packets = []
        
        self.packet_timestamps = []
        self.packet_sizes = []
        self.syn_seen = False
        self.fin_seen = False
        self.rst_seen = False
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

    def add_packet(self, pkt, is_client_to_server: bool):
        ts = float(pkt.time)
        if self.start_time is None or ts < self.start_time:
            self.start_time = ts
        if self.end_time is None or ts > self.end_time:
            self.end_time = ts

        self.packet_timestamps.append(ts)
        self.packet_sizes.append(len(pkt))

        tcp = pkt[TCP]
        if tcp.flags.S:
            self.syn_seen = True
        if tcp.flags.F:
            self.fin_seen = True
        if tcp.flags.R:
            self.rst_seen = True

        if is_client_to_server:
            self.client_packets.append(pkt)
        else:
            self.server_packets.append(pkt)

    def get_reassembled_payloads(self) -> (bytes, bytes):
        """
        Sorts directional packets by TCP sequence numbers and reassembles contiguous streams,
        handling TCP retransmissions, duplicate ACKs, and out-of-order packets.
        """
        def reassemble_flow(pkts) -> bytes:
            if not pkts:
                return b""
            
            # Sort by TCP sequence number and timestamp
            sorted_pkts = sorted(pkts, key=lambda p: (p[TCP].seq, float(p.time)))
            stream_bytes = bytearray()
            last_seq = None

            for pkt in sorted_pkts:
                if Raw in pkt:
                    data = bytes(pkt[Raw].load)
                    seq = pkt[TCP].seq
                    
                    if last_seq is None:
                        stream_bytes.extend(data)
                        last_seq = seq + len(data)
                    else:
                        if seq >= last_seq:
                            # Contiguous or forward packet
                            stream_bytes.extend(data)
                            last_seq = seq + len(data)
                        elif seq + len(data) > last_seq:
                            # Overlapping retransmission / partial update
                            offset = last_seq - seq
                            stream_bytes.extend(data[offset:])
                            last_seq = seq + len(data)
            return bytes(stream_bytes)

        return reassemble_flow(self.client_packets), reassemble_flow(self.server_packets)


class PCAPAnalyzer:
    """Dissects PCAP/PCAPNG files, reassembles email TCP streams, and evaluates posture."""

    def __init__(self, ml_engine: Optional[MLEngine] = None, rules_engine: Optional[RulesEngine] = None):
        self.ml_engine = ml_engine or MLEngine()
        self.rules_engine = rules_engine or RulesEngine()

    def analyze_pcap(
        self,
        pcap_path: str,
        progress_callback=None
    ) -> Dict[str, Any]:
        """Analyzes a PCAP file and returns comprehensive session and overall assessment data."""
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        if progress_callback:
            progress_callback(10, "Reading network packets from capture...")

        packets = rdpcap(pcap_path)
        total_packets = len(packets)

        if progress_callback:
            progress_callback(30, f"Reassembling TCP streams from {total_packets} packets...")

        # Group packets into 4-tuple TCP streams
        streams: Dict[str, StreamSession] = {}
        EMAIL_PORTS = {25, 587, 465, 143, 993, 110, 995}

        for pkt in packets:
            if not pkt.haslayer(TCP):
                continue
            
            ip_layer = pkt[IP] if pkt.haslayer(IP) else (pkt[IPv6] if pkt.haslayer(IPv6) else None)
            if not ip_layer:
                continue

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            tcp_layer = pkt[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport

            # Determine client vs server direction
            if dst_port in EMAIL_PORTS:
                client_ip, client_port = src_ip, src_port
                server_ip, server_port = dst_ip, dst_port
                is_c2s = True
            elif src_port in EMAIL_PORTS:
                client_ip, client_port = dst_ip, dst_port
                server_ip, server_port = src_ip, src_port
                is_c2s = False
            else:
                if dst_port < src_port:
                    client_ip, client_port = src_ip, src_port
                    server_ip, server_port = dst_ip, dst_port
                    is_c2s = True
                else:
                    client_ip, client_port = dst_ip, dst_port
                    server_ip, server_port = src_ip, src_port
                    is_c2s = False

            stream_key = f"{client_ip}:{client_port}->{server_ip}:{server_port}"
            if stream_key not in streams:
                streams[stream_key] = StreamSession(
                    stream_id=f"stream-{len(streams)+1:03d}",
                    client_ip=client_ip,
                    client_port=client_port,
                    server_ip=server_ip,
                    server_port=server_port
                )

            streams[stream_key].add_packet(pkt, is_c2s)

        if progress_callback:
            progress_callback(55, f"Dissecting email protocols and TLS handshakes in {len(streams)} streams...")

        # Process each stream
        analyzed_sessions = []
        all_findings = []
        all_certificates = []

        for idx, (skey, session) in enumerate(streams.items()):
            c_payload, s_payload = session.get_reassembled_payloads()

            # 1. TLS analysis
            tls_info = TLSParser.parse_tls_stream(c_payload, s_payload)

            # 2. Protocol detection (with TLS state awareness)
            proto_info = ProtocolDetector.identify_protocol_and_tls_mode(
                client_port=session.client_port,
                server_port=session.server_port,
                client_payload=c_payload,
                server_payload=s_payload,
                tls_detected=tls_info.get("tls_detected", False)
            )

            # 3. Behavioral feature extraction
            behavioral_features = BehavioralFeatureExtractor.extract_features(
                packet_sizes=session.packet_sizes,
                packet_timestamps=session.packet_timestamps,
                client_bytes=len(c_payload),
                server_bytes=len(s_payload),
                start_time=session.start_time or 0.0,
                end_time=session.end_time or 0.0
            )

            # Reconcile STARTTLS state with TLS Handshake detection
            starttls_upgraded = proto_info["starttls_upgraded"] and tls_info["tls_detected"]
            if proto_info["starttls_accepted"] and tls_info["tls_detected"]:
                starttls_upgraded = True

            session_meta = {
                "stream_id": session.stream_id,
                "protocol": proto_info["protocol"],
                "is_implicit_tls": proto_info["is_implicit_tls"],
                "starttls_offered": proto_info["starttls_offered"],
                "starttls_requested": proto_info["starttls_requested"],
                "starttls_accepted": proto_info["starttls_accepted"],
                "starttls_upgraded": starttls_upgraded,
                "has_plaintext_credentials": proto_info["has_plaintext_credentials"],
                "tls_version": tls_info["tls_version"],
                "cipher_suite": tls_info["cipher_suite"],
                "cipher_strength": tls_info["cipher_strength"],
                "key_exchange": tls_info["key_exchange"],
                "forward_secrecy": tls_info["forward_secrecy"],
                "key_bits": tls_info["key_bits"],
                "certificate_chain": tls_info["certificate_chain"],
                "leaf_certificate": tls_info["leaf_certificate"],
                "client_ip": session.client_ip,
                "server_ip": session.server_ip,
                "client_port": session.client_port,
                "server_port": session.server_port,
                "duration": behavioral_features["duration"],
                "packet_count": len(session.packet_sizes),
                "byte_count": sum(session.packet_sizes),
                "sni": tls_info["sni"],
            }

            rule_result = self.rules_engine.evaluate_session(session_meta)
            session_findings = rule_result["findings"]
            all_findings.extend(session_findings)

            # AI Evaluation: Random Forest (Crypto Risk) + Isolation Forest (Behavioral Anomaly)
            ml_result = self.ml_engine.evaluate_session(
                session_meta=session_meta,
                behavioral_features=behavioral_features
            )

            final_risk_score = rule_result["risk_score"]
            final_risk_level = rule_result["risk_level"]

            session_record = {
                **session_meta,
                "findings_count": len(session_findings),
                "risk_score": final_risk_score,
                "risk_level": final_risk_level,
                "rule_risk_level": rule_result["risk_level"],
                "rule_risk_score": rule_result["risk_score"],
                "rf_predicted_risk": ml_result["rf_risk_class"],
                "rf_confidence": ml_result["rf_confidence"],
                "is_anomalous": ml_result["is_anomalous"],
                "anomaly_score": ml_result["anomaly_score"],
                "behavioral_summary": behavioral_features,
            }

            analyzed_sessions.append(session_record)

            # Collect certificates
            if tls_info.get("leaf_certificate"):
                cert_data = tls_info["leaf_certificate"]
                cert_data["session_id"] = session.stream_id
                cert_data["chain_status"] = tls_info["certificate_chain"]["status"]
                cert_data["chain_valid"] = tls_info["certificate_chain"]["is_valid"]
                cert_data["chain_hierarchy"] = tls_info["certificate_chain"]["hierarchy"]
                all_certificates.append(cert_data)

        if progress_callback:
            progress_callback(85, "Calculating posture score & security aggregates...")

        # Aggregate overall assessment
        overall_assessment = self.rules_engine.calculate_overall_posture(
            sessions=analyzed_sessions,
            all_findings=all_findings
        )

        if progress_callback:
            progress_callback(100, "Analysis complete.")

        return {
            "total_packets": total_packets,
            "total_sessions": len(analyzed_sessions),
            "sessions": analyzed_sessions,
            "findings": all_findings,
            "certificates": all_certificates,
            "assessment": overall_assessment,
            "ml_summary": self.ml_engine.summarize_analysis(analyzed_sessions)
        }
