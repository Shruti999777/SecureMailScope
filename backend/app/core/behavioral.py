"""
SecureMailScope - Behavioral Traffic Shape Feature Extractor
Extracts statistical and temporal features from TCP streams for Isolation Forest anomaly detection.
"""

import numpy as np
from typing import List, Dict, Any


class BehavioralFeatureExtractor:
    """Extracts non-cryptographic, behavioral session shape features."""

    @classmethod
    def extract_features(
        cls,
        packet_sizes: List[int],
        packet_timestamps: List[float],
        client_bytes: int,
        server_bytes: int,
        start_time: float,
        end_time: float
    ) -> Dict[str, Any]:
        pkt_count = len(packet_sizes)
        total_bytes = sum(packet_sizes) if packet_sizes else 0
        duration = max(0.001, end_time - start_time) if end_time >= start_time else 0.001

        # Packet size statistics
        if pkt_count > 0:
            mean_pkt_size = float(np.mean(packet_sizes))
            std_pkt_size = float(np.std(packet_sizes)) if pkt_count > 1 else 0.0
        else:
            mean_pkt_size = 0.0
            std_pkt_size = 0.0

        # Inter-arrival time statistics
        if len(packet_timestamps) > 1:
            sorted_ts = sorted(packet_timestamps)
            iats = np.diff(sorted_ts)
            mean_iat = float(np.mean(iats))
            std_iat = float(np.std(iats)) if len(iats) > 1 else 0.0
            
            # Burstiness: fraction of packets arriving in fastest 20% interval
            fast_thresh = np.percentile(iats, 20) if len(iats) >= 5 else 0.01
            burst_ratio = float(np.sum(iats <= fast_thresh) / len(iats))
        else:
            mean_iat = 0.0
            std_iat = 0.0
            burst_ratio = 0.0

        # Client-to-server ratio
        c2s_ratio = float(client_bytes / (server_bytes + 1))
        bytes_per_second = float(total_bytes / duration)
        packets_per_second = float(pkt_count / duration)

        return {
            "packet_count": pkt_count,
            "byte_count": total_bytes,
            "duration": round(duration, 4),
            "client_bytes": client_bytes,
            "server_bytes": server_bytes,
            "client_to_server_ratio": round(c2s_ratio, 3),
            "mean_packet_size": round(mean_pkt_size, 2),
            "std_packet_size": round(std_pkt_size, 2),
            "mean_inter_arrival_time": round(mean_iat, 5),
            "std_inter_arrival_time": round(std_iat, 5),
            "burst_ratio": round(burst_ratio, 3),
            "bytes_per_second": round(bytes_per_second, 2),
            "packets_per_second": round(packets_per_second, 2),
        }
