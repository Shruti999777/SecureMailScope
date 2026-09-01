"""
SecureMailScope - Dual-Model Machine Learning Engine
- Random Forest: Trained on cryptographic posture features to classify risk.
- Isolation Forest: Trained on behavioral session shape features to detect anomalies.
"""

import os
import joblib
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support

from app.config import settings


class MLEngine:
    """Manages AI model inference, feature mapping, and evaluations."""

    RF_CLASSES = ["SECURE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def __init__(self, models_dir: Optional[Path] = None):
        self.models_dir = models_dir or settings.MODELS_DIR
        self.rf_model_path = self.models_dir / "random_forest_risk.joblib"
        self.if_model_path = self.models_dir / "isolation_forest_behavioral.joblib"
        
        self.rf_model: Optional[RandomForestClassifier] = None
        self.if_model: Optional[IsolationForest] = None
        
        self._load_or_train_baseline_models()

    def _load_or_train_baseline_models(self):
        """Loads saved models or initializes and trains high-quality baseline models."""
        try:
            if self.rf_model_path.exists():
                self.rf_model = joblib.load(self.rf_model_path)
            if self.if_model_path.exists():
                self.if_model = joblib.load(self.if_model_path)
        except Exception:
            pass

        if self.rf_model is None or self.if_model is None:
            self._train_and_save_baseline_models()

    @classmethod
    def vectorize_crypto_features(cls, session_meta: Dict[str, Any]) -> List[float]:
        """
        Converts session cryptographic properties into a numeric feature vector.
        Features (9 dimensions):
        1. TLS Version (0=None, 1=SSL3, 2=TLS1.0, 3=TLS1.1, 4=TLS1.2, 5=TLS1.3)
        2. Cipher Strength (0=None/Null, 1=Insecure, 2=Weak, 3=Medium, 4=Secure)
        3. Key Exchange (0=None, 1=Static RSA, 2=DHE, 3=ECDHE)
        4. Forward Secrecy (0=No, 1=Yes)
        5. Cert Chain Status (0=Broken/Invalid, 1=Self-Signed/Untrusted, 2=Valid)
        6. Key Size (bits, e.g. 1024, 2048, 4096, 256 for ECC)
        7. Weak Signature Flag (1=Weak/MD5/SHA1, 0=Secure/SHA256+)
        8. Plaintext Credentials Flag (1=Found, 0=Clean)
        9. Encrypted Session Flag (1=Yes, 0=Plaintext)
        """
        # 1. TLS Version
        tls_ver = session_meta.get("tls_version", "None") or "None"
        tls_map = {"None": 0.0, "SSL 3.0": 1.0, "0x0300": 1.0, "TLS 1.0": 2.0, "0x0301": 2.0, "TLS 1.1": 3.0, "0x0302": 3.0, "TLS 1.2": 4.0, "0x0303": 4.0, "TLS 1.3": 5.0, "0x0304": 5.0}
        tls_val = tls_map.get(tls_ver, 0.0)

        # 2. Cipher Strength
        strength = session_meta.get("cipher_strength", "UNKNOWN")
        strength_map = {"CRITICAL": 0.0, "INSECURE": 1.0, "WEAK": 2.0, "MEDIUM": 3.0, "SECURE": 4.0, "UNKNOWN": 1.0}
        strength_val = strength_map.get(strength, 1.0)

        # 3. Key Exchange
        kex = session_meta.get("key_exchange", "Unknown") or "Unknown"
        kex_val = 3.0 if "ECDHE" in kex else (2.0 if "DHE" in kex else (1.0 if "RSA" in kex else 0.0))

        # 4. Forward Secrecy
        fs_val = 1.0 if session_meta.get("forward_secrecy") else 0.0

        # 5. Cert Chain Status
        chain_info = session_meta.get("certificate_chain", {})
        c_status = chain_info.get("status", "NO_CERT")
        if chain_info.get("is_valid"):
            cert_val = 2.0
        elif c_status in ("SELF_SIGNED", "UNTRUSTED_ROOT"):
            cert_val = 1.0
        else:
            cert_val = 0.0

        # 6. Key size
        leaf = session_meta.get("leaf_certificate")
        k_size = float(leaf.get("key_size", 0)) if leaf else float(session_meta.get("key_bits", 0))

        # 7. Weak signature
        weak_sig = 1.0 if (leaf and leaf.get("is_weak_signature")) else 0.0

        # 8. Plaintext credentials
        creds = 1.0 if session_meta.get("has_plaintext_credentials") else 0.0

        # 9. Encrypted session flag
        is_enc = 1.0 if (tls_val > 0 or session_meta.get("is_implicit_tls") or session_meta.get("starttls_upgraded")) else 0.0

        return [tls_val, strength_val, kex_val, fs_val, cert_val, k_size, weak_sig, creds, is_enc]

    @classmethod
    def vectorize_behavioral_features(cls, behavioral_features: Dict[str, Any]) -> List[float]:
        """
        Converts session traffic shape into a numeric feature vector for Isolation Forest.
        Features (7 dimensions):
        1. packet_count
        2. byte_count
        3. duration
        4. client_to_server_ratio
        5. mean_packet_size
        6. mean_inter_arrival_time
        7. burst_ratio
        """
        return [
            float(behavioral_features.get("packet_count", 0)),
            float(behavioral_features.get("byte_count", 0)),
            float(behavioral_features.get("duration", 0.001)),
            float(behavioral_features.get("client_to_server_ratio", 1.0)),
            float(behavioral_features.get("mean_packet_size", 100.0)),
            float(behavioral_features.get("mean_inter_arrival_time", 0.05)),
            float(behavioral_features.get("burst_ratio", 0.1)),
        ]

    def evaluate_session(
        self,
        session_meta: Dict[str, Any],
        behavioral_features: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluates session with Random Forest and Isolation Forest."""
        # 1. Random Forest Crypto Classification
        rf_vector = self.vectorize_crypto_features(session_meta)
        rf_class = "UNKNOWN"
        rf_confidence = 0.0

        if self.rf_model:
            try:
                probs = self.rf_model.predict_proba([rf_vector])[0]
                pred_idx = int(np.argmax(probs))
                rf_class = self.rf_model.classes_[pred_idx]
                rf_confidence = round(float(probs[pred_idx]), 4)
            except Exception:
                pass

        # 2. Isolation Forest Behavioral Anomaly Detection
        if_vector = self.vectorize_behavioral_features(behavioral_features)
        is_anomalous = False
        anomaly_score = 0.0

        if self.if_model:
            try:
                # Decision function: lower values mean more anomalous
                score_raw = self.if_model.decision_function([if_vector])[0]
                pred = self.if_model.predict([if_vector])[0]
                is_anomalous = bool(pred == -1)
                # Map raw score to 0.0 (normal) - 1.0 (highly anomalous)
                anomaly_score = round(float(np.clip(0.5 - (score_raw * 1.5), 0.0, 1.0)), 4)
            except Exception:
                pass

        return {
            "rf_risk_class": rf_class,
            "rf_confidence": rf_confidence,
            "is_anomalous": is_anomalous,
            "anomaly_score": anomaly_score,
            "crypto_feature_vector": rf_vector,
            "behavioral_feature_vector": if_vector
        }

    def summarize_analysis(self, sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregates ML statistics for the analyzed sessions."""
        total = len(sessions)
        if total == 0:
            return {
                "total_sessions": 0,
                "anomalous_sessions": 0,
                "anomaly_rate": 0.0,
                "rf_predictions": {},
                "anomalous_session_ids": []
            }

        anom_count = sum(1 for s in sessions if s.get("is_anomalous"))
        anom_ids = [s.get("stream_id") for s in sessions if s.get("is_anomalous")]
        rf_dist = {}
        for s in sessions:
            c = s.get("rf_predicted_risk", "UNKNOWN")
            rf_dist[c] = rf_dist.get(c, 0) + 1

        return {
            "total_sessions": total,
            "anomalous_sessions": anom_count,
            "normal_sessions": total - anom_count,
            "anomaly_rate": round(anom_count / total, 4) if total else 0.0,
            "rf_predictions": rf_dist,
            "anomalous_session_ids": anom_ids
        }

    def _train_and_save_baseline_models(self):
        """Generates comprehensive training dataset and fits both RF and IF models."""
        # 1. Train Random Forest Classifier
        # Synthetic dataset representing various cryptographic configurations
        X_rf = []
        y_rf = []

        # SECURE samples: TLS 1.3, AES-GCM/ChaCha20, ECDHE, Valid Cert, RSA 2048+/ECC
        for _ in range(120):
            X_rf.append([5.0, 4.0, 3.0, 1.0, 2.0, 2048.0, 0.0, 0.0, 1.0])
            y_rf.append("SECURE")
            X_rf.append([5.0, 4.0, 3.0, 1.0, 2.0, 4096.0, 0.0, 0.0, 1.0])
            y_rf.append("SECURE")
            X_rf.append([4.0, 4.0, 3.0, 1.0, 2.0, 256.0, 0.0, 0.0, 1.0])  # ECDSA
            y_rf.append("SECURE")

        # LOW samples: TLS 1.2, AES-GCM, ECDHE, Valid Cert
        for _ in range(80):
            X_rf.append([4.0, 4.0, 3.0, 1.0, 2.0, 2048.0, 0.0, 0.0, 1.0])
            y_rf.append("LOW")

        # MEDIUM samples: TLS 1.2 with Static RSA (no FS) or CBC cipher
        for _ in range(80):
            X_rf.append([4.0, 3.0, 1.0, 0.0, 2.0, 2048.0, 0.0, 0.0, 1.0])
            y_rf.append("MEDIUM")
            X_rf.append([3.0, 3.0, 2.0, 1.0, 2.0, 2048.0, 0.0, 0.0, 1.0])  # TLS 1.1
            y_rf.append("MEDIUM")

        # HIGH samples: TLS 1.0, Expired Cert, Self-Signed, Weak RSA 1024, Weak SHA1
        for _ in range(100):
            X_rf.append([2.0, 3.0, 1.0, 0.0, 2.0, 2048.0, 0.0, 0.0, 1.0])  # TLS 1.0
            y_rf.append("HIGH")
            X_rf.append([4.0, 4.0, 3.0, 1.0, 0.0, 2048.0, 0.0, 0.0, 1.0])  # Expired
            y_rf.append("HIGH")
            X_rf.append([4.0, 4.0, 3.0, 1.0, 1.0, 2048.0, 0.0, 0.0, 1.0])  # Self-signed
            y_rf.append("HIGH")
            X_rf.append([4.0, 4.0, 3.0, 1.0, 2.0, 1024.0, 0.0, 0.0, 1.0])  # RSA 1024
            y_rf.append("HIGH")
            X_rf.append([4.0, 4.0, 3.0, 1.0, 2.0, 2048.0, 1.0, 0.0, 1.0])  # SHA-1
            y_rf.append("HIGH")
            X_rf.append([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])     # Plaintext
            y_rf.append("HIGH")

        # CRITICAL samples: Plaintext credentials, SSL 3.0, RC4, 3DES, NULL
        for _ in range(80):
            X_rf.append([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0])     # Plaintext creds
            y_rf.append("CRITICAL")
            X_rf.append([1.0, 0.0, 1.0, 0.0, 2.0, 2048.0, 0.0, 0.0, 1.0])  # SSL 3.0
            y_rf.append("CRITICAL")
            X_rf.append([4.0, 0.0, 1.0, 0.0, 2.0, 2048.0, 0.0, 0.0, 1.0])  # RC4
            y_rf.append("CRITICAL")
            X_rf.append([4.0, 1.0, 1.0, 0.0, 2.0, 2048.0, 0.0, 0.0, 1.0])  # 3DES
            y_rf.append("CRITICAL")

        rf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
        rf.fit(X_rf, y_rf)
        self.rf_model = rf
        joblib.dump(rf, self.rf_model_path)

        # 2. Train Isolation Forest Anomaly Detector on Behavioral Traffic Shape
        # Standard email sessions: moderate packets (10-80), bytes (1KB-50KB), duration (0.5s-10s)
        np.random.seed(42)
        normal_samples = []
        for _ in range(500):
            pkts = np.random.uniform(12, 60)
            bytes_tot = pkts * np.random.uniform(80, 450)
            dur = np.random.uniform(0.8, 8.0)
            c2s = np.random.uniform(0.3, 2.5)
            mean_sz = bytes_tot / pkts
            mean_iat = dur / pkts
            burst = np.random.uniform(0.1, 0.35)
            normal_samples.append([pkts, bytes_tot, dur, c2s, mean_sz, mean_iat, burst])

        # A few anomalous outliers (burst attacks, massive dumps, scanning)
        for _ in range(25):
            pkts = np.random.uniform(500, 3000)
            bytes_tot = pkts * np.random.uniform(1000, 1500)
            dur = np.random.uniform(0.1, 0.5)  # ultra fast burst
            c2s = np.random.uniform(10.0, 50.0)
            mean_sz = 1200.0
            mean_iat = 0.0001
            burst = 0.95
            normal_samples.append([pkts, bytes_tot, dur, c2s, mean_sz, mean_iat, burst])

        iso = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        iso.fit(normal_samples)
        self.if_model = iso
        joblib.dump(iso, self.if_model_path)
