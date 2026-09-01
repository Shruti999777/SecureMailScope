"""
SecureMailScope - Machine Learning Model Trainer & Evaluation Suite
Trains:
1. Random Forest Classifier on Cryptographic Security Posture Features.
2. Isolation Forest on Behavioral Session Traffic Shape Features.

Evaluates & Outputs:
- Train / Test Split (80% / 20%)
- 5-Fold Cross Validation
- Accuracy, Precision, Recall, F1-Score (Macro & Weighted)
- Multi-class Confusion Matrix
- Isolation Forest Anomaly Detection Rates
"""

import os
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support, accuracy_score

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "data" / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)


def build_synthetic_crypto_dataset(num_samples: int = 2500):
    """
    Synthesizes rich dataset of cryptographic feature vectors and ground truth risk labels.
    Features: [tls_ver, cipher_str, kex_type, fs_flag, cert_status, key_size, weak_sig, creds, is_enc]
    """
    np.random.seed(42)
    X = []
    y = []

    # 1. SECURE: Modern TLS 1.3/1.2, ECDHE, AES-GCM/ChaCha20, Valid Cert, RSA 2048+/ECC
    for _ in range(int(num_samples * 0.30)):
        tls_ver = 5.0 if np.random.rand() > 0.3 else 4.0
        cipher_str = 4.0
        kex = 3.0  # ECDHE
        fs = 1.0
        cert_st = 2.0  # Valid
        key_sz = 2048.0 if np.random.rand() > 0.4 else (4096.0 if np.random.rand() > 0.5 else 256.0)
        weak_sig = 0.0
        creds = 0.0
        is_enc = 1.0
        X.append([tls_ver, cipher_str, kex, fs, cert_st, key_sz, weak_sig, creds, is_enc])
        y.append("SECURE")

    # 2. LOW: TLS 1.2, AES-GCM, ECDHE, Valid Cert
    for _ in range(int(num_samples * 0.20)):
        tls_ver = 4.0
        cipher_str = 4.0
        kex = 3.0
        fs = 1.0
        cert_st = 2.0
        key_sz = 2048.0
        weak_sig = 0.0
        creds = 0.0
        is_enc = 1.0
        X.append([tls_ver, cipher_str, kex, fs, cert_st, key_sz, weak_sig, creds, is_enc])
        y.append("LOW")

    # 3. MEDIUM: Static RSA (no FS) or TLS 1.1 or CBC Mode
    for _ in range(int(num_samples * 0.20)):
        tls_ver = 4.0 if np.random.rand() > 0.5 else 3.0
        cipher_str = 3.0  # Medium/CBC
        kex = 1.0 if np.random.rand() > 0.4 else 2.0  # Static RSA or DHE
        fs = 0.0 if kex == 1.0 else 1.0
        cert_st = 2.0
        key_sz = 2048.0
        weak_sig = 0.0
        creds = 0.0
        is_enc = 1.0
        X.append([tls_ver, cipher_str, kex, fs, cert_st, key_sz, weak_sig, creds, is_enc])
        y.append("MEDIUM")

    # 4. HIGH: TLS 1.0, Expired Cert, Self-Signed, RSA 1024, Weak SHA1, or Cleartext
    for _ in range(int(num_samples * 0.18)):
        sub_case = np.random.randint(0, 5)
        if sub_case == 0:  # TLS 1.0
            X.append([2.0, 3.0, 1.0, 0.0, 2.0, 2048.0, 0.0, 0.0, 1.0])
        elif sub_case == 1:  # Expired
            X.append([4.0, 4.0, 3.0, 1.0, 0.0, 2048.0, 0.0, 0.0, 1.0])
        elif sub_case == 2:  # Self-signed
            X.append([4.0, 4.0, 3.0, 1.0, 1.0, 2048.0, 0.0, 0.0, 1.0])
        elif sub_case == 3:  # Weak RSA 1024
            X.append([4.0, 4.0, 3.0, 1.0, 2.0, 1024.0, 0.0, 0.0, 1.0])
        else:  # Cleartext without STARTTLS
            X.append([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
        y.append("HIGH")

    # 5. CRITICAL: Plaintext Credential Leakage, SSL 3.0, RC4, 3DES, NULL
    for _ in range(int(num_samples * 0.12)):
        sub_case = np.random.randint(0, 4)
        if sub_case == 0:  # Plaintext credentials
            X.append([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0])
        elif sub_case == 1:  # RC4
            X.append([4.0, 0.0, 1.0, 0.0, 2.0, 2048.0, 0.0, 0.0, 1.0])
        elif sub_case == 2:  # 3DES
            X.append([4.0, 1.0, 1.0, 0.0, 2.0, 2048.0, 0.0, 0.0, 1.0])
        else:  # SSL 3.0
            X.append([1.0, 0.0, 1.0, 0.0, 2.0, 2048.0, 0.0, 0.0, 1.0])
        y.append("CRITICAL")

    return np.array(X), np.array(y)


def build_synthetic_behavioral_dataset(num_samples: int = 3000):
    """
    Synthesizes behavioral session shape vectors:
    [packet_count, byte_count, duration, client_to_server_ratio, mean_packet_size, mean_inter_arrival_time, burst_ratio]
    """
    np.random.seed(42)
    X = []
    
    # 95% Normal email sessions
    for _ in range(int(num_samples * 0.95)):
        pkts = np.random.uniform(10, 80)
        bytes_tot = pkts * np.random.uniform(90, 500)
        dur = np.random.uniform(0.5, 10.0)
        c2s = np.random.uniform(0.2, 3.0)
        mean_sz = bytes_tot / pkts
        mean_iat = dur / pkts
        burst = np.random.uniform(0.08, 0.35)
        X.append([pkts, bytes_tot, dur, c2s, mean_sz, mean_iat, burst])

    # 5% Anomalous outliers (DDoS, massive brute force bursts, data exfiltration)
    for _ in range(int(num_samples * 0.05)):
        sub_type = np.random.randint(0, 3)
        if sub_type == 0:  # High-rate Brute Force Burst
            pkts = np.random.uniform(300, 1500)
            bytes_tot = pkts * 80
            dur = np.random.uniform(0.1, 0.5)
            c2s = np.random.uniform(15.0, 60.0)
            mean_sz = 80.0
            mean_iat = dur / pkts
            burst = np.random.uniform(0.85, 0.99)
        elif sub_type == 1:  # Data Exfiltration Dump
            pkts = np.random.uniform(2000, 8000)
            bytes_tot = pkts * 1400
            dur = np.random.uniform(1.0, 5.0)
            c2s = np.random.uniform(20.0, 100.0)
            mean_sz = 1400.0
            mean_iat = dur / pkts
            burst = np.random.uniform(0.70, 0.90)
        else:  # Port scan / connection spike
            pkts = np.random.uniform(3, 6)
            bytes_tot = pkts * 40
            dur = 0.001
            c2s = 50.0
            mean_sz = 40.0
            mean_iat = 0.0001
            burst = 1.0
        X.append([pkts, bytes_tot, dur, c2s, mean_sz, mean_iat, burst])

    return np.array(X)


def train_and_evaluate_all():
    print("=" * 70)
    print(" SECUREMAILSCOPE - MACHINE LEARNING MODEL TRAINING & EVALUATION ")
    print("=" * 70)

    # 1. Random Forest Classifier Training & Evaluation
    print("\n[+] 1. Training Random Forest Cryptographic Risk Classifier...")
    X_crypto, y_crypto = build_synthetic_crypto_dataset(num_samples=3000)
    
    # Train / Test Split (80% / 20%)
    X_train, X_test, y_train, y_test = train_test_split(
        X_crypto, y_crypto, test_size=0.20, random_state=42, stratify=y_crypto
    )

    rf_model = RandomForestClassifier(n_estimators=120, max_depth=12, random_state=42)
    rf_model.fit(X_train, y_train)

    y_pred = rf_model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec_w, rec_w, f1_w, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted")
    prec_m, rec_m, f1_m, _ = precision_recall_fscore_support(y_test, y_pred, average="macro")

    # 5-Fold Cross Validation
    cv_scores = cross_val_score(rf_model, X_crypto, y_crypto, cv=5)

    print("\n--- RANDOM FOREST EVALUATION METRICS ---")
    print(f"Test Accuracy:           {acc * 100:.2f}%")
    print(f"Weighted Precision:      {prec_w:.4f}")
    print(f"Weighted Recall:         {rec_w:.4f}")
    print(f"Weighted F1-Score:       {f1_w:.4f}")
    print(f"Macro F1-Score:          {f1_m:.4f}")
    print(f"5-Fold CV Mean Accuracy: {cv_scores.mean() * 100:.2f}% (+/- {cv_scores.std() * 2 * 100:.2f}%)")

    print("\n--- CLASSIFICATION REPORT ---")
    print(classification_report(y_test, y_pred, digits=4))

    classes = ["SECURE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    cm = confusion_matrix(y_test, y_pred, labels=classes)
    cm_df = pd.DataFrame(cm, index=[f"Actual_{c}" for c in classes], columns=[f"Pred_{c}" for c in classes])
    print("--- CONFUSION MATRIX ---")
    print(cm_df)

    # Save RF model artifact
    rf_path = MODELS_DIR / "random_forest_risk.joblib"
    joblib.dump(rf_model, rf_path)
    print(f"\n[+] Saved Random Forest model to: {rf_path}")

    # 2. Isolation Forest Behavioral Anomaly Detection
    print("\n" + "=" * 70)
    print("[+] 2. Training Isolation Forest Behavioral Anomaly Detector...")
    X_behavioral = build_synthetic_behavioral_dataset(num_samples=3000)

    iso_model = IsolationForest(n_estimators=120, contamination=0.05, random_state=42)
    iso_model.fit(X_behavioral)

    preds = iso_model.predict(X_behavioral)
    total = len(preds)
    anomalous = int(np.sum(preds == -1))
    normal = int(np.sum(preds == 1))
    anomaly_rate = anomalous / total

    print("\n--- ISOLATION FOREST EVALUATION STATS ---")
    print(f"Total Evaluated Sessions:  {total}")
    print(f"Normal Sessions:           {normal} ({(normal/total)*100:.1f}%)")
    print(f"Anomalous Sessions:        {anomalous} ({(anomalous/total)*100:.1f}%)")
    print(f"Detected Anomaly Rate:     {anomaly_rate * 100:.2f}% (Expected contamination ~ 5%)")

    # Save IF model artifact
    if_path = MODELS_DIR / "isolation_forest_behavioral.joblib"
    joblib.dump(iso_model, if_path)
    print(f"\n[+] Saved Isolation Forest model to: {if_path}")
    print("=" * 70)


if __name__ == "__main__":
    train_and_evaluate_all()
