# SecureMailScope
AI-powered email traffic security analyzer for PCAP-based cryptographic posture assessment, TLS analysis, certificate validation, and dual-AI risk detection.
SecureMailScope is a PCAP-based email security analysis system designed to inspect captured network traffic and identify security risks in encrypted email communication.
The system takes a .pcap network capture as input and analyzes the packets to understand how an email connection was established, how TLS encryption was negotiated, which certificates were used, and whether the connection demonstrates secure cryptographic properties.
# How the system works
1. PCAP Input
The user provides a network capture (.pcap) containing email traffic.
The system processes the captured packets instead of requiring access to the original mail server.
2. Packet and Protocol Analysis
Network packets are parsed to identify relevant email and TLS communication.
Important connection information such as IP addresses, ports, protocols, packet sizes, and communication patterns is extracted.
3. TLS Security Analysis
The system examines TLS communication and identifies the negotiated TLS version and cryptographic parameters.
It evaluates whether the connection uses modern and secure encryption mechanisms.
4. Key Exchange and Forward Secrecy
The TLS handshake is analyzed to identify the key-exchange mechanism.
The system checks whether the connection provides Perfect Forward Secrecy (PFS), which helps prevent previously captured encrypted traffic from being decrypted if a long-term private key is later compromised.
5. X.509 Certificate Analysis
Certificates present in the captured TLS traffic are extracted and parsed.
The system examines certificate information such as:
Subject and issuer
Validity period
Public-key information
Signature algorithm
Certificate chain
Trust/validation-related properties
6. Feature Extraction
Security-relevant characteristics from the network traffic, TLS handshake, certificates, and connection behavior are converted into features.
These features are used for automated security analysis.
7. AI-Based Anomaly Detection
SecureMailScope uses an Isolation Forest anomaly-detection model to identify unusual characteristics in the analyzed traffic.
Instead of relying only on fixed rules, the model helps identify traffic that deviates from expected patterns.
8. Risk Analysis
The results from protocol analysis, certificate inspection, cryptographic checks, and anomaly detection are combined to identify potential security concerns.
The system can highlight issues such as weak cryptographic configurations, certificate problems, suspicious communication patterns, or anomalous traffic.
9. Results and Visualization
The analyzed information is presented through the application's frontend.
The user can inspect the connection details, TLS information, certificate information, detected anomalies, and overall security assessment.

# Workflow
PCAP File │ ▼ Packet Extraction │ ▼ Protocol Identification │ ▼ TLS Analysis │ ┌────────────┴────────────┐ ▼ ▼ Key Exchange / PFS X.509 Analysis │ │ └────────────┬────────────┘ ▼ Feature Extraction │ ▼ Isolation Forest Model │ ▼ Anomaly Detection │ ▼ Risk Assessment │ ▼ Web Dashboard

# Objective
The main objective of SecureMailScope is to provide a practical security-analysis platform for encrypted email traffic. Rather than simply displaying packets, the project combines network forensics, TLS security analysis, X.509 certificate inspection, cryptographic evaluation, and machine-learning-based anomaly detection to provide a deeper assessment of the security of an email connection.

