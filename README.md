# 🛡️ AI-Powered Deep Packet Inspection & Threat Detection

An **AI-powered network traffic analysis and threat detection system** that combines **Deep Packet Inspection (DPI)**, **flow-based machine learning**, **TLS/HTTP inspection**, **application classification**, **threat scoring**, and **rule-based enforcement**.

The system analyzes PCAP network captures, reconstructs network flows, extracts behavioral features, identifies applications, detects suspicious traffic patterns, assigns threat scores, and produces machine-readable reports and an interactive Streamlit dashboard.

---

## 🚀 Overview

Traditional Deep Packet Inspection systems mainly rely on predefined signatures and rules.

This project extends DPI with a **Machine Learning threat intelligence layer**.

```text
                         PCAP FILE
                            │
                            ▼
                  ┌──────────────────┐
                  │   PCAP Reader    │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Packet Parsing   │
                  │ Ethernet / IP    │
                  │ TCP / UDP        │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Flow Tracking    │
                  │ 5-Tuple Based    │
                  └────────┬─────────┘
                           │
              ┌────────────┴────────────┐
              │                         │
              ▼                         ▼
      ┌─────────────────┐      ┌─────────────────┐
      │ TLS / HTTP DPI  │      │ Flow Features   │
      │ SNI / Host      │      │ Statistics      │
      └────────┬────────┘      └────────┬────────┘
               │                        │
               └───────────┬────────────┘
                           ▼
                 ┌────────────────────┐
                 │   ML Inference     │
                 │                    │
                 │ Application Model  │
                 │ Threat Model       │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ Threat Scoring     │
                 │ + XAI Drivers      │
                 │ + Enforcement      │
                 └─────────┬──────────┘
                           │
              ┌────────────┼─────────────┐
              ▼            ▼             ▼
          PCAP Output   JSON / CSV    Dashboard
```

---

# 📑 Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [What Makes This Project AI-Powered?](#2-what-makes-this-project-ai-powered)
3. [Networking Background](#3-networking-background)
4. [Project Architecture](#4-project-architecture)
5. [Project Features](#5-project-features)
6. [File Structure](#6-file-structure)
7. [The Journey of a Packet](#7-the-journey-of-a-packet)
8. [Flow Tracking](#8-flow-tracking)
9. [Deep Packet Inspection](#9-deep-packet-inspection)
10. [Machine Learning Pipeline](#10-machine-learning-pipeline)
11. [ML Features](#11-ml-features)
12. [Application Classification](#12-application-classification)
13. [Threat and Anomaly Detection](#13-threat-and-anomaly-detection)
14. [Threat Scoring](#14-threat-scoring)
15. [Explainable AI](#15-explainable-ai)
16. [Blocking and Enforcement](#16-blocking-and-enforcement)
17. [Reports](#17-reports)
18. [Dashboard](#18-dashboard)
19. [Model Training](#19-model-training)
20. [Building and Running](#20-building-and-running)
21. [Example Output](#21-example-output)
22. [Threat Classes](#22-threat-classes)
23. [Application Classes](#23-application-classes)
24. [Limitations](#24-limitations)
25. [Future Improvements](#25-future-improvements)
26. [Summary](#26-summary)

---

# 1. What is DPI?

**Deep Packet Inspection (DPI)** is a network traffic analysis technique that examines packet headers and, when available, application-layer payload information.

A basic firewall may inspect:

```text
Source IP
Destination IP
Source Port
Destination Port
Protocol
```

DPI goes deeper:

```text
Ethernet
   ↓
IP
   ↓
TCP / UDP
   ↓
Application Payload
   ↓
TLS / HTTP information
   ↓
SNI / Host / Application
```

### Real-world applications

DPI can be used for:

* Network monitoring
* Intrusion detection
* Application identification
* Traffic classification
* Policy enforcement
* Threat detection
* Bandwidth management
* Security analytics

### What this project does

This project combines traditional DPI with machine learning:

```text
PCAP
 │
 ├── Packet Parsing
 │
 ├── Flow Reconstruction
 │
 ├── SNI / HTTP Inspection
 │
 ├── Application Classification
 │
 ├── ML Threat Detection
 │
 ├── Threat Scoring
 │
 ├── Rule-Based Blocking
 │
 └── Reports + Dashboard
```

---

# 2. What Makes This Project AI-Powered?

The original DPI pipeline used deterministic rules such as:

```text
SNI contains "youtube"
        ↓
YouTube
        ↓
Block
```

The current system adds **machine learning based traffic intelligence**.

Instead of relying only on a domain name, the system can analyze behavioral properties of a network flow.

For example:

```text
Packets
Bytes
Packet sizes
Inter-arrival times
Entropy
TCP flags
Destination port
SNI presence
Flow duration
```

These features are passed to trained Random Forest models.

```text
Network Flow
     │
     ▼
32 Behavioral Features
     │
     ├───────────────┐
     ▼               ▼
Application RF    Threat RF
     │               │
     ▼               ▼
Application       Attack Type
     │               │
     └───────┬───────┘
             ▼
       Threat Scoring
             │
             ▼
      ALLOW / BLOCK
```

The training pipeline generates **8,000 synthetic network-flow samples** and trains separate Random Forest models for application classification and threat/anomaly detection.

---

# 3. Networking Background

## 3.1 Network Layers

```text
┌─────────────────────────────────────────┐
│ Layer 7 │ HTTP / HTTPS / DNS / TLS     │
├─────────────────────────────────────────┤
│ Layer 4 │ TCP / UDP                    │
├─────────────────────────────────────────┤
│ Layer 3 │ IPv4                         │
├─────────────────────────────────────────┤
│ Layer 2 │ Ethernet                     │
└─────────────────────────────────────────┘
```

The DPI engine operates across these layers to transform raw packet bytes into meaningful flow-level information.

---

## 3.2 Packet Structure

A typical Ethernet + IPv4 + TCP packet looks like:

```text
┌──────────────────────────────────────────────┐
│ Ethernet Header                              │
├──────────────────────────────────────────────┤
│ IPv4 Header                                  │
├──────────────────────────────────────────────┤
│ TCP Header                                   │
├──────────────────────────────────────────────┤
│ Application Payload                          │
│                                              │
│ TLS Client Hello / HTTP Request / Data       │
└──────────────────────────────────────────────┘
```

---

# 4. Project Architecture

The project has two major layers.

## Layer 1 — DPI

Responsible for understanding network traffic.

```text
PCAP
 ↓
Packet Parsing
 ↓
5-Tuple
 ↓
Flow Tracking
 ↓
SNI / HTTP Extraction
```

## Layer 2 — AI Threat Intelligence

Responsible for understanding the behavior of the flow.

```text
Flow
 ↓
Feature Extraction
 ↓
Application Classifier
 ↓
Threat Detector
 ↓
Threat Score
 ↓
Risk Level
 ↓
Decision
```

Together:

```text
                 AI-POWERED DPI
                       │
        ┌──────────────┴──────────────┐
        │                             │
   Traditional DPI                 ML Layer
        │                             │
  ┌─────┴──────┐               ┌──────┴──────┐
  │            │               │             │
Packet       SNI/HTTP      Application     Threat
Parsing      Detection     Classifier      Detector
  │            │               │             │
  └─────┬──────┘               └──────┬──────┘
        │                             │
        └─────────────┬───────────────┘
                      ▼
                Threat Scoring
                      │
                      ▼
                Enforcement
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
        PCAP        Reports     Dashboard
```

---

# 5. Project Features

### 🔍 Deep Packet Inspection

* Ethernet parsing
* IPv4 parsing
* TCP/UDP inspection
* TLS Client Hello inspection
* SNI extraction
* HTTP Host extraction

### 🌐 Flow Analysis

* Five-tuple based flow tracking
* Packet counts
* Byte statistics
* Packet length statistics
* Inter-arrival-time statistics
* TCP flag statistics

### 🤖 Machine Learning

* Random Forest application classifier
* Random Forest threat classifier
* 32 flow-level features
* Application prediction confidence
* Threat/anomaly score
* Attack-type prediction

### 🧠 Threat Intelligence

* Threat score from 0–100
* Threat levels
* Attack classification
* Explainable feature drivers
* Trusted-domain adjustments
* Rule-based enforcement

### 📊 Reporting

* JSON report
* CSV report
* Application breakdown
* Flow-level threat intelligence
* Inference timing
* Threat statistics

### 📈 Dashboard

Streamlit dashboard with:

* Threat-level filtering
* Application filtering
* Block/allow filtering
* IP/domain search
* Flow inspection
* Threat scores
* Attack types
* ML predictions

---

# 6. File Structure

```text
AI-Powered-Deep-Packet-Inspection-Threat-Detection/
│
├── include/
│   ├── pcap_reader.h
│   ├── packet_parser.h
│   ├── sni_extractor.h
│   ├── types.h
│   ├── rule_manager.h
│   ├── connection_tracker.h
│   ├── load_balancer.h
│   ├── fast_path.h
│   ├── thread_safe_queue.h
│   └── dpi_engine.h
│
├── src/
│   ├── pcap_reader.cpp
│   ├── packet_parser.cpp
│   ├── sni_extractor.cpp
│   ├── types.cpp
│   ├── main_working.cpp
│   └── dpi_mt.cpp
│
├── models/
│   ├── classifier_model.json
│   └── anomaly_model.json
│
├── train_models.py
├── run_dpi.py
├── dashboard.py
│
├── generate_test_pcap.py
├── generate_full_test.py
├── generate_demo_report.py
│
├── test_dpi.pcap
├── test_attack.pcap
├── test_full_threats.pcap
│
├── reports/
│   ├── dpi_report.json
│   └── dpi_report.csv
│
├── requirements.txt
├── CMakeLists.txt
├── WINDOWS_SETUP.md
└── README.md
```

---

# 7. The Journey of a Packet

Let's follow a packet from the PCAP file to the final ML decision.

```text
PCAP
 │
 ▼
Read Packet
 │
 ▼
Parse Ethernet
 │
 ▼
Parse IPv4
 │
 ▼
Parse TCP / UDP
 │
 ▼
Create Five-Tuple
 │
 ▼
Find / Create Flow
 │
 ▼
Extract SNI / HTTP Host
 │
 ▼
Generate Flow Features
 │
 ▼
Application ML Model
 │
 ▼
Threat ML Model
 │
 ▼
Threat Scoring
 │
 ▼
ALLOW / BLOCK
 │
 ├──► Output PCAP
 └──► JSON / CSV Report
```

---

# 8. Flow Tracking

Machine learning is performed on **network flows**, rather than treating every packet as an independent example.

A flow is identified using the five-tuple:

```text
Source IP
Destination IP
Source Port
Destination Port
Protocol
```

Example:

```text
192.168.1.100:54321
        ↓
142.250.185.206:443
        ↓
TCP
```

This becomes:

```text
FiveTuple(
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol
)
```

All packets belonging to this flow contribute to the same feature set.

---

# 9. Deep Packet Inspection

## 9.1 TLS SNI Extraction

For HTTPS traffic, the engine inspects the TLS Client Hello.

```text
TLS Client Hello
       │
       ▼
Extensions
       │
       ▼
SNI Extension
       │
       ▼
www.youtube.com
```

The extracted domain can help identify the application.

Example:

```text
www.youtube.com
       ↓
YouTube
```

---

## 9.2 HTTP Host Extraction

For HTTP traffic, the engine searches for:

```text
Host: example.com
```

and extracts:

```text
example.com
```

This information can be combined with the ML prediction.

---

# 10. Machine Learning Pipeline

The ML system contains two Random Forest classifiers.

```text
                   Network Flow
                        │
                        ▼
               Feature Extraction
                        │
               ┌────────┴────────┐
               │                 │
               ▼                 ▼
       Application Model   Threat Model
        Random Forest       Random Forest
               │                 │
               ▼                 ▼
       Predicted App        Attack Type
       Confidence           Anomaly Score
               │                 │
               └────────┬────────┘
                        ▼
                  Threat Scorer
                        │
                        ▼
                 Final Decision
```

The training script creates synthetic flow data, trains both models, and serializes the individual decision trees into JSON so that inference can be performed without loading a Python/scikit-learn model at runtime.

---

# 11. ML Features

The model uses **32 network-flow features**.

### Flow statistics

```text
duration_sec
pkts_src
pkts_dst
bytes_src
bytes_dst
```

### Packet statistics

```text
pkt_len_mean
pkt_len_std
```

### Timing statistics

```text
iat_mean
iat_std
```

### Traffic direction

```text
bytes_ratio
```

### First packet lengths

```text
p1_len
p2_len
p3_len
p4_len
p5_len
p6_len
p7_len
p8_len
```

### First packet inter-arrival times

```text
p1_iat
p2_iat
p3_iat
p4_iat
p5_iat
p6_iat
p7_iat
p8_iat
```

### Security / protocol features

```text
payload_entropy_mean
dest_port
tcp_syn_count
tcp_fin_count
tcp_rst_count
sni_present
```

These features capture both **network behavior** and **protocol characteristics**.

---

# 12. Application Classification

The application classifier predicts the type of traffic based on flow behavior.

The model currently supports:

```text
UNKNOWN
HTTP
HTTPS
DNS
Google
YouTube
Facebook
Instagram
Twitter
Netflix
Amazon
Microsoft
Apple
WhatsApp
Telegram
TikTok
Spotify
Zoom
Discord
GitHub
```

The model contains:

```text
Random Forest
15 Trees
Maximum Depth = 12
Minimum Samples per Leaf = 5
Class Weight = balanced
```

The classifier produces:

```text
Predicted Application
        +
Confidence
        +
Important Features
```

The system can also use SNI-based identification when a known domain is directly recognized.

---

# 13. Threat and Anomaly Detection

The second Random Forest model analyzes the same flow features for suspicious behavior.

It predicts five classes:

```text
BENIGN
SYN_FLOOD
OBFUSCATED_TUNNEL
DATA_EXFILTRATION
C2_BEACONING
```

## SYN Flood

Characteristics include:

```text
Large number of SYN packets
Very few responses
Short inter-arrival times
```

Example:

```text
SYN
SYN
SYN
SYN
SYN
SYN
...
```

---

## Obfuscated Tunnel

Potential characteristics:

```text
High payload entropy
Unusual ports
Encoded / obfuscated traffic patterns
```

---

## Data Exfiltration

Potential characteristics:

```text
Very large outbound byte volume
Large packet sizes
High source-to-destination byte ratio
High entropy
```

---

## C2 Beaconing

Potential characteristics:

```text
Repeated communication
Similar packet sizes
Regular timing
Low inter-arrival-time variance
Persistent communication
```

The synthetic training generator explicitly models these behavioral patterns.

---

# 14. Threat Scoring

The ML prediction is not used alone.

The system combines multiple signals to produce a **0–100 threat score**.

```text
ML anomaly score
        +
Attack classification
        +
Application confidence
        +
Flow statistics
        +
Entropy
        +
TCP behavior
        +
Destination port
        +
SNI information
        +
Trusted-domain adjustments
        ↓
   Threat Score
```

The system then assigns a threat level such as:

```text
0–29    LOW
30–59   MEDIUM
60–69   HIGH
70–100  CRITICAL
```

The enforcement threshold can be configured.

Default:

```text
Threat Threshold = 70
```

---

# 15. Explainable AI

The system does not only return:

```text
Threat Detected
```

It also attempts to explain **why** the model reached the result.

For each Random Forest prediction, the engine tracks the features used by decision-tree splits and identifies the most frequently used feature drivers.

Example:

```text
Threat Score: 87/100

Attack:
DATA_EXFILTRATION

Important Features:
- bytes_src
- payload_entropy_mean
- pkts_src

Decision:
BLOCK
```

Another example:

```text
Threat Score: 12/100

Application:
HTTPS

Attack:
BENIGN

Important Features:
- dest_port
- sni_present
- pkt_len_mean

Decision:
ALLOW
```

This makes the output easier to interpret than a simple black-box prediction.

---

# 16. Blocking and Enforcement

The system supports both traditional rules and ML-based enforcement.

## Rule-based blocking

### Application

```text
--block-app YouTube
```

### IP

```text
--block-ip 192.168.1.50
```

### Domain

```text
--block-domain facebook
```

---

## ML-based blocking

The threat score can also trigger enforcement.

```text
Flow
 │
 ▼
Threat Score
 │
 ├── < Threshold ──► ALLOW
 │
 └── >= Threshold ─► BLOCK
```

Example:

```text
Threat Score: 82
Threshold:    70

82 >= 70
   ↓
BLOCK
```

The final flow report contains the predicted application, threat score, threat level, attack type, confidence, rationale and enforcement decision.

---

# 17. Reports

After processing, the system generates:

```text
reports/
├── dpi_report.json
└── dpi_report.csv
```

## JSON Report

Contains:

```text
Total packets
Forwarded packets
Dropped packets
Active flows
Evaluated flows
High-threat flows
Average threat score
Average confidence
Inference time
Application breakdown
Flow-level results
```

Each flow can contain:

```text
Flow ID
Source IP
Source Port
Destination IP
Destination Port
Protocol
Application
SNI
Threat Score
Threat Level
Confidence
Anomaly Score
Attack Type
Decision
Rationale
XAI Drivers
```

The same information is exported to CSV for further analysis.

---

# 18. Dashboard

The project includes a Streamlit dashboard.

Run:

```bash
streamlit run dashboard.py
```

The dashboard reads:

```text
reports/dpi_report.json
reports/dpi_report.csv
```

and provides interactive analysis.

### Available filters

```text
Threat Level
    ├── ALL
    ├── CRITICAL
    ├── HIGH
    ├── MEDIUM
    └── LOW

Enforcement
    ├── ALL
    ├── BLOCK
    └── ALLOW

Application
    ├── YouTube
    ├── Facebook
    ├── Google
    ├── HTTPS
    ├── DNS
    ├── GitHub
    └── ...
```

You can also search using:

```text
IP address
Domain
Threat reason
```

The dashboard is designed around the ML-generated threat level, enforcement decision and application prediction.

---

# 19. Model Training

The models can be retrained using:

```bash
python train_models.py
```

The training process is:

```text
Generate Synthetic Network Flows
             │
             ▼
       8,000 Samples
             │
             ▼
       Feature Matrix
             │
       ┌─────┴─────┐
       ▼           ▼
   App Labels   Attack Labels
       │           │
       ▼           ▼
 Random Forest  Random Forest
       │           │
       └─────┬─────┘
             ▼
      Serialize Trees
             │
             ▼
       JSON Models
```

Generated files:

```text
models/classifier_model.json
models/anomaly_model.json
```

The application model and threat model both use 15-tree Random Forest configurations with maximum depth 12 and balanced class weights.

---

# 20. Building and Running

## 20.1 Prerequisites

### Python

Recommended:

```text
Python 3.10+
```

Install dependencies:

```bash
pip install -r requirements.txt
```

The current requirements include Streamlit, Pandas, NumPy, Matplotlib and scikit-learn.

---

## 20.2 Generate Test PCAP

```bash
python generate_test_pcap.py
```

Additional test generators are available:

```bash
python generate_full_test.py
python generate_demo_report.py
```

---

## 20.3 Run the DPI Engine

Basic:

```bash
python run_dpi.py test_dpi.pcap output.pcap
```

Attack capture:

```bash
python run_dpi.py test_attack.pcap output.pcap
```

Full threat test:

```bash
python run_dpi.py test_full_threats.pcap output.pcap
```

---

## 20.4 Block an Application

```bash
python run_dpi.py input.pcap output.pcap \
    --block-app YouTube
```

Multiple applications:

```bash
python run_dpi.py input.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok
```

---

## 20.5 Block an IP

```bash
python run_dpi.py input.pcap output.pcap \
    --block-ip 192.168.1.50
```

---

## 20.6 Block a Domain

```bash
python run_dpi.py input.pcap output.pcap \
    --block-domain facebook
```

---

## 20.7 Configure ML Threat Threshold

Default threshold:

```text
70
```

Custom threshold:

```bash
python run_dpi.py input.pcap output.pcap \
    --block-threat-score 80
```

The CLI supports application, IP, domain and threat-score blocking options.

---

## 20.8 Launch Dashboard

After generating the report:

```bash
streamlit run dashboard.py
```

The dashboard expects:

```text
reports/dpi_report.json
reports/dpi_report.csv
```

---

# 21. Example Output

A typical run produces output similar to:

```text
================================================================
 AI-POWERED DPI & THREAT DETECTION ENGINE v2.0 (REAL ML)
================================================================

[DPI] Reading input capture: test_attack.pcap

[Rules] AI Threat Threshold: 70/100

[DPI] Processing packets & running Machine Learning Threat Inference...

----------------------------------------------------------------
 REAL ML THREAT INTELLIGENCE & CLASSIFICATION
----------------------------------------------------------------

 Evaluated Flows:          25
 High Threats (>=70):      6
 Inference Time:         XX.XX ms

----------------------------------------------------------------
 APPLICATION BREAKDOWN
----------------------------------------------------------------

 HTTPS              12
 DNS                 4
 YouTube             3
 GitHub              2
 UNKNOWN             4

================================================================

[AI Explainable Threat Intelligence & Risk Matrix]

[LOW     ] Score:  12/100 | Decision: ALLOW | App: HTTPS | Attack: BENIGN

[CRITICAL] Score:  91/100 | Decision: BLOCK | App: UNKNOWN | Attack: SYN_FLOOD

[HIGH    ] Score:  76/100 | Decision: BLOCK | App: HTTPS | Attack: DATA_EXFILTRATION
```

The engine also exports the processed intelligence into JSON and CSV reports.

---

# 22. Threat Classes

| Threat Class        | Description                                         |
| ------------------- | --------------------------------------------------- |
| `BENIGN`            | Normal network activity                             |
| `SYN_FLOOD`         | Abnormally high SYN traffic                         |
| `OBFUSCATED_TUNNEL` | Suspicious high-entropy / tunneling behavior        |
| `DATA_EXFILTRATION` | Large outbound data transfer pattern                |
| `C2_BEACONING`      | Repeated periodic command-and-control style traffic |

---

# 23. Application Classes

The application classifier currently supports:

| Category            | Examples                             |
| ------------------- | ------------------------------------ |
| Web                 | HTTP, HTTPS                          |
| DNS                 | DNS                                  |
| Search / Cloud      | Google, Microsoft                    |
| Social              | Facebook, Instagram, Twitter, TikTok |
| Video               | YouTube, Netflix                     |
| Messaging           | WhatsApp, Telegram, Discord          |
| Productivity        | Zoom                                 |
| Music               | Spotify                              |
| Development         | GitHub                               |
| E-commerce          | Amazon                               |
| Devices / Platforms | Apple                                |
| Unknown             | UNKNOWN                              |

---

# 24. Limitations

This project is designed as a **research and educational network security system**, not as a production-grade IDS/IPS.

### Synthetic training data

The current ML models are trained using synthetic network-flow data rather than a large real-world intrusion dataset.

Therefore, model performance on unseen real-world traffic may differ significantly.

### Encrypted traffic

Modern encrypted protocols can hide application-layer information.

SNI availability can also vary depending on protocol and encryption technology.

### QUIC / HTTP3

QUIC operates over UDP and requires additional protocol handling for deeper analysis.

### Concept drift

Real network traffic changes over time.

A model trained on one traffic distribution may require retraining when deployed in a different environment.

### Rule-based trust

Known/trusted domains are treated differently during threat scoring, so this logic should be carefully reviewed before production deployment.

---

# 25. Future Improvements

## 🤖 Machine Learning

* Train on CIC-IDS2017 / CIC-IDS2018
* Train on UNSW-NB15
* Add XGBoost / LightGBM
* Compare Random Forest with neural networks
* Hyperparameter optimization
* Cross-validation
* Real validation/test split
* Precision, recall, F1 and ROC-AUC evaluation
* Model calibration

## 🌐 Network Security

* QUIC / HTTP3 inspection
* DNS tunneling detection
* JA3 / JA4 TLS fingerprinting
* Port scanning detection
* Brute-force detection
* Botnet detection
* DGA detection
* More protocol support

## ⚡ Performance

* Real-time packet capture
* Multi-threaded ML inference
* Batch inference
* C++ inference engine
* Zero-copy packet processing
* GPU acceleration

## 📊 Dashboard

* Real-time traffic monitoring
* Threat timeline
* Network graph
* Attack distribution charts
* Flow drill-down
* Alert history
* Model confidence visualization

## 🧠 Explainability

* SHAP integration
* Feature importance visualization
* Per-flow explanations
* Attack-pattern explanations
* Confidence calibration

---

# 26. Summary

This project combines **networking, cybersecurity, systems programming and machine learning** into a single pipeline.

The complete system can be summarized as:

```text
             ┌─────────────────────┐
             │      PCAP File      │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │   Packet Parsing    │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │   Flow Tracking     │
             │      5-Tuple        │
             └──────────┬──────────┘
                        │
             ┌──────────┴──────────┐
             │                     │
             ▼                     ▼
      ┌─────────────┐       ┌──────────────┐
      │ SNI / HTTP  │       │ ML Features  │
      │ Inspection  │       │ Extraction    │
      └──────┬──────┘       └──────┬───────┘
             │                     │
             │             ┌───────┴────────┐
             │             │                │
             │             ▼                ▼
             │       Application       Threat Model
             │       Classifier        Classifier
             │             │                │
             │             ▼                ▼
             │       Application        Attack Type
             │       + Confidence       + Anomaly
             │             │                │
             └─────────────┴────────┬───────┘
                                    ▼
                           ┌─────────────────┐
                           │ Threat Scoring  │
                           └────────┬────────┘
                                    │
                         ┌──────────┴──────────┐
                         ▼                     ▼
                      ALLOW                  BLOCK
                         │                     │
                         └──────────┬──────────┘
                                    ▼
                           ┌─────────────────┐
                           │ Reports + PCAP  │
                           └────────┬────────┘
                                    │
                                    ▼
                           ┌─────────────────┐
                           │ Streamlit       │
                           │ Dashboard       │
                           └─────────────────┘
```

## Key Concepts Demonstrated

* Deep Packet Inspection
* Network protocol parsing
* TCP/IP networking
* TLS SNI extraction
* HTTP Host extraction
* Five-tuple flow tracking
* Network feature engineering
* Random Forest classification
* Threat/anomaly detection
* Explainable ML
* Risk scoring
* Rule-based enforcement
* PCAP processing
* JSON/CSV reporting
* Streamlit visualization

The main idea behind the project is:

> **Don't just inspect packets — understand the behavior of the traffic.**

Traditional DPI tells us **what is inside or associated with the traffic**.

Machine learning helps us understand **how that traffic behaves**.

Combining both creates a more complete network threat detection pipeline.
