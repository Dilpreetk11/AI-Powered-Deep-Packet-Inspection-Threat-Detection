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
