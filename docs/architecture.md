# CampaignX AI — System Architecture

CampaignX AI is a unified, evidence-driven threat and scam intelligence platform engineered to bridge technical IOC investigation with multilingual scam telemetry.

```
USER INPUT (IOC or Multilingual Scam Message)
    │
    ▼
INPUT TYPE & LANGUAGE DETECTION
    │
    ▼
NORMALIZATION & ENTITY RESOLUTION (Phones, UPIs, Domains, IPs, Hashes)
    │
    ▼
SCAM DNA EXTRACTION (Taxonomic Targets, Urgency, Fear, Payment Channels)
    │
    ▼
THREAT INTELLIGENCE PROVIDERS (ThreatFusion, VirusTotal, AbuseIPDB, Offline Mock)
    │
    ▼
HYBRID CORRELATION ENGINE (Stage 1: ML Candidates → Stage 2: Deterministic Verification)
    │
    ▼
FALSE-POSITIVE REJECTION DEFENSE (Rejects generic keywords without shared infrastructure)
    │
    ▼
CANONICAL EVIDENCE LEDGER (OBSERVED, INFERRED, PREDICTED)
    │
    ▼
THREAT GRAPH & CAMPAIGN CLUSTERING (NetworkX + React Flow)
    │
    ▼
DETERMINISTIC RISK ENGINE (Multi-factor weighted scoring)
    │
    ▼
AI INVESTIGATOR (Gemini / Grok / OpenRouter / Deterministic Mock Fallback)
    │
    ▼
SOC DASHBOARD & EXPORT (STIX 2.1 / JSON / CSV)
```
