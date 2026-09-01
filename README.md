# CAMPAIGNX AI — Unified Threat & Scam Intelligence Platform

> **"From Indicators and Messages to the Campaign Behind the Threat."**

An evidence-driven threat and scam intelligence platform that connects suspicious technical indicators, scam communications, infrastructure, malware, and attacker techniques into unified campaigns with deterministic verification and explainable AI.

---

## ⚡ Core Capabilities

- **Unified Universal Ingestion**: Ingest IOCs (IP, domain, hash, URL, CVE, email, phone, UPI) and multilingual scam messages (English, Hindi, Hinglish, Tamil, Tanglish).
- **Scam DNA Extraction**: Strict taxonomic extraction of impersonation targets, psychological pressure tactics, payment mechanisms, and indicators.
- **Canonical Entity Resolution**: Automatic normalization, deduplication, and PII masking (HMAC-SHA256).
- **Hybrid Correlation Engine**: ML candidate relationship generation coupled with strict deterministic multi-factor verification.
- **False-Positive Defense**: Rejects campaign grouping based on generic keyword similarities alone without corroborated shared infrastructure.
- **Interactive Threat Graph**: High-density interactive node-link visualization powered by NetworkX and React Flow.
- **Evidence Drawer & Namespaces**: Every link and finding links to canonical, auditable evidence records (`OBSERVED`, `INFERRED`, `PREDICTED`).
- **AI Investigator**: Grounded analysis engine with Gemini, Grok, OpenRouter, and Deterministic Offline Mock providers.
- **100% Offline Capability**: Runs completely standalone with synthetic datasets, deterministic providers, and zero external dependency requirements.

---

## 🏗️ Architecture

```
campaignx-ai/
├── backend/               # FastAPI, SQLAlchemy, NetworkX, ML & AI Pipeline
│   ├── app/
│   │   ├── api/          # REST Endpoints
│   │   ├── core/         # Config, Logging, Security
│   │   ├── models/       # SQLAlchemy Data Models
│   │   ├── schemas/      # Pydantic v2 Schemas
│   │   ├── providers/    # Threat Intel & AI Providers
│   │   ├── ml/           # ML Candidate Generation & Embeddings
│   │   ├── correlation/  # Deterministic Correlation Engine
│   │   ├── graph/        # NetworkX Graph Engine
│   │   ├── campaigns/    # Campaign Clustering & Emerging Detector
│   │   ├── evidence/     # Evidence Engine & Confidence Namespaces
│   │   └── reports/      # PDF, JSON, CSV, STIX 2.1 Export
│   └── tests/            # Pytest Test Suites
├── frontend/             # React + Vite + Tailwind + React Flow + Recharts
├── data/                 # Seed Data & Ground Truth Synthetic Datasets
├── docs/                 # Architecture, API, & Evaluation Documentation
└── docker-compose.yml    # Containerized deployment
```

---

## 🚀 Quickstart (Local Offline Mode)

### Backend

```bash
# 1. Install dependencies
pip install -r backend/requirements.txt

# 2. Run backend (default MODE=offline, SQLite)
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

Interactive API documentation available at: `http://localhost:8000/docs`

### Frontend

```bash
# 1. Install dependencies
cd frontend
npm install

# 2. Start dev server
npm run dev
```

Dashboard accessible at: `http://localhost:5173`

---

## 🧪 Running Automated Tests

```bash
pytest backend/tests -v
```

---

## 🐳 Docker Deployment

```bash
docker compose up -d --build
```
