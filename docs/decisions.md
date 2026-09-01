# Architectural Decisions & Rationales

## 1. Two-Stage Hybrid Correlation
- **Rationale**: Relying solely on ML text embeddings creates severe false positives where benign bank messages cluster with phishing syndicates. We separate ML candidate discovery from deterministic infrastructure corroboration (shared phone, UPI, domain, hash).

## 2. PII HMAC Masking
- **Rationale**: Telemetry contains real phone numbers and UPI IDs. To comply with privacy and SOC security standards, all raw PII is masked with HMAC-SHA256 tokens in logs while remaining auditable for permitted investigators.

## 3. Strict Deterministic AI Grounding
- **Rationale**: Standard LLMs hallucinate non-existent IOCs, malware families, and confidence numbers. CampaignX AI strictly restricts the AI Investigator to supplied verified telemetry and deterministic risk scores.
