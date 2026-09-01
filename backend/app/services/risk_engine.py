from typing import Dict, Any, List
from backend.app.models import RiskAssessment, Evidence
from backend.app.evidence.builder import create_canonical_evidence
from backend.app.schemas.scam_dna import ScamDNASchema


class DeterministicRiskEngine:
    """
    Deterministic risk calculation engine based on multi-factor weighted scoring.
    The LLM never calculates risk scores; this engine provides the auditable risk foundation.
    """

    def calculate_incident_risk(
        self,
        incident_id: str,
        dna: ScamDNASchema,
        has_verified_campaign: bool = False,
        known_malware: bool = False,
        provider_malicious_count: int = 0
    ) -> Dict[str, Any]:
        score = 0.0
        factors = []

        # 1. Psychological pressure / Urgency / Fear (up to 25 pts)
        psycho_points = (dna.urgency * 10.0) + (dna.fear * 10.0) + (dna.authority_pressure * 5.0)
        score += psycho_points
        if psycho_points > 12:
            factors.append(f"High psychological coercion tactics (Urgency: {dna.urgency}, Fear: {dna.fear})")

        # 2. Payment or Credential Harvest Redirection (up to 30 pts)
        if dna.credential_request:
            score += 20.0
            factors.append("Credential harvesting targeting banking or personal accounts")
        if dna.payment_request:
            score += 15.0
            factors.append(f"Direct payment redirection via {dna.payment_method.upper()}")

        # 3. Known Infrastructure or Campaign Link (up to 30 pts)
        if has_verified_campaign:
            score += 25.0
            factors.append("Corroborated membership in active malicious campaign syndicate")

        # 4. External Provider Detections (up to 20 pts)
        if provider_malicious_count > 0:
            score += min(20.0, provider_malicious_count * 10.0)
            factors.append(f"{provider_malicious_count} threat intelligence engine detections")

        # 5. Malware Association (up to 20 pts)
        if known_malware:
            score += 20.0
            factors.append("Associated with weaponized malware or phishing kit payload")

        final_score = min(100.0, round(score, 1))

        if final_score >= 80.0:
            severity = "CRITICAL"
        elif final_score >= 60.0:
            severity = "HIGH"
        elif final_score >= 40.0:
            severity = "MEDIUM"
        elif final_score >= 20.0:
            severity = "LOW"
        else:
            severity = "INFO"

        evidence = create_canonical_evidence(
            claim=f"Deterministic risk computed: {final_score}/100 ({severity}) based on {len(factors)} verified factors.",
            evidence_type="INFERRED",
            source="Deterministic Risk Engine",
            confidence=0.98,
            supporting_incident_ids=[incident_id],
            scoring_factors={"factors": factors, "raw_score": final_score}
        )

        return {
            "risk_score": final_score,
            "severity": severity,
            "risk_factors": factors,
            "evidence": {
                "claim": evidence.claim,
                "confidence": evidence.confidence
            }
        }


risk_engine = DeterministicRiskEngine()
