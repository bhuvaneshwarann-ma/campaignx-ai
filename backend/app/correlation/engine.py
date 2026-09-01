from typing import Tuple, Dict, Any, List, Optional
from backend.app.schemas.scam_dna import ScamDNASchema
from backend.app.ml.candidate_generator import candidate_generator
from backend.app.evidence.builder import create_canonical_evidence
from backend.app.models import Evidence


class VerificationResult:
    def __init__(
        self,
        is_verified: bool,
        confidence: float,
        probability: float,
        reason: str,
        shared_elements: List[str],
        evidence: Optional[Evidence] = None,
        scoring_factors: Optional[Dict[str, Any]] = None
    ):
        self.is_verified = is_verified
        self.relationship_confidence = confidence
        self.relationship_probability = probability
        self.verification_reason = reason
        self.shared_elements = shared_elements
        self.evidence = evidence
        self.scoring_factors = scoring_factors or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_verified": self.is_verified,
            "relationship_confidence": self.relationship_confidence,
            "relationship_probability": self.relationship_probability,
            "verification_reason": self.verification_reason,
            "shared_elements": self.shared_elements,
            "scoring_factors": self.scoring_factors,
            "evidence": {
                "claim": self.evidence.claim,
                "type": self.evidence.type,
                "confidence": self.evidence.confidence
            } if self.evidence else None
        }


class HybridCorrelationEngine:
    """
    Two-Stage Hybrid Correlation Pipeline:
    - Stage 1: ML Candidate Generation (computes relationship_probability)
    - Stage 2: Deterministic Multi-factor Verification (computes relationship_confidence)
    - False-Positive Protection: Rejects generic similarity without shared infrastructure.
    """

    def correlate_incidents(
        self,
        inc_a_id: str,
        dna_a: ScamDNASchema,
        text_a: str,
        inc_b_id: str,
        dna_b: ScamDNASchema,
        text_b: str
    ) -> VerificationResult:
        # Stage 1: ML Candidate Probability
        prob, ml_factors = candidate_generator.compute_candidate_probability(
            dna_a, dna_b, text_a, text_b
        )

        # Stage 2: Deterministic Verification
        shared_phones = set(dna_a.phone_numbers).intersection(set(dna_b.phone_numbers))
        shared_upis = set(dna_a.upi_ids).intersection(set(dna_b.upi_ids))
        shared_domains = set(dna_a.domains).intersection(set(dna_b.domains))
        shared_urls = set(dna_a.urls).intersection(set(dna_b.urls))
        
        shared_elements = []
        corroboration_points = 0
        base_confidence = 0.0

        if shared_phones:
            for p in shared_phones:
                shared_elements.append(f"Phone: {p}")
            corroboration_points += 4
            base_confidence = max(base_confidence, 0.94)

        if shared_upis:
            for u in shared_upis:
                shared_elements.append(f"UPI: {u}")
            corroboration_points += 4
            base_confidence = max(base_confidence, 0.95)

        if shared_domains:
            for d in shared_domains:
                shared_elements.append(f"Domain: {d}")
            corroboration_points += 3
            base_confidence = max(base_confidence, 0.90)

        if shared_urls:
            for u in shared_urls:
                shared_elements.append(f"URL: {u}")
            corroboration_points += 3
            base_confidence = max(base_confidence, 0.92)

        # FALSE POSITIVE PROTECTION
        if corroboration_points == 0:
            # Rejection: Generic similarity only
            reason = "Generic behavioral similarity was insufficient to establish campaign membership."
            evidence = create_canonical_evidence(
                claim=f"Correlation rejected between {inc_a_id} and {inc_b_id}: lack of shared infrastructure.",
                evidence_type="PREDICTED",
                source="Correlation Engine (False Positive Defense)",
                confidence=0.10,
                supporting_incident_ids=[inc_a_id, inc_b_id],
                scoring_factors={**ml_factors, "corroboration_points": 0}
            )
            return VerificationResult(
                is_verified=False,
                confidence=0.0,
                probability=prob,
                reason=reason,
                shared_elements=[],
                evidence=evidence,
                scoring_factors=ml_factors
            )

        # Verified Relationship
        verified_confidence = round(min(0.99, base_confidence + (0.02 * min(3, len(shared_elements) - 1))), 2)
        claim = f"Deterministic link established via shared {', '.join(shared_elements)}"
        evidence = create_canonical_evidence(
            claim=claim,
            evidence_type="OBSERVED",
            source="Correlation Engine (Deterministic Verifier)",
            confidence=verified_confidence,
            supporting_incident_ids=[inc_a_id, inc_b_id],
            scoring_factors={
                **ml_factors,
                "corroboration_points": corroboration_points,
                "shared_elements": shared_elements
            }
        )

        return VerificationResult(
            is_verified=True,
            confidence=verified_confidence,
            probability=prob,
            reason=claim,
            shared_elements=shared_elements,
            evidence=evidence,
            scoring_factors={**ml_factors, "corroboration_points": corroboration_points}
        )


correlation_engine = HybridCorrelationEngine()
