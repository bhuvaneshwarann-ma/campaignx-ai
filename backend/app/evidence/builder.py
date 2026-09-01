from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from backend.app.models import Evidence


def create_canonical_evidence(
    claim: str,
    evidence_type: str,  # OBSERVED, INFERRED, PREDICTED
    source: str,
    confidence: float,
    supporting_incident_ids: Optional[List[str]] = None,
    supporting_entity_ids: Optional[List[str]] = None,
    supporting_relationship_ids: Optional[List[str]] = None,
    scoring_factors: Optional[Dict[str, Any]] = None,
) -> Evidence:
    """
    Creates a validated canonical Evidence database instance.
    Enforces strict typing (OBSERVED, INFERRED, PREDICTED) and auditable provenance.
    """
    valid_types = {"OBSERVED", "INFERRED", "PREDICTED"}
    norm_type = evidence_type.upper()
    if norm_type not in valid_types:
        norm_type = "INFERRED"

    return Evidence(
        claim=claim,
        type=norm_type,
        source=source,
        confidence=max(0.0, min(1.0, float(confidence))),
        supporting_incident_ids=supporting_incident_ids or [],
        supporting_entity_ids=supporting_entity_ids or [],
        supporting_relationship_ids=supporting_relationship_ids or [],
        scoring_factors=scoring_factors or {},
        timestamp=datetime.now(timezone.utc)
    )
