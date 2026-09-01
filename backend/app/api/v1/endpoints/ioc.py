import re
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models import Entity, Observation
from backend.app.schemas.api import UniversalSearchRequest
from backend.app.services.entity_resolver import extract_and_resolve_entities
from backend.app.providers.manager import provider_manager
from backend.app.services.risk_engine import risk_engine
from backend.app.graph.engine import graph_engine

router = APIRouter()


def detect_query_type(query: str) -> str:
    q = query.strip()
    if re.match(r'^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$', q):
        return "HASH"
    if re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', q):
        return "IP"
    if re.match(r'^https?://', q, re.IGNORECASE):
        return "URL"
    if re.match(r'^CVE-\d{4}-\d{4,7}$', q, re.IGNORECASE):
        return "CVE"
    if "@" in q and ("." in q.split("@")[-1]):
        return "EMAIL"
    if "@" in q:
        return "UPI"
    if re.match(r'^\+?[0-9\s\-()]{10,16}$', q):
        return "PHONE"
    if re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$', q):
        return "DOMAIN"
    return "TEXT"


@router.get("/lookup", summary="Universal IOC Investigation Search (GET)")
async def universal_ioc_lookup_get(
    query: str,
    depth: int = 2,
    db: Session = Depends(get_db)
):
    return await universal_ioc_lookup(UniversalSearchRequest(query=query, depth=depth), db=db)


@router.post("/lookup", summary="Universal IOC Investigation Search")
async def universal_ioc_lookup(
    payload: UniversalSearchRequest,
    db: Session = Depends(get_db)
):

    query = payload.query.strip()
    detected_type = detect_query_type(query)

    # 1. Query Providers
    provider_results = await provider_manager.lookup_indicator(query, detected_type)
    
    # 2. Extract and resolve canonical entity
    entities = extract_and_resolve_entities(query)
    canonical = entities[0].canonical_value if entities else query
    masked = entities[0].masked_value if entities else query

    # 3. Calculate Risk
    malicious_count = sum(1 for r in provider_results if r.verdict == "MALICIOUS")
    is_mal = malicious_count > 0
    
    score = 85.0 if is_mal else (30.0 if any(r.verdict == "SUSPICIOUS" for r in provider_results) else 0.0)
    severity = "CRITICAL" if score >= 80 else ("HIGH" if score >= 60 else ("MEDIUM" if score >= 40 else "CLEAN"))

    # 4. Extract Threat Actor / Malware details from provider results
    malware_family = next((r.malware_family for r in provider_results if r.malware_family), None)
    actors = list(set([actor for r in provider_results for actor in r.associated_actors]))
    techniques = list(set([tech for r in provider_results for tech in r.mitre_techniques]))

    # 5. Build Graph Representation
    graph_engine.graph.add_node(canonical, label=canonical, type=detected_type, risk_score=score)
    if malware_family:
        graph_engine.graph.add_node(malware_family, label=malware_family, type="Malware", risk_score=90.0)
        graph_engine.graph.add_edge(canonical, malware_family, type="USES_MALWARE", confidence=0.95)
    for a in actors:
        graph_engine.graph.add_node(a, label=a, type="ThreatActor", risk_score=95.0)
        graph_engine.graph.add_edge(canonical, a, type="ATTRIBUTED_TO", confidence=0.88)
    for t in techniques:
        graph_engine.graph.add_node(t, label=t, type="ATT&CK", risk_score=70.0)
        graph_engine.graph.add_edge(canonical, t, type="USES_TECHNIQUE", confidence=0.90)

    graph_data = graph_engine.build_subgraph_for_entity(canonical, depth=payload.depth)

    return {
        "query": query,
        "detected_type": detected_type,
        "canonical_value": canonical,
        "masked_value": masked,
        "risk_assessment": {
            "risk_score": score,
            "severity": severity,
            "malicious_engines": malicious_count
        },
        "intelligence": {
            "malware_family": malware_family,
            "associated_actors": actors,
            "mitre_techniques": techniques
        },
        "providers": [r.model_dump() for r in provider_results],
        "graph": graph_data
    }
