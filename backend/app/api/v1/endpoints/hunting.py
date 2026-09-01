from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.schemas.api import ThreatHuntingRequest
from backend.app.graph.engine import graph_engine
from backend.app.providers.manager import provider_manager

router = APIRouter()


@router.get("", summary="Execute Threat Hunting Pivot (GET)")
@router.get("/hunt", summary="Execute Threat Hunting Pivot (GET /hunt)")
async def execute_threat_hunt_get(
    ioc: str = "185.220.101.5",
    mode: str = "DEEP",
    depth: int = 2,
    db: Session = Depends(get_db)
):
    return await execute_threat_hunt(ThreatHuntingRequest(seed_indicator=ioc, mode=mode, depth=depth), db=db)


@router.post("", summary="Execute Threat Hunting Pivot (Lite / Deep)")
@router.post("/hunt", summary="Execute Threat Hunting Pivot POST (/hunt)")
async def execute_threat_hunt(
    payload: ThreatHuntingRequest,
    db: Session = Depends(get_db)
):

    seed = payload.seed_indicator.strip()
    depth = max(1, min(5, payload.depth))
    is_deep = payload.mode.upper() == "DEEP"

    # Query baseline provider data for seed
    provider_results = await provider_manager.lookup_indicator(seed, "AUTO")
    
    # Register seed in graph
    graph_engine.graph.add_node(seed, label=seed, type="RootIOC", risk_score=85.0)

    # Simulated multi-hop pivots for deep hunting
    if is_deep or depth >= 2:
        # Hop 1: Related Domain / IP
        domain = f"c2-{seed.replace('.', '-')}.net" if "." in seed else "auth-gateway.org"
        ip = "185.220.101.5"
        graph_engine.graph.add_node(domain, label=domain, type="Domain", risk_score=90.0)
        graph_engine.graph.add_node(ip, label=ip, type="IP", risk_score=92.0)
        graph_engine.graph.add_edge(seed, domain, type="RESOLVES_TO", confidence=0.95)
        graph_engine.graph.add_edge(domain, ip, type="HOSTED_ON", confidence=0.98)

        # Hop 2: Malware Payload
        malware = "FakeBank APK Stealer"
        graph_engine.graph.add_node(malware, label=malware, type="Malware", risk_score=95.0)
        graph_engine.graph.add_edge(ip, malware, type="DELIVERS", confidence=0.91)

        # Hop 3: Threat Actor & ATT&CK
        actor = "PhantomRaven"
        tactic = "T1566.002"
        graph_engine.graph.add_node(actor, label=actor, type="ThreatActor", risk_score=98.0)
        graph_engine.graph.add_node(tactic, label=tactic, type="ATT&CK", risk_score=80.0)
        graph_engine.graph.add_edge(malware, actor, type="ATTRIBUTED_TO", confidence=0.88)
        graph_engine.graph.add_edge(actor, tactic, type="USES_TECHNIQUE", confidence=0.94)

    graph_data = graph_engine.build_subgraph_for_entity(seed, depth=depth)

    return {
        "seed_indicator": seed,
        "mode": payload.mode,
        "depth": depth,
        "pivots_discovered": graph_data["stats"]["node_count"],
        "graph": graph_data,
        "recommendations": [
            f"Pivot to upstream hosting provider for IP infrastructure",
            f"Block correlated MITRE ATT&CK technique T1566.002 across mail gateways",
            f"Perform certificate transparency log monitoring for related domains"
        ]
    }
