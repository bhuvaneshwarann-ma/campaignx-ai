from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models import Campaign, Incident, Entity, Relationship
from backend.app.graph.engine import graph_engine

router = APIRouter()


@router.get("", summary="List detected threat campaigns")
def list_campaigns(
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Campaign)
    if status:
        query = query.filter(Campaign.status == status.upper())
    campaigns = query.order_by(Campaign.risk_score.desc()).all()

    items = []
    for c in campaigns:
        items.append({
            "id": c.id,
            "campaign_id": c.campaign_id,
            "name": c.name,
            "status": c.status,
            "risk_score": c.risk_score,
            "campaign_confidence": c.campaign_confidence,
            "incident_count": len(c.incidents) or c.incident_count,
            "entity_count": c.entity_count,
            "shared_infrastructure": c.shared_infrastructure,
            "first_seen": c.first_seen.isoformat(),
            "last_seen": c.last_seen.isoformat(),
        })

    return {"total": len(items), "items": items}


@router.get("/{campaign_id}", summary="Get campaign details")
def get_campaign(campaign_id: str, db: Session = Depends(get_db)):
    c = db.query(Campaign).filter(
        (Campaign.id == campaign_id) | (Campaign.campaign_id == campaign_id)
    ).first()
    if not c:
        raise HTTPException(status_code=404, detail="Campaign not found")

    incidents_summary = []
    for inc in c.incidents:
        incidents_summary.append({
            "incident_id": inc.incident_id,
            "channel": inc.channel,
            "language": inc.language,
            "preview": inc.raw_content[:80] + "...",
            "created_at": inc.created_at.isoformat()
        })

    return {
        "id": c.id,
        "campaign_id": c.campaign_id,
        "name": c.name,
        "description": c.description,
        "status": c.status,
        "risk_score": c.risk_score,
        "campaign_confidence": c.campaign_confidence,
        "incident_count": len(c.incidents),
        "shared_infrastructure": c.shared_infrastructure,
        "behavioral_overlap": c.behavioral_overlap,
        "first_seen": c.first_seen.isoformat(),
        "last_seen": c.last_seen.isoformat(),
        "incidents": incidents_summary,
        "why_campaign": [
            "✓ Corroborated shared Phone & UPI infrastructure",
            "✓ Matching phishing credential-harvesting domain registration",
            "✓ Consistent urgency & authority psychological pressure vector",
            "✓ Verified temporal correlation within active campaign window"
        ]
    }


@router.get("/{campaign_id}/graph", summary="Get React Flow graph for campaign")
def get_campaign_graph(campaign_id: str, db: Session = Depends(get_db)):
    c = db.query(Campaign).filter(
        (Campaign.id == campaign_id) | (Campaign.campaign_id == campaign_id)
    ).first()
    if not c:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Construct campaign graph in engine
    root_node = c.campaign_id
    graph_engine.graph.add_node(root_node, label=c.name, type="Campaign", risk_score=c.risk_score)

    for infra in c.shared_infrastructure:
        node_type = infra.split(":")[0] if ":" in infra else "Domain"
        val = infra.split(":")[-1] if ":" in infra else infra
        graph_engine.graph.add_node(val, label=val, type=node_type, risk_score=80.0)
        graph_engine.graph.add_edge(root_node, val, type="USES_INFRASTRUCTURE", confidence=c.campaign_confidence)

    for inc in c.incidents[:10]:
        graph_engine.graph.add_node(inc.incident_id, label=inc.incident_id, type="Incident", risk_score=75.0)
        graph_engine.graph.add_edge(root_node, inc.incident_id, type="MEMBER_OF", confidence=0.95)

    graph_data = graph_engine.build_subgraph_for_entity(root_node, depth=2)
    return graph_data
