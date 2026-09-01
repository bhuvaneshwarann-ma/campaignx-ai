from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models import AttackTechnique, Incident, Campaign, Entity
from backend.app.graph.engine import graph_engine

router = APIRouter()


@router.get("/global", summary="Get Global Threat Intelligence Graph")
def get_global_threat_graph(db: Session = Depends(get_db)):
    """
    Returns the real-time active threat graph constructed from live database records.
    """
    # Ensure graph is populated with latest database campaigns and entities
    campaigns = db.query(Campaign).all()
    for camp in campaigns:
        graph_engine.graph.add_node(
            camp.campaign_id,
            label=camp.name,
            type="Campaign",
            risk_score=camp.risk_score
        )
        if camp.shared_infrastructure:
            for infra in camp.shared_infrastructure:
                graph_engine.graph.add_node(
                    infra,
                    label=infra,
                    type="Infrastructure",
                    risk_score=camp.risk_score
                )
                graph_engine.graph.add_edge(
                    camp.campaign_id,
                    infra,
                    type="USES_INFRASTRUCTURE",
                    confidence=camp.campaign_confidence
                )

    return graph_engine.serialize_graph()
