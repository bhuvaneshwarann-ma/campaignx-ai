from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models import Incident, Campaign
from backend.app.schemas.api import AIAnalysisRequest
from backend.app.ai.investigator import ai_investigator
from backend.app.core.security import check_prompt_injection

router = APIRouter()


@router.post("/analyze", summary="Run AI Grounded Investigation Analysis")
async def run_ai_analysis(
    payload: AIAnalysisRequest,
    db: Session = Depends(get_db)
):
    if check_prompt_injection(payload.query):
        raise HTTPException(status_code=400, detail="Disallowed instruction or prompt injection detected.")

    context = dict(payload.context)

    # Enrich context if incident_id or campaign_id supplied
    if payload.incident_id:
        inc = db.query(Incident).filter(
            (Incident.id == payload.incident_id) | (Incident.incident_id == payload.incident_id)
        ).first()
        if inc:
            context["incident_id"] = inc.incident_id
            context["channel"] = inc.channel
            context["language"] = inc.language
            if inc.campaign:
                context["campaign_name"] = inc.campaign.name
                context["shared_elements"] = inc.campaign.shared_infrastructure
            if inc.scam_dna:
                context["tactics"] = inc.scam_dna.social_engineering_tactics
                context["urgency"] = inc.scam_dna.urgency

    if payload.campaign_id:
        camp = db.query(Campaign).filter(
            (Campaign.id == payload.campaign_id) | (Campaign.campaign_id == payload.campaign_id)
        ).first()
        if camp:
            context["campaign_name"] = camp.name
            context["shared_elements"] = camp.shared_infrastructure
            context["risk_score"] = camp.risk_score

    res = await ai_investigator.analyze(payload.query, context)
    return res.model_dump()
