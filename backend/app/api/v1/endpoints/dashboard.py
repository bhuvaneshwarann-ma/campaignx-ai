from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models import Incident, Campaign, Entity, AttackTechnique
from backend.app.providers.manager import provider_manager

router = APIRouter()


@router.get("/dashboard", summary="SOC Dashboard Aggregated Metrics")
def get_dashboard_metrics(db: Session = Depends(get_db)):
    total_incidents = db.query(Incident).count()
    total_campaigns = db.query(Campaign).count()
    active_campaigns = db.query(Campaign).filter(Campaign.status == "ACTIVE").count()
    emerging_campaigns = db.query(Campaign).filter(Campaign.status == "EMERGING").count()
    total_entities = db.query(Entity).count()
    total_techniques = db.query(AttackTechnique).count()

    provider_health = provider_manager.get_provider_health()

    # Incident volume by channel
    channel_counts = {
        "sms": db.query(Incident).filter(Incident.channel == "sms").count(),
        "whatsapp": db.query(Incident).filter(Incident.channel == "whatsapp").count(),
        "email": db.query(Incident).filter(Incident.channel == "email").count(),
        "voice_transcript": db.query(Incident).filter(Incident.channel == "voice_transcript").count(),
    }

    # Incident volume by language
    lang_counts = {
        "english": db.query(Incident).filter(Incident.language == "english").count(),
        "hinglish": db.query(Incident).filter(Incident.language == "hinglish").count(),
        "hindi": db.query(Incident).filter(Incident.language == "hindi").count(),
        "tanglish": db.query(Incident).filter(Incident.language == "tanglish").count(),
        "tamil": db.query(Incident).filter(Incident.language == "tamil").count(),
    }

    # Recent emerging or active campaigns
    top_campaigns = db.query(Campaign).order_by(Campaign.risk_score.desc()).limit(5).all()
    campaign_list = [{
        "campaign_id": c.campaign_id,
        "name": c.name,
        "status": c.status,
        "risk_score": c.risk_score,
        "confidence": c.campaign_confidence,
        "incident_count": len(c.incidents) or c.incident_count
    } for c in top_campaigns]

    return {
        "summary": {
            "total_incidents": total_incidents,
            "total_campaigns": total_campaigns,
            "active_campaigns": active_campaigns,
            "emerging_campaigns": emerging_campaigns,
            "total_entities": total_entities,
            "threat_actors_tracked": 5,
            "malware_families": 4,
            "attack_techniques": total_techniques
        },
        "channel_distribution": channel_counts,
        "language_distribution": lang_counts,
        "top_campaigns": campaign_list,
        "provider_health": provider_health
    }
