import uuid
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models import Incident, ScamDNA, Entity, EntityMention, Campaign, Relationship
from backend.app.schemas.api import IncidentCreate
from backend.app.services.scam_dna_extractor import extract_scam_dna
from backend.app.services.entity_resolver import extract_and_resolve_entities
from backend.app.services.risk_engine import risk_engine
from backend.app.campaigns.detector import campaign_detector
from backend.app.core.security import check_prompt_injection

router = APIRouter()


@router.post("", summary="Submit and analyze a new suspicious incident")
async def create_incident(
    payload: IncidentCreate,
    db: Session = Depends(get_db)
):
    # 1. Security validation
    if check_prompt_injection(payload.raw_content):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Potential prompt injection or invalid command format detected."
        )

    # 2. Extract Scam DNA
    dna_schema = extract_scam_dna(payload.raw_content, channel=payload.channel)
    
    # 3. Extract and resolve canonical entities
    extracted_entities = extract_and_resolve_entities(payload.raw_content)

    # 4. Generate incident identifier
    count = db.query(Incident).count()
    inc_code = f"INC-{count + 1:04d}"

    # 5. Check if it correlates with an existing campaign
    active_campaigns = db.query(Campaign).all()
    assigned_campaign_id = None
    
    # Check infrastructure overlap with active campaigns
    infra_set = set(dna_schema.phone_numbers + dna_schema.upi_ids + dna_schema.domains + dna_schema.urls)
    for camp in active_campaigns:
        camp_infra = set(camp.shared_infrastructure or [])
        # Also check target detail
        if infra_set.intersection(camp_infra) or (camp.name and dna_schema.impersonation_target and dna_schema.impersonation_target.lower() in camp.name.lower()):
            assigned_campaign_id = camp.id
            break

    # If no existing campaign matches and high threat/scam confidence, create a live emerging campaign
    if not assigned_campaign_id and (dna_schema.impersonation_target != "none" or len(infra_set) > 0):
        target_name = dna_schema.impersonation_target_detail or (dna_schema.impersonation_target.title() if dna_schema.impersonation_target else "Suspicious Activity")
        camp_code = f"CAM-LIVE-{uuid.uuid4().hex[:6].upper()}"
        new_camp = Campaign(
            campaign_id=camp_code,
            name=f"{target_name} Threat Campaign",
            description=f"Automated threat campaign tracking {target_name} across live ingestion telemetry.",
            status="EMERGING",
            risk_score=85.0,
            campaign_confidence=0.88,
            shared_infrastructure=list(infra_set),
            behavioral_overlap={"tactics": dna_schema.social_engineering_tactics, "languages": [dna_schema.language]}
        )
        db.add(new_camp)
        db.flush()
        assigned_campaign_id = new_camp.id
    
    # Evaluate risk score
    risk_info = risk_engine.calculate_incident_risk(
        incident_id=inc_code,
        dna=dna_schema,
        has_verified_campaign=bool(assigned_campaign_id)
    )

    incident = Incident(
        incident_id=inc_code,
        channel=payload.channel,
        language=dna_schema.language,
        raw_content=payload.raw_content,
        normalized_content=payload.raw_content,
        source=payload.source,
        tags=payload.tags,
        status="analyzed",
        campaign_id=assigned_campaign_id
    )
    db.add(incident)
    db.flush()

    # Save ScamDNA
    scam_dna = ScamDNA(
        incident_id=incident.id,
        language=dna_schema.language,
        channel=dna_schema.channel,
        impersonation_target=dna_schema.impersonation_target,
        impersonation_target_detail=dna_schema.impersonation_target_detail,
        urgency=dna_schema.urgency,
        fear=dna_schema.fear,
        authority_pressure=dna_schema.authority_pressure,
        credential_request=dna_schema.credential_request,
        payment_request=dna_schema.payment_request,
        payment_method=dna_schema.payment_method,
        requested_action=dna_schema.requested_action,
        social_engineering_tactics=dna_schema.social_engineering_tactics,
        target_type=dna_schema.target_type,
        script_features=dna_schema.script_features,
        infrastructure_indicators=dna_schema.infrastructure_indicators,
        phone_numbers=dna_schema.phone_numbers,
        upi_ids=dna_schema.upi_ids,
        urls=dna_schema.urls,
        domains=dna_schema.domains,
        emails=dna_schema.emails,
        extraction_confidence=dna_schema.extraction_confidence
    )
    db.add(scam_dna)

    # Save entities & mentions
    for ent in extracted_entities:
        db_ent = db.query(Entity).filter(
            Entity.type == ent.type,
            Entity.canonical_value == ent.canonical_value
        ).first()

        if not db_ent:
            db_ent = Entity(
                type=ent.type,
                canonical_value=ent.canonical_value,
                raw_value=ent.raw_value,
                masked_value=ent.masked_value,
                risk_score=risk_info["risk_score"]
            )
            db.add(db_ent)
            db.flush()

        mention = EntityMention(
            incident_id=incident.id,
            entity_id=db_ent.id,
            confidence=ent.confidence
        )
        db.add(mention)

    db.commit()
    db.refresh(incident)

    return {
        "id": incident.id,
        "incident_id": incident.incident_id,
        "channel": incident.channel,
        "language": incident.language,
        "status": incident.status,
        "risk_assessment": risk_info,
        "scam_dna": dna_schema.model_dump(),
        "entities_count": len(extracted_entities),
        "created_at": incident.created_at.isoformat()
    }


@router.get("", summary="List incidents with pagination")
def list_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    channel: Optional[str] = None,
    language: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Incident)
    if channel:
        query = query.filter(Incident.channel == channel)
    if language:
        query = query.filter(Incident.language == language)
        
    total = query.count()
    incidents = query.order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()

    items = []
    for inc in incidents:
        items.append({
            "id": inc.id,
            "incident_id": inc.incident_id,
            "channel": inc.channel,
            "language": inc.language,
            "raw_content": inc.raw_content[:120] + "..." if len(inc.raw_content) > 120 else inc.raw_content,
            "campaign_id": inc.campaign.campaign_id if inc.campaign else None,
            "campaign_name": inc.campaign.name if inc.campaign else None,
            "created_at": inc.created_at.isoformat()
        })

    return {"total": total, "items": items, "skip": skip, "limit": limit}


@router.get("/{incident_id}", summary="Get incident details by ID")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(
        (Incident.id == incident_id) | (Incident.incident_id == incident_id)
    ).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    dna_dict = None
    if inc.scam_dna:
        dna_dict = {
            "impersonation_target": inc.scam_dna.impersonation_target,
            "impersonation_target_detail": inc.scam_dna.impersonation_target_detail,
            "urgency": inc.scam_dna.urgency,
            "fear": inc.scam_dna.fear,
            "authority_pressure": inc.scam_dna.authority_pressure,
            "credential_request": inc.scam_dna.credential_request,
            "payment_request": inc.scam_dna.payment_request,
            "payment_method": inc.scam_dna.payment_method,
            "social_engineering_tactics": inc.scam_dna.social_engineering_tactics,
            "script_features": inc.scam_dna.script_features,
            "phone_numbers": inc.scam_dna.phone_numbers,
            "upi_ids": inc.scam_dna.upi_ids,
            "urls": inc.scam_dna.urls,
            "domains": inc.scam_dna.domains,
            "extraction_confidence": inc.scam_dna.extraction_confidence
        }

    entities = []
    for mention in inc.entity_mentions:
        entities.append({
            "type": mention.entity.type,
            "canonical_value": mention.entity.canonical_value,
            "masked_value": mention.entity.masked_value,
            "risk_score": mention.entity.risk_score
        })

    return {
        "id": inc.id,
        "incident_id": inc.incident_id,
        "channel": inc.channel,
        "language": inc.language,
        "raw_content": inc.raw_content,
        "campaign_id": inc.campaign.campaign_id if inc.campaign else None,
        "campaign_name": inc.campaign.name if inc.campaign else None,
        "scam_dna": dna_dict,
        "entities": entities,
        "created_at": inc.created_at.isoformat()
    }
