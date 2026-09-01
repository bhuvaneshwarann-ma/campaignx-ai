import json
from pathlib import Path
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.app.database.session import SessionLocal, Base, engine
from backend.app.database.init_db import init_db
from backend.app.ml.synthetic_generator import generate_synthetic_dataset
from backend.app.services.scam_dna_extractor import extract_scam_dna
from backend.app.services.entity_resolver import extract_and_resolve_entities
from backend.app.models import Campaign, Incident, ScamDNA, Entity, EntityMention, ThreatActor, MalwareFamily
from backend.app.core.logging import logger

DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)



def seed_database():
    """Seeds database with synthetic campaigns, incidents, entities, and actors."""
    logger.info("Initializing DB schema...")
    init_db()

    incidents_file = DATA_DIR / "synthetic_incidents.json"
    campaigns_file = DATA_DIR / "synthetic_campaigns.json"

    if not incidents_file.exists() or not campaigns_file.exists():
        logger.info("Generating synthetic data...")
        generate_synthetic_dataset()

    with open(incidents_file, "r", encoding="utf-8") as f:
        incidents_data = json.load(f)
    with open(campaigns_file, "r", encoding="utf-8") as f:
        campaigns_data = json.load(f)

    db: Session = SessionLocal()
    try:
        # Check if already seeded
        if db.query(Campaign).count() > 0:
            logger.info("Database already seeded with campaigns.")
            return

        # 1. Seed Campaigns
        campaign_map = {}
        for c in campaigns_data:
            camp = Campaign(
                campaign_id=c["campaign_id"],
                name=c["name"],
                description=f"Automated threat intelligence tracking {c['name']} across multi-channel telemetry.",
                status="ACTIVE",
                risk_score=88.0,
                campaign_confidence=0.94,
                shared_infrastructure=[f"Phone:{p}" for p in c["phones"]] + [f"UPI:{u}" for u in c["upis"]] + [f"Domain:{d}" for d in c["domains"]],
                behavioral_overlap={"tactics": c["tactics"], "languages": c["languages"]}
            )
            db.add(camp)
            db.flush()
            campaign_map[c["campaign_id"]] = camp.id

            # Seed Threat Actor
            if c.get("actor") and c["actor"] != "None":
                if not db.query(ThreatActor).filter(ThreatActor.name == c["actor"]).first():
                    actor = ThreatActor(
                        name=c["actor"],
                        aliases=[f"APT-{c['actor']}"],
                        attribution_level="STRONGLY_ASSOCIATED",
                        description=f"Financially motivated threat syndicate behind {c['name']}.",
                        infrastructure=c["domains"] + c["ips"],
                        associated_malware=[c["malware"]] if c.get("malware") and c["malware"] != "None" else [],
                        techniques=["T1566.002", "T1071.001"]
                    )
                    db.add(actor)

            # Seed Malware
            if c.get("malware") and c["malware"] != "None":
                if not db.query(MalwareFamily).filter(MalwareFamily.name == c["malware"]).first():
                    malware = MalwareFamily(
                        name=c["malware"],
                        aliases=[f"Win32/{c['malware']}"],
                        malware_type="STEALER" if "Stealer" in c["malware"] else "TROJAN",
                        description=f"Weaponized payload utilized in {c['name']}.",
                        signatures=c["hashes"],
                        techniques=["T1059.001", "T1071.001"]
                    )
                    db.add(malware)

        # 2. Seed Incidents
        for inc in incidents_data:
            camp_fk = campaign_map.get(inc.get("campaign_id"))
            incident = Incident(
                incident_id=inc["incident_id"],
                channel=inc["channel"],
                language=inc["language"],
                raw_content=inc["raw_content"],
                normalized_content=inc["raw_content"],
                source="telemetry_stream",
                status="analyzed",
                campaign_id=camp_fk
            )
            db.add(incident)
            db.flush()

            # Extract & Save Scam DNA
            dna_schema = extract_scam_dna(inc["raw_content"], channel=inc["channel"])
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

            # Entities
            extracted_entities = extract_and_resolve_entities(inc["raw_content"])
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
                        risk_score=85.0 if camp_fk else 0.0
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
        logger.info("Seeding completed successfully!")
    except Exception as e:
        db.rollback()
        logger.error(f"Seeding failed: {e}")
        raise e
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
