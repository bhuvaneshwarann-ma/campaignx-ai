import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app.database.session import Base
from backend.app.database.init_db import init_db, get_password_hash
from backend.app.models import (
    User, Campaign, Incident, ScamDNA, Entity, EntityMention,
    Relationship, Evidence, RiskAssessment, Observation, ThreatActor,
    MalwareFamily, AttackTechnique, Investigation, AIReport, AuditLog
)

# Test in-memory SQLite DB
TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="module")
def db():
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    init_db(session)
    yield session
    session.close()
    Base.metadata.drop_all(bind=test_engine)


def test_user_creation(db):
    admin = db.query(User).filter(User.username == "admin").first()
    assert admin is not None
    assert admin.email == "admin@campaignx.ai"
    assert admin.role == "admin"
    assert admin.is_active is True


def test_campaign_incident_relationship(db):
    campaign = Campaign(
        campaign_id="CAM-TEST-001",
        name="Test Phishing Campaign",
        status="ACTIVE",
        risk_score=85.0,
        campaign_confidence=0.92,
        shared_infrastructure=["test-domain.com", "+919876543210"]
    )
    db.add(campaign)
    db.commit()

    incident = Incident(
        incident_id="INC-TEST-001",
        channel="sms",
        language="english",
        raw_content="Your bank account is suspended. Visit test-domain.com immediately.",
        campaign_id=campaign.id
    )
    db.add(incident)
    db.commit()

    assert incident.campaign.campaign_id == "CAM-TEST-001"
    assert len(campaign.incidents) == 1
    assert campaign.incidents[0].incident_id == "INC-TEST-001"


def test_scam_dna_relationship(db):
    incident = Incident(
        incident_id="INC-TEST-002",
        channel="whatsapp",
        language="hinglish",
        raw_content="Aapka KYC expire ho gaya hai. Abhi verify karein."
    )
    db.add(incident)
    db.commit()

    scam_dna = ScamDNA(
        incident_id=incident.id,
        language="hinglish",
        channel="whatsapp",
        impersonation_target="bank",
        impersonation_target_detail="State Bank KYC",
        urgency=0.9,
        fear=0.7,
        authority_pressure=0.8,
        credential_request=True,
        payment_request=False,
        social_engineering_tactics=["urgency_pressure", "authority_impersonation"],
        phone_numbers=["+919876543210"],
        extraction_confidence=0.95
    )
    db.add(scam_dna)
    db.commit()

    fetched = db.query(Incident).filter(Incident.incident_id == "INC-TEST-002").first()
    assert fetched.scam_dna is not None
    assert fetched.scam_dna.impersonation_target == "bank"
    assert fetched.scam_dna.urgency == 0.9
    assert "urgency_pressure" in fetched.scam_dna.social_engineering_tactics


def test_entity_mention_and_relationship(db):
    entity1 = Entity(
        type="PHONE",
        canonical_value="+919876543210",
        raw_value="+91 98765 43210",
        masked_value="PHONE_A1B2C3D4",
        risk_score=75.0
    )
    entity2 = Entity(
        type="UPI",
        canonical_value="scammer@okaxis",
        raw_value="Scammer@OkAxis",
        masked_value="UPI_E5F6G7H8",
        risk_score=80.0
    )
    db.add_all([entity1, entity2])
    db.commit()

    rel = Relationship(
        source_id=entity1.id,
        target_id=entity2.id,
        type="ASSOCIATED_WITH",
        confidence=0.95,
        probability=0.98,
        is_verified=True,
        verification_reason="Co-occurred in multiple verified scam messages"
    )
    db.add(rel)
    db.commit()

    assert rel.source_entity.canonical_value == "+919876543210"
    assert rel.target_entity.canonical_value == "scammer@okaxis"
    assert rel.is_verified is True


def test_evidence_model(db):
    evidence = Evidence(
        claim="Shared UPI ID 'scammer@okaxis' links Incident 1 and Incident 2",
        type="OBSERVED",
        source="Entity Resolver",
        confidence=1.0,
        supporting_incident_ids=["INC-TEST-001", "INC-TEST-002"],
        supporting_entity_ids=[],
        supporting_relationship_ids=[]
    )
    db.add(evidence)
    db.commit()

    assert evidence.type == "OBSERVED"
    assert len(evidence.supporting_incident_ids) == 2


def test_attack_techniques_seeded(db):
    techniques = db.query(AttackTechnique).all()
    assert len(techniques) >= 8
    t1566 = db.query(AttackTechnique).filter(AttackTechnique.technique_id == "T1566.002").first()
    assert t1566 is not None
    assert "Phishing" in t1566.name
