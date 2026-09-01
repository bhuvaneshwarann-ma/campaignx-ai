import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, DateTime, ForeignKey, JSON, Enum
)
from sqlalchemy.orm import relationship
from backend.app.database.session import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="analyst", nullable=False)  # admin, analyst, viewer
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    investigations = relationship("Investigation", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    campaign_id = Column(String(50), unique=True, index=True, nullable=False)  # e.g., CAM-001
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(30), default="EMERGING", nullable=False)  # EMERGING, ACTIVE, MONITORED, INACTIVE, DISMISSED
    first_seen = Column(DateTime, default=get_utc_now, nullable=False)
    last_seen = Column(DateTime, default=get_utc_now, nullable=False)
    incident_count = Column(Integer, default=0, nullable=False)
    entity_count = Column(Integer, default=0, nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)  # 0.0 - 100.0
    campaign_confidence = Column(Float, default=0.0, nullable=False)  # 0.0 - 1.0
    shared_infrastructure = Column(JSON, default=list, nullable=False)
    behavioral_overlap = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    incidents = relationship("Incident", back_populates="campaign")
    relationships = relationship("Relationship", back_populates="campaign")
    ai_reports = relationship("AIReport", back_populates="campaign")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    incident_id = Column(String(50), unique=True, index=True, nullable=False)  # e.g., INC-001
    channel = Column(String(50), nullable=False)  # sms, whatsapp, email, voice_transcript, ioc_lookup, text
    language = Column(String(20), default="unknown", nullable=False)  # english, hindi, hinglish, tamil, tanglish, unknown
    raw_content = Column(Text, nullable=False)
    normalized_content = Column(Text, nullable=True)
    source = Column(String(100), default="analyst_submission", nullable=False)
    tags = Column(JSON, default=list, nullable=False)
    status = Column(String(30), default="analyzed", nullable=False)
    campaign_id = Column(String(36), ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    campaign = relationship("Campaign", back_populates="incidents")
    scam_dna = relationship("ScamDNA", back_populates="incident", uselist=False, cascade="all, delete-orphan")
    entity_mentions = relationship("EntityMention", back_populates="incident", cascade="all, delete-orphan")
    relationships = relationship("Relationship", back_populates="incident")
    ai_reports = relationship("AIReport", back_populates="incident")


class ScamDNA(Base):
    __tablename__ = "scam_dna"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), unique=True, nullable=False)
    language = Column(String(20), nullable=False)
    channel = Column(String(50), nullable=False)
    impersonation_target = Column(String(50), nullable=False)  # bank, government_tax, law_enforcement, telecom, delivery_courier, etc.
    impersonation_target_detail = Column(String(255), nullable=True)
    urgency = Column(Float, default=0.0, nullable=False)  # 0.0 - 1.0
    fear = Column(Float, default=0.0, nullable=False)  # 0.0 - 1.0
    authority_pressure = Column(Float, default=0.0, nullable=False)  # 0.0 - 1.0
    credential_request = Column(Boolean, default=False, nullable=False)
    payment_request = Column(Boolean, default=False, nullable=False)
    payment_method = Column(String(50), default="other", nullable=False)  # upi, bank_transfer, gift_card, crypto, etc.
    requested_action = Column(String(255), nullable=True)
    social_engineering_tactics = Column(JSON, default=list, nullable=False)
    target_type = Column(String(50), default="individual", nullable=False)
    script_features = Column(JSON, default=list, nullable=False)
    infrastructure_indicators = Column(JSON, default=list, nullable=False)
    phone_numbers = Column(JSON, default=list, nullable=False)
    upi_ids = Column(JSON, default=list, nullable=False)
    urls = Column(JSON, default=list, nullable=False)
    domains = Column(JSON, default=list, nullable=False)
    emails = Column(JSON, default=list, nullable=False)
    extraction_confidence = Column(Float, default=0.0, nullable=False)  # 0.0 - 1.0
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    incident = relationship("Incident", back_populates="scam_dna")


class Entity(Base):
    __tablename__ = "entities"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    type = Column(String(30), nullable=False, index=True)  # PHONE, UPI, EMAIL, URL, DOMAIN, IP, HASH, CVE, MALWARE, ACTOR
    canonical_value = Column(String(512), nullable=False, index=True)
    raw_value = Column(String(512), nullable=False)
    masked_value = Column(String(512), nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)  # 0.0 - 100.0
    first_seen = Column(DateTime, default=get_utc_now, nullable=False)
    last_seen = Column(DateTime, default=get_utc_now, nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    mentions = relationship("EntityMention", back_populates="entity", cascade="all, delete-orphan")
    source_relationships = relationship("Relationship", foreign_keys="Relationship.source_id", back_populates="source_entity")
    target_relationships = relationship("Relationship", foreign_keys="Relationship.target_id", back_populates="target_entity")
    observations = relationship("Observation", back_populates="entity", cascade="all, delete-orphan")


class EntityMention(Base):
    __tablename__ = "entity_mentions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_id = Column(String(36), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True)
    context = Column(Text, nullable=True)
    confidence = Column(Float, default=1.0, nullable=False)  # 0.0 - 1.0
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    incident = relationship("Incident", back_populates="entity_mentions")
    entity = relationship("Entity", back_populates="mentions")


class Relationship(Base):
    __tablename__ = "relationships"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    source_id = Column(String(36), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id = Column(String(36), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True)
    type = Column(String(50), nullable=False, index=True)  # USES_PHONE, USES_UPI, RESOLVES_TO, ASSOCIATED_WITH, etc.
    confidence = Column(Float, default=0.0, nullable=False)  # deterministic verified confidence
    probability = Column(Float, default=0.0, nullable=False)  # ML candidate probability
    is_verified = Column(Boolean, default=False, nullable=False)
    verification_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    source_entity = relationship("Entity", foreign_keys=[source_id], back_populates="source_relationships")
    target_entity = relationship("Entity", foreign_keys=[target_id], back_populates="target_relationships")
    incident = relationship("Incident", back_populates="relationships")
    campaign = relationship("Campaign", back_populates="relationships")


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    claim = Column(Text, nullable=False)
    type = Column(String(20), nullable=False)  # OBSERVED, INFERRED, PREDICTED
    source = Column(String(100), nullable=False)  # Entity Resolver, Provider, Rule Engine, ML Predictor
    confidence = Column(Float, default=1.0, nullable=False)
    supporting_incident_ids = Column(JSON, default=list, nullable=False)
    supporting_entity_ids = Column(JSON, default=list, nullable=False)
    supporting_relationship_ids = Column(JSON, default=list, nullable=False)
    scoring_factors = Column(JSON, default=dict, nullable=False)
    timestamp = Column(DateTime, default=get_utc_now, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    target_type = Column(String(30), nullable=False)  # INCIDENT, ENTITY, CAMPAIGN, IOC
    target_id = Column(String(50), nullable=False, index=True)
    risk_score = Column(Float, nullable=False)  # 0.0 - 100.0
    severity = Column(String(20), nullable=False)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    risk_factors = Column(JSON, default=list, nullable=False)
    evidence_id = Column(String(36), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    calculated_at = Column(DateTime, default=get_utc_now, nullable=False)


class Observation(Base):
    __tablename__ = "observations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    entity_id = Column(String(36), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True)
    provider_name = Column(String(50), nullable=False)  # VirusTotal, AbuseIPDB, OTX, ThreatFusion, etc.
    raw_response = Column(JSON, default=dict, nullable=False)
    verdict = Column(String(20), default="UNKNOWN", nullable=False)  # MALICIOUS, SUSPICIOUS, CLEAN, UNKNOWN
    score = Column(Float, default=0.0, nullable=False)
    timestamp = Column(DateTime, default=get_utc_now, nullable=False)

    entity = relationship("Entity", back_populates="observations")


class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    name = Column(String(100), unique=True, nullable=False)
    aliases = Column(JSON, default=list, nullable=False)
    attribution_level = Column(String(30), default="UNKNOWN", nullable=False)  # CONFIRMED, STRONGLY_ASSOCIATED, POSSIBLE_MATCH, etc.
    description = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=get_utc_now, nullable=False)
    last_seen = Column(DateTime, default=get_utc_now, nullable=False)
    infrastructure = Column(JSON, default=list, nullable=False)
    associated_malware = Column(JSON, default=list, nullable=False)
    techniques = Column(JSON, default=list, nullable=False)
    evidence_ids = Column(JSON, default=list, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)


class MalwareFamily(Base):
    __tablename__ = "malware_families"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    name = Column(String(100), unique=True, nullable=False)
    aliases = Column(JSON, default=list, nullable=False)
    malware_type = Column(String(50), default="OTHER", nullable=False)  # RANSOMWARE, TROJAN, STEALER, BOTNET, APK_SPYWARE, etc.
    description = Column(Text, nullable=True)
    signatures = Column(JSON, default=list, nullable=False)
    cves = Column(JSON, default=list, nullable=False)
    techniques = Column(JSON, default=list, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    technique_id = Column(String(30), unique=True, index=True, nullable=False)  # e.g., T1566.002
    name = Column(String(255), nullable=False)
    tactic = Column(String(100), nullable=False)  # e.g., Initial Access, Execution, Persistence
    sub_technique_of = Column(String(30), nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    title = Column(String(255), nullable=False)
    query = Column(Text, nullable=False)
    query_type = Column(String(30), nullable=False)  # IOC, SCAM, CAMPAIGN, HUNT
    depth = Column(Integer, default=1, nullable=False)  # 1 - 5
    status = Column(String(30), default="COMPLETED", nullable=False)
    results_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    user = relationship("User", back_populates="investigations")
    ai_reports = relationship("AIReport", back_populates="investigation")


class AIReport(Base):
    __tablename__ = "ai_reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True)
    summary = Column(Text, nullable=False)
    evidence_text = Column(Text, nullable=False)
    analysis_text = Column(Text, nullable=False)
    confidence_score = Column(Float, default=0.0, nullable=False)
    limitations_text = Column(Text, nullable=False)
    next_steps_text = Column(Text, nullable=False)
    provider_used = Column(String(50), default="MockLLM", nullable=False)
    model_name = Column(String(50), default="mock-offline-v1", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    investigation = relationship("Investigation", back_populates="ai_reports")
    campaign = relationship("Campaign", back_populates="ai_reports")
    incident = relationship("Incident", back_populates="ai_reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(100), nullable=False)  # LOGIN, QUERY, CREATE_INCIDENT, EXPORT_REPORT, etc.
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(String(100), nullable=False)
    details_json = Column(JSON, default=dict, nullable=False)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime, default=get_utc_now, nullable=False)

    user = relationship("User", back_populates="audit_logs")
