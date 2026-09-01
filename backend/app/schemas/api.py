from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from backend.app.schemas.scam_dna import ScamDNASchema


class IncidentCreate(BaseModel):
    channel: str = Field(default="sms", description="sms, whatsapp, email, voice_transcript, text")
    raw_content: str = Field(..., min_length=5, description="Raw suspicious message or incident content")
    source: str = Field(default="analyst_submission")
    tags: List[str] = Field(default_factory=list)


class UniversalSearchRequest(BaseModel):
    query: str = Field(..., min_length=1, description="IOC (IP, domain, hash, URL, CVE, phone, UPI, email) or text")
    depth: int = Field(default=1, ge=1, le=5)


class ThreatHuntingRequest(BaseModel):
    seed_indicator: str
    seed_type: str = "AUTO"  # AUTO, IP, DOMAIN, HASH, URL, PHONE, UPI, CVE
    depth: int = Field(default=2, ge=1, le=5)
    mode: str = "LITE"  # LITE or DEEP


class AIAnalysisRequest(BaseModel):
    query: str
    incident_id: Optional[str] = None
    campaign_id: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
