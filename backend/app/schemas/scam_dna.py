from typing import List, Optional, Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator

AllowedImpersonationTarget = Literal[
    "bank",
    "government_tax",
    "law_enforcement",
    "telecom",
    "delivery_courier",
    "family_member",
    "employer",
    "tech_support",
    "other",
    "none"
]

AllowedTactics = Literal[
    "urgency_pressure",
    "authority_impersonation",
    "fear_induction",
    "artificial_scarcity",
    "trust_building",
    "isolation_tactic",
    "credential_harvesting",
    "payment_redirection"
]

AllowedPaymentMethod = Literal[
    "upi",
    "bank_transfer",
    "gift_card",
    "crypto",
    "cash_pickup",
    "wallet_app",
    "other",
    "none"
]


class ScamDNASchema(BaseModel):
    language: str = Field(default="english", description="Detected language (english, hindi, hinglish, tamil, tanglish, unknown)")
    channel: str = Field(default="sms", description="Communication channel (sms, whatsapp, email, voice_transcript, text)")
    impersonation_target: AllowedImpersonationTarget = Field(..., description="Taxonomic impersonation target category")
    impersonation_target_detail: Optional[str] = Field(None, description="Specific target brand or entity mentioned, e.g. State Bank of India")
    
    urgency: float = Field(..., ge=0.0, le=1.0, description="Urgency pressure score (0.0 - 1.0)")
    fear: float = Field(..., ge=0.0, le=1.0, description="Fear induction score (0.0 - 1.0)")
    authority_pressure: float = Field(..., ge=0.0, le=1.0, description="Authority coercion score (0.0 - 1.0)")
    
    credential_request: bool = Field(default=False, description="Whether login, OTP, PIN, or Aadhaar credentials were requested")
    payment_request: bool = Field(default=False, description="Whether direct monetary transfer was requested")
    payment_method: AllowedPaymentMethod = Field(default="none", description="Specific payment channel requested")
    requested_action: Optional[str] = Field(None, description="Specific call to action, e.g. click link, send UPI, install APK")
    
    social_engineering_tactics: List[AllowedTactics] = Field(default_factory=list, description="Validated social engineering tactics")
    target_type: str = Field(default="individual", description="Target profile (individual, corporate, merchant)")
    script_features: List[str] = Field(default_factory=list, description="Key structural tropes identified in the text")
    infrastructure_indicators: List[str] = Field(default_factory=list, description="Extracted raw IOC tokens")
    
    phone_numbers: List[str] = Field(default_factory=list)
    upi_ids: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    
    extraction_confidence: float = Field(default=0.9, ge=0.0, le=1.0, description="Extraction certainty namespace")

    model_config = ConfigDict(from_attributes=True)
