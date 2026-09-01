from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field


class ProviderStatus(str, Enum):
    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    NOT_CONFIGURED = "NOT CONFIGURED"


class ProviderResult(BaseModel):
    provider_name: str
    status: ProviderStatus
    indicator: str
    indicator_type: str
    verdict: str = "UNKNOWN"  # MALICIOUS, SUSPICIOUS, CLEAN, UNKNOWN
    score: float = 0.0  # 0.0 - 100.0
    detections: int = 0
    total_engines: int = 0
    reputation: Optional[int] = None
    malware_family: Optional[str] = None
    associated_actors: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    message: Optional[str] = None


class ThreatIntelProvider(ABC):
    name: str = "BaseProvider"

    @abstractmethod
    def get_status(self) -> ProviderStatus:
        pass

    @abstractmethod
    async def lookup_ip(self, ip: str) -> ProviderResult:
        pass

    @abstractmethod
    async def lookup_domain(self, domain: str) -> ProviderResult:
        pass

    @abstractmethod
    async def lookup_url(self, url: str) -> ProviderResult:
        pass

    @abstractmethod
    async def lookup_hash(self, hash_val: str) -> ProviderResult:
        pass

    @abstractmethod
    async def lookup_cve(self, cve: str) -> ProviderResult:
        pass

    @abstractmethod
    async def lookup_phone(self, phone: str) -> ProviderResult:
        pass

    @abstractmethod
    async def lookup_email(self, email: str) -> ProviderResult:
        pass
