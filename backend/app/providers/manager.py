import asyncio
from typing import List, Dict, Any
from backend.app.providers.base import ThreatIntelProvider, ProviderResult, ProviderStatus
from backend.app.providers.urlhaus import URLhausProvider
from backend.app.providers.threatfox import ThreatFoxProvider
from backend.app.providers.live_dns_geo import LiveDNSGeoProvider
from backend.app.providers.circl_cve import CIRCLCVEProvider
from backend.app.providers.virustotal import VirusTotalProvider
from backend.app.providers.abuseipdb import AbuseIPDBProvider
from backend.app.providers.ai_intel_provider import (
    GeminiThreatIntelProvider,
    OpenRouterThreatIntelProvider
)
from backend.app.providers.mock_provider import MockThreatIntelProvider
from backend.app.core.config import settings
from backend.app.core.logging import logger


class ProviderManager:
    def __init__(self):
        self.providers: List[ThreatIntelProvider] = [
            URLhausProvider(),
            ThreatFoxProvider(),
            LiveDNSGeoProvider(),
            CIRCLCVEProvider(),
            VirusTotalProvider(),
            AbuseIPDBProvider(),
            GeminiThreatIntelProvider(),
            OpenRouterThreatIntelProvider(),
            MockThreatIntelProvider(),
        ]

    def get_provider_health(self) -> Dict[str, str]:
        """Returns map of provider names to their active status string."""
        health = {}
        for p in self.providers:
            if settings.is_offline and p.name != "DeterministicMockIntel":
                health[p.name] = ProviderStatus.NOT_CONFIGURED.value if p.get_status() == ProviderStatus.NOT_CONFIGURED else "OFFLINE (OFFLINE_MODE)"
            else:
                health[p.name] = p.get_status().value
        return health

    async def _query_single_provider(self, provider: ThreatIntelProvider, indicator: str, indicator_type: str, method_name: str) -> ProviderResult:
        if settings.is_offline and provider.name != "DeterministicMockIntel":
            return ProviderResult(
                provider_name=provider.name,
                status=ProviderStatus.NOT_CONFIGURED if provider.get_status() == ProviderStatus.NOT_CONFIGURED else ProviderStatus.ONLINE,
                indicator=indicator,
                indicator_type=indicator_type,
                verdict="UNKNOWN",
                message="Offline mode active"
            )

        if hasattr(provider, method_name):
            try:
                return await getattr(provider, method_name)(indicator)
            except Exception as e:
                logger.error(f"Error querying provider {provider.name}: {e}")
                return ProviderResult(
                    provider_name=provider.name,
                    status=ProviderStatus.OFFLINE,
                    indicator=indicator,
                    indicator_type=indicator_type,
                    verdict="UNKNOWN",
                    message=str(e)
                )
        return ProviderResult(
            provider_name=provider.name,
            status=provider.get_status(),
            indicator=indicator,
            indicator_type=indicator_type,
            verdict="UNKNOWN"
        )

    async def lookup_indicator(self, indicator: str, indicator_type: str) -> List[ProviderResult]:
        """Query all active threat intelligence providers in parallel."""
        method_name = f"lookup_{indicator_type.lower()}"
        tasks = [
            self._query_single_provider(provider, indicator, indicator_type, method_name)
            for provider in self.providers
        ]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return list(results)


provider_manager = ProviderManager()
