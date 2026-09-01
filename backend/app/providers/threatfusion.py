import httpx
from backend.app.providers.base import ThreatIntelProvider, ProviderResult, ProviderStatus
from backend.app.core.config import settings
from backend.app.core.logging import logger


class ThreatFusionProvider(ThreatIntelProvider):
    name: str = "ThreatFusionAI"

    def get_status(self) -> ProviderStatus:
        if not settings.THREATFUSION_API_KEY:
            return ProviderStatus.NOT_CONFIGURED
        return ProviderStatus.ONLINE

    async def _query_api(self, endpoint: str, params: dict, indicator: str, indicator_type: str) -> ProviderResult:
        if not settings.THREATFUSION_API_KEY:
            return ProviderResult(
                provider_name=self.name,
                status=ProviderStatus.NOT_CONFIGURED,
                indicator=indicator,
                indicator_type=indicator_type,
                verdict="UNKNOWN",
                score=0.0,
                message="ThreatFusion API key not configured"
            )

        url = f"{settings.THREATFUSION_BASE_URL}{endpoint}"
        headers = {"Authorization": f"Bearer {settings.THREATFUSION_API_KEY}"}

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(url, params=params, headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    return ProviderResult(
                        provider_name=self.name,
                        status=ProviderStatus.ONLINE,
                        indicator=indicator,
                        indicator_type=indicator_type,
                        verdict=data.get("verdict", "SUSPICIOUS"),
                        score=float(data.get("score", 75.0)),
                        raw_data=data
                    )
                elif res.status_code == 404:
                    return ProviderResult(
                        provider_name=self.name,
                        status=ProviderStatus.ONLINE,
                        indicator=indicator,
                        indicator_type=indicator_type,
                        verdict="CLEAN",
                        score=0.0
                    )
                else:
                    return ProviderResult(
                        provider_name=self.name,
                        status=ProviderStatus.DEGRADED,
                        indicator=indicator,
                        indicator_type=indicator_type,
                        verdict="UNKNOWN",
                        message=f"ThreatFusion returned HTTP {res.status_code}"
                    )
        except Exception as e:
            logger.warning(f"ThreatFusion API query failed: {e}")
            return ProviderResult(
                provider_name=self.name,
                status=ProviderStatus.OFFLINE,
                indicator=indicator,
                indicator_type=indicator_type,
                verdict="UNKNOWN",
                message=f"Provider unavailable: {str(e)}"
            )

    async def lookup_ip(self, ip: str) -> ProviderResult:
        return await self._query_api("/v1/ip/lookup", {"ip": ip}, ip, "IP")

    async def lookup_domain(self, domain: str) -> ProviderResult:
        return await self._query_api("/v1/domain/lookup", {"domain": domain}, domain, "DOMAIN")

    async def lookup_url(self, url: str) -> ProviderResult:
        return await self._query_api("/v1/url/lookup", {"url": url}, url, "URL")

    async def lookup_hash(self, hash_val: str) -> ProviderResult:
        return await self._query_api("/v1/hash/lookup", {"hash": hash_val}, hash_val, "HASH")

    async def lookup_cve(self, cve: str) -> ProviderResult:
        return await self._query_api("/v1/cve/lookup", {"cve": cve}, cve, "CVE")

    async def lookup_phone(self, phone: str) -> ProviderResult:
        return await self._query_api("/v1/phone/lookup", {"phone": phone}, phone, "PHONE")

    async def lookup_email(self, email: str) -> ProviderResult:
        return await self._query_api("/v1/email/lookup", {"email": email}, email, "EMAIL")
