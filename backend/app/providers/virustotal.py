import httpx
from backend.app.providers.base import ThreatIntelProvider, ProviderResult, ProviderStatus
from backend.app.core.config import settings
from backend.app.core.logging import logger


class VirusTotalProvider(ThreatIntelProvider):
    name: str = "VirusTotal"

    def get_status(self) -> ProviderStatus:
        if not settings.VIRUSTOTAL_API_KEY:
            return ProviderStatus.NOT_CONFIGURED
        return ProviderStatus.ONLINE

    async def _query_vt(self, endpoint: str, indicator: str, indicator_type: str) -> ProviderResult:
        if not settings.VIRUSTOTAL_API_KEY:
            return ProviderResult(
                provider_name=self.name,
                status=ProviderStatus.NOT_CONFIGURED,
                indicator=indicator,
                indicator_type=indicator_type,
                verdict="UNKNOWN",
                message="VirusTotal API key not configured"
            )
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(f"https://www.virustotal.com/api/v3/{endpoint}", headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) or 1
                    verdict = "MALICIOUS" if malicious > 2 else ("SUSPICIOUS" if (malicious + suspicious) > 0 else "CLEAN")
                    score = min(100.0, (malicious * 15.0) + (suspicious * 5.0))
                    return ProviderResult(
                        provider_name=self.name,
                        status=ProviderStatus.ONLINE,
                        indicator=indicator,
                        indicator_type=indicator_type,
                        verdict=verdict,
                        score=score,
                        detections=malicious,
                        total_engines=total,
                        raw_data=stats
                    )
                return ProviderResult(
                    provider_name=self.name,
                    status=ProviderStatus.DEGRADED,
                    indicator=indicator,
                    indicator_type=indicator_type,
                    message=f"VirusTotal status {res.status_code}"
                )
        except Exception as e:
            return ProviderResult(
                provider_name=self.name,
                status=ProviderStatus.OFFLINE,
                indicator=indicator,
                indicator_type=indicator_type,
                message=str(e)
            )

    async def lookup_ip(self, ip: str) -> ProviderResult:
        return await self._query_vt(f"ip_addresses/{ip}", ip, "IP")

    async def lookup_domain(self, domain: str) -> ProviderResult:
        return await self._query_vt(f"domains/{domain}", domain, "DOMAIN")

    async def lookup_url(self, url: str) -> ProviderResult:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return await self._query_vt(f"urls/{url_id}", url, "URL")

    async def lookup_hash(self, hash_val: str) -> ProviderResult:
        return await self._query_vt(f"files/{hash_val}", hash_val, "HASH")

    async def lookup_cve(self, cve: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=cve, indicator_type="CVE", verdict="UNKNOWN")

    async def lookup_phone(self, phone: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=phone, indicator_type="PHONE", verdict="UNKNOWN")

    async def lookup_email(self, email: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=email, indicator_type="EMAIL", verdict="UNKNOWN")
