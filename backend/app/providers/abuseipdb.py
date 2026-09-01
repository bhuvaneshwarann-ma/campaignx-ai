import httpx
from backend.app.providers.base import ThreatIntelProvider, ProviderResult, ProviderStatus
from backend.app.core.config import settings


class AbuseIPDBProvider(ThreatIntelProvider):
    name: str = "AbuseIPDB"

    def get_status(self) -> ProviderStatus:
        if not settings.ABUSEIPDB_API_KEY:
            return ProviderStatus.NOT_CONFIGURED
        return ProviderStatus.ONLINE

    async def lookup_ip(self, ip: str) -> ProviderResult:
        if not settings.ABUSEIPDB_API_KEY:
            return ProviderResult(
                provider_name=self.name,
                status=ProviderStatus.NOT_CONFIGURED,
                indicator=ip,
                indicator_type="IP",
                verdict="UNKNOWN",
                message="AbuseIPDB API key not configured"
            )
        headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers)
                if res.status_code == 200:
                    data = res.json().get("data", {})
                    score = float(data.get("abuseConfidenceScore", 0.0))
                    verdict = "MALICIOUS" if score > 50 else ("SUSPICIOUS" if score > 15 else "CLEAN")
                    return ProviderResult(
                        provider_name=self.name,
                        status=ProviderStatus.ONLINE,
                        indicator=ip,
                        indicator_type="IP",
                        verdict=verdict,
                        score=score,
                        detections=data.get("totalReports", 0),
                        raw_data=data
                    )
                return ProviderResult(
                    provider_name=self.name,
                    status=ProviderStatus.DEGRADED,
                    indicator=ip,
                    indicator_type="IP",
                    message=f"AbuseIPDB HTTP {res.status_code}"
                )
        except Exception as e:
            return ProviderResult(
                provider_name=self.name,
                status=ProviderStatus.OFFLINE,
                indicator=ip,
                indicator_type="IP",
                message=str(e)
            )

    async def lookup_domain(self, domain: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=domain, indicator_type="DOMAIN", verdict="UNKNOWN")

    async def lookup_url(self, url: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=url, indicator_type="URL", verdict="UNKNOWN")

    async def lookup_hash(self, hash_val: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=hash_val, indicator_type="HASH", verdict="UNKNOWN")

    async def lookup_cve(self, cve: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=cve, indicator_type="CVE", verdict="UNKNOWN")

    async def lookup_phone(self, phone: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=phone, indicator_type="PHONE", verdict="UNKNOWN")

    async def lookup_email(self, email: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=email, indicator_type="EMAIL", verdict="UNKNOWN")
