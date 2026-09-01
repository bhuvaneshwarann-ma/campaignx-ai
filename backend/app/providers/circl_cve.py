import httpx
from backend.app.providers.base import ThreatIntelProvider, ProviderResult, ProviderStatus
from backend.app.core.logging import logger


class CIRCLCVEProvider(ThreatIntelProvider):
    """
    Live CVE Vulnerability Intelligence from CIRCL / National Vulnerability Database.
    100% Free Public API - No API key required.
    """
    name: str = "CIRCL CVE / NVD"

    def get_status(self) -> ProviderStatus:
        return ProviderStatus.ONLINE

    async def lookup_cve(self, cve: str) -> ProviderResult:
        cve_id = cve.strip().upper()
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                res = await client.get(f"https://cve.circl.lu/api/cve/{cve_id}")
                if res.status_code == 200 and res.json():
                    data = res.json()
                    cvss = float(data.get("cvss") or 0.0)
                    summary = data.get("summary", "")
                    cwe = data.get("cwe", "")
                    verdict = "MALICIOUS" if cvss >= 7.0 else ("SUSPICIOUS" if cvss > 4.0 else "CLEAN")
                    score = cvss * 10.0

                    return ProviderResult(
                        provider_name=self.name,
                        status=ProviderStatus.ONLINE,
                        indicator=cve_id,
                        indicator_type="CVE",
                        verdict=verdict,
                        score=score,
                        detections=1 if cvss >= 7.0 else 0,
                        total_engines=1,
                        mitre_techniques=["T1190", "T1203"],
                        raw_data={
                            "cvss": cvss,
                            "cwe": cwe,
                            "summary": summary[:200] + "..." if len(summary) > 200 else summary,
                            "published": data.get("Published"),
                            "modified": data.get("Modified"),
                            "vulnerable_configurations": len(data.get("vulnerable_configuration", []))
                        }
                    )
        except Exception as e:
            logger.warning(f"CIRCL CVE lookup failed: {e}")

        return ProviderResult(
            provider_name=self.name,
            status=ProviderStatus.ONLINE,
            indicator=cve_id,
            indicator_type="CVE",
            verdict="UNKNOWN"
        )

    async def lookup_ip(self, ip: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=ip, indicator_type="IP", verdict="UNKNOWN")

    async def lookup_domain(self, domain: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=domain, indicator_type="DOMAIN", verdict="UNKNOWN")

    async def lookup_url(self, url: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=url, indicator_type="URL", verdict="UNKNOWN")

    async def lookup_hash(self, hash_val: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=hash_val, indicator_type="HASH", verdict="UNKNOWN")

    async def lookup_phone(self, phone: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=phone, indicator_type="PHONE", verdict="UNKNOWN")

    async def lookup_email(self, email: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=email, indicator_type="EMAIL", verdict="UNKNOWN")
