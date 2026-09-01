import httpx
from typing import Optional
from backend.app.providers.base import ThreatIntelProvider, ProviderResult, ProviderStatus
from backend.app.core.logging import logger


class URLhausProvider(ThreatIntelProvider):
    """
    Real-Time Malware URL & Payload Intelligence from abuse.ch URLhaus API.
    100% Free Public Threat Intelligence - No API key required.
    """
    name: str = "URLhaus (abuse.ch)"

    def get_status(self) -> ProviderStatus:
        return ProviderStatus.ONLINE

    async def lookup_url(self, url: str) -> ProviderResult:
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                res = await client.post(
                    "https://urlhaus-api.abuse.ch/v1/url/",
                    data={"url": url}
                )
                if res.status_code == 200:
                    data = res.json()
                    query_status = data.get("query_status")
                    if query_status == "ok":
                        threat = data.get("threat", "malware_download")
                        tags = data.get("tags") or []
                        status = data.get("url_status", "online")
                        return ProviderResult(
                            provider_name=self.name,
                            status=ProviderStatus.ONLINE,
                            indicator=url,
                            indicator_type="URL",
                            verdict="MALICIOUS",
                            score=95.0,
                            detections=1,
                            total_engines=1,
                            malware_family=tags[0] if tags else threat,
                            mitre_techniques=["T1566.002", "T1204.001"],
                            raw_data={
                                "urlhaus_status": status,
                                "threat": threat,
                                "tags": tags,
                                "payloads_count": len(data.get("payloads", [])),
                                "reporter": data.get("reporter")
                            }
                        )
                    elif query_status == "no_results":
                        return ProviderResult(
                            provider_name=self.name,
                            status=ProviderStatus.ONLINE,
                            indicator=url,
                            indicator_type="URL",
                            verdict="CLEAN",
                            score=0.0,
                            detections=0,
                            total_engines=1,
                            raw_data={"urlhaus_status": "No active malicious URL records found"}
                        )
                return ProviderResult(
                    provider_name=self.name,
                    status=ProviderStatus.ONLINE,
                    indicator=url,
                    indicator_type="URL",
                    verdict="UNKNOWN",
                    message=f"HTTP {res.status_code}"
                )
        except Exception as e:
            logger.warning(f"URLhaus lookup failed: {e}")
            return ProviderResult(
                provider_name=self.name,
                status=ProviderStatus.DEGRADED,
                indicator=url,
                indicator_type="URL",
                verdict="UNKNOWN",
                message=str(e)
            )

    async def lookup_domain(self, domain: str) -> ProviderResult:
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                res = await client.post(
                    "https://urlhaus-api.abuse.ch/v1/host/",
                    data={"host": domain}
                )
                if res.status_code == 200:
                    data = res.json()
                    query_status = data.get("query_status")
                    if query_status == "ok":
                        urls = data.get("urls", [])
                        malicious_urls_count = len(urls)
                        return ProviderResult(
                            provider_name=self.name,
                            status=ProviderStatus.ONLINE,
                            indicator=domain,
                            indicator_type="DOMAIN",
                            verdict="MALICIOUS" if malicious_urls_count > 0 else "SUSPICIOUS",
                            score=min(100.0, 60.0 + (malicious_urls_count * 5.0)),
                            detections=malicious_urls_count,
                            total_engines=max(1, malicious_urls_count),
                            raw_data={
                                "host": domain,
                                "first_seen": data.get("firstseen"),
                                "active_urls_count": malicious_urls_count,
                            }
                        )
                    else:
                        return ProviderResult(
                            provider_name=self.name,
                            status=ProviderStatus.ONLINE,
                            indicator=domain,
                            indicator_type="DOMAIN",
                            verdict="CLEAN",
                            score=0.0,
                            detections=0,
                            total_engines=1,
                            raw_data={"status": "No host records in URLhaus"}
                        )
        except Exception as e:
            logger.warning(f"URLhaus host lookup failed: {e}")
        return ProviderResult(provider_name=self.name, status=ProviderStatus.ONLINE, indicator=domain, indicator_type="DOMAIN", verdict="UNKNOWN")

    async def lookup_ip(self, ip: str) -> ProviderResult:
        return await self.lookup_domain(ip)

    async def lookup_hash(self, hash_val: str) -> ProviderResult:
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                res = await client.post(
                    "https://urlhaus-api.abuse.ch/v1/payload/",
                    data={"sha256_hash" if len(hash_val) == 64 else "md5_hash": hash_val}
                )
                if res.status_code == 200:
                    data = res.json()
                    if data.get("query_status") == "ok":
                        file_type = data.get("file_type", "Executable")
                        signature = data.get("signature")
                        return ProviderResult(
                            provider_name=self.name,
                            status=ProviderStatus.ONLINE,
                            indicator=hash_val,
                            indicator_type="HASH",
                            verdict="MALICIOUS",
                            score=98.0,
                            detections=1,
                            total_engines=1,
                            malware_family=signature or file_type,
                            raw_data=data
                        )
                    return ProviderResult(
                        provider_name=self.name,
                        status=ProviderStatus.ONLINE,
                        indicator=hash_val,
                        indicator_type="HASH",
                        verdict="CLEAN",
                        score=0.0
                    )
        except Exception as e:
            logger.warning(f"URLhaus payload lookup failed: {e}")
        return ProviderResult(provider_name=self.name, status=ProviderStatus.ONLINE, indicator=hash_val, indicator_type="HASH", verdict="UNKNOWN")

    async def lookup_cve(self, cve: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=cve, indicator_type="CVE", verdict="UNKNOWN")

    async def lookup_phone(self, phone: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=phone, indicator_type="PHONE", verdict="UNKNOWN")

    async def lookup_email(self, email: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=email, indicator_type="EMAIL", verdict="UNKNOWN")
