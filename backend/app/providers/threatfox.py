import httpx
from backend.app.providers.base import ThreatIntelProvider, ProviderResult, ProviderStatus
from backend.app.core.logging import logger


class ThreatFoxProvider(ThreatIntelProvider):
    """
    Real-Time Indicator of Compromise (IOC) Intelligence from abuse.ch ThreatFox API.
    Covers malicious IPs, C2 domains, malware hashes, and threat actors in real-time.
    100% Free Public Threat Intelligence - No API key required.
    """
    name: str = "ThreatFox (abuse.ch)"

    def get_status(self) -> ProviderStatus:
        return ProviderStatus.ONLINE

    async def _query_threatfox(self, search_term: str, indicator_type: str) -> ProviderResult:
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                res = await client.post(
                    "https://threatfox-api.abuse.ch/v1/",
                    json={"query": "search_ioc", "search_term": search_term}
                )
                if res.status_code == 200:
                    data = res.json()
                    query_status = data.get("query_status")
                    if query_status == "ok":
                        items = data.get("data", [])
                        if items:
                            first = items[0]
                            malware_printable = first.get("malware_printable")
                            threat_type = first.get("threat_type_desc")
                            confidence = float(first.get("confidence_level", 85))
                            tags = first.get("tags") or []
                            
                            actors = []
                            if first.get("threat_actor"):
                                actors.append(first.get("threat_actor"))

                            return ProviderResult(
                                provider_name=self.name,
                                status=ProviderStatus.ONLINE,
                                indicator=search_term,
                                indicator_type=indicator_type,
                                verdict="MALICIOUS",
                                score=confidence,
                                detections=len(items),
                                total_engines=len(items),
                                malware_family=malware_printable,
                                associated_actors=actors,
                                mitre_techniques=["T1071.001", "T1566.002"],
                                raw_data={
                                    "threat_type": threat_type,
                                    "first_seen": first.get("first_seen_utc"),
                                    "reporter": first.get("reporter"),
                                    "tags": tags,
                                    "ioc_count": len(items)
                                }
                            )
                    elif query_status == "no_result":
                        return ProviderResult(
                            provider_name=self.name,
                            status=ProviderStatus.ONLINE,
                            indicator=search_term,
                            indicator_type=indicator_type,
                            verdict="CLEAN",
                            score=0.0,
                            detections=0,
                            total_engines=1,
                            raw_data={"status": "No active IOC in ThreatFox feed"}
                        )
        except Exception as e:
            logger.warning(f"ThreatFox query failed: {e}")
            return ProviderResult(
                provider_name=self.name,
                status=ProviderStatus.DEGRADED,
                indicator=search_term,
                indicator_type=indicator_type,
                verdict="UNKNOWN",
                message=str(e)
            )

        return ProviderResult(
            provider_name=self.name,
            status=ProviderStatus.ONLINE,
            indicator=search_term,
            indicator_type=indicator_type,
            verdict="UNKNOWN"
        )

    async def lookup_ip(self, ip: str) -> ProviderResult:
        return await self._query_threatfox(ip, "IP")

    async def lookup_domain(self, domain: str) -> ProviderResult:
        return await self._query_threatfox(domain, "DOMAIN")

    async def lookup_url(self, url: str) -> ProviderResult:
        return await self._query_threatfox(url, "URL")

    async def lookup_hash(self, hash_val: str) -> ProviderResult:
        return await self._query_threatfox(hash_val, "HASH")

    async def lookup_cve(self, cve: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=cve, indicator_type="CVE", verdict="UNKNOWN")

    async def lookup_phone(self, phone: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=phone, indicator_type="PHONE", verdict="UNKNOWN")

    async def lookup_email(self, email: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=email, indicator_type="EMAIL", verdict="UNKNOWN")
