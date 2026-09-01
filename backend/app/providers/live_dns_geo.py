import httpx
from backend.app.providers.base import ThreatIntelProvider, ProviderResult, ProviderStatus
from backend.app.core.logging import logger


class LiveDNSGeoProvider(ThreatIntelProvider):
    """
    Live DNS Resolution (Cloudflare DoH) and Live IP Geolocation / ASN / Org Intelligence (IP-API).
    100% Real-Time Live Network Resolution - Zero API keys required.
    """
    name: str = "Live DNS & GeoIP"

    def get_status(self) -> ProviderStatus:
        return ProviderStatus.ONLINE

    async def lookup_ip(self, ip: str) -> ProviderResult:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query")
                if res.status_code == 200:
                    data = res.json()
                    if data.get("status") == "success":
                        isp = data.get("isp", "")
                        org = data.get("org", "")
                        as_info = data.get("as", "")
                        country = data.get("country", "")
                        city = data.get("city", "")

                        # Known high-risk bulletproof / proxy hosting ASNs or keywords
                        is_suspicious_hosting = any(k in f"{isp} {org} {as_info}".lower() for k in ["vpn", "tor", "hosting", "cloud", "datacenter", "m247", "ovh", "leaseweb", "digitalocean", "linode"])
                        score = 35.0 if is_suspicious_hosting else 10.0
                        verdict = "SUSPICIOUS" if is_suspicious_hosting else "CLEAN"

                        return ProviderResult(
                            provider_name=self.name,
                            status=ProviderStatus.ONLINE,
                            indicator=ip,
                            indicator_type="IP",
                            verdict=verdict,
                            score=score,
                            raw_data={
                                "country": country,
                                "country_code": data.get("countryCode"),
                                "city": city,
                                "isp": isp,
                                "org": org,
                                "asn": as_info,
                                "coordinates": f"{data.get('lat')}, {data.get('lon')}",
                                "timezone": data.get("timezone"),
                            }
                        )
        except Exception as e:
            logger.warning(f"Live GeoIP lookup failed: {e}")

        return ProviderResult(
            provider_name=self.name,
            status=ProviderStatus.ONLINE,
            indicator=ip,
            indicator_type="IP",
            verdict="UNKNOWN"
        )

    async def lookup_domain(self, domain: str) -> ProviderResult:
        try:
            # Query Cloudflare DNS-over-HTTPS (DoH)
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(
                    "https://cloudflare-dns.com/dns-query",
                    params={"name": domain, "type": "A"},
                    headers={"accept": "application/dns-json"}
                )
                if res.status_code == 200:
                    dns_data = res.json()
                    answers = dns_data.get("Answer", [])
                    resolved_ips = [a.get("data") for a in answers if a.get("type") == 1]
                    
                    if resolved_ips:
                        first_ip = resolved_ips[0]
                        # Fetch geo info for resolved IP
                        geo_res = await client.get(f"http://ip-api.com/json/{first_ip}?fields=status,country,city,isp,org,as")
                        geo_data = geo_res.json() if geo_res.status_code == 200 else {}

                        return ProviderResult(
                            provider_name=self.name,
                            status=ProviderStatus.ONLINE,
                            indicator=domain,
                            indicator_type="DOMAIN",
                            verdict="CLEAN",
                            score=15.0,
                            raw_data={
                                "resolved_ips": resolved_ips,
                                "primary_ip": first_ip,
                                "country": geo_data.get("country"),
                                "city": geo_data.get("city"),
                                "isp": geo_data.get("isp"),
                                "asn": geo_data.get("as"),
                                "status": "Domain is actively resolved online via Live DoH"
                            }
                        )
                    else:
                        return ProviderResult(
                            provider_name=self.name,
                            status=ProviderStatus.ONLINE,
                            indicator=domain,
                            indicator_type="DOMAIN",
                            verdict="SUSPICIOUS",
                            score=40.0,
                            raw_data={"status": "Domain has no active A-records (NXDOMAIN or parked)"}
                        )
        except Exception as e:
            logger.warning(f"Live DNS lookup failed: {e}")

        return ProviderResult(
            provider_name=self.name,
            status=ProviderStatus.ONLINE,
            indicator=domain,
            indicator_type="DOMAIN",
            verdict="UNKNOWN"
        )

    async def lookup_url(self, url: str) -> ProviderResult:
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        domain = parsed.hostname or url
        return await self.lookup_domain(domain)

    async def lookup_hash(self, hash_val: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=hash_val, indicator_type="HASH", verdict="UNKNOWN")

    async def lookup_cve(self, cve: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=cve, indicator_type="CVE", verdict="UNKNOWN")

    async def lookup_phone(self, phone: str) -> ProviderResult:
        return ProviderResult(provider_name=self.name, status=self.get_status(), indicator=phone, indicator_type="PHONE", verdict="UNKNOWN")

    async def lookup_email(self, email: str) -> ProviderResult:
        domain = email.split("@")[-1] if "@" in email else email
        return await self.lookup_domain(domain)
