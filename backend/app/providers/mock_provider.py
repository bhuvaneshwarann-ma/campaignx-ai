from backend.app.providers.base import ThreatIntelProvider, ProviderResult, ProviderStatus

# Known malicious IOC intelligence database for offline operations
KNOWN_OFFLINE_IOCS = {
    "185.220.101.5": {
        "verdict": "MALICIOUS",
        "score": 92.0,
        "detections": 48,
        "total_engines": 88,
        "malware_family": "FakeBank APK Stealer",
        "associated_actors": ["PhantomRaven"],
        "mitre_techniques": ["T1071.001", "T1566.002"],
        "details": {"country": "DE", "asn": "AS200052", "threat": "Phishing C2 Host"}
    },
    "45.142.166.11": {
        "verdict": "MALICIOUS",
        "score": 88.0,
        "detections": 36,
        "total_engines": 85,
        "malware_family": "QuickSupport Remote Trojan",
        "associated_actors": ["VoltScammer"],
        "mitre_techniques": ["T1204.001", "T1059.001"],
        "details": {"country": "RU", "asn": "AS49392", "threat": "Extortion Infrastructure"}
    },
    "sbi-kyc-verify-online.com": {
        "verdict": "MALICIOUS",
        "score": 95.0,
        "detections": 29,
        "total_engines": 90,
        "malware_family": "FakeBank PhishKit",
        "associated_actors": ["PhantomRaven"],
        "mitre_techniques": ["T1566.002", "T1598.003"],
        "details": {"registrar": "NameCheap Inc", "created": "2026-07-15"}
    },
    "bill-payment-portal-online.org": {
        "verdict": "MALICIOUS",
        "score": 85.0,
        "detections": 22,
        "total_engines": 90,
        "malware_family": "PaymentRedirect ScamKit",
        "associated_actors": ["VoltScammer"],
        "mitre_techniques": ["T1566.002"],
        "details": {"registrar": "PublicDomainRegistry", "created": "2026-07-20"}
    },
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "verdict": "MALICIOUS",
        "score": 96.0,
        "detections": 62,
        "total_engines": 70,
        "malware_family": "FakeBank APK Stealer",
        "associated_actors": ["PhantomRaven"],
        "mitre_techniques": ["T1059.001", "T1071.001"],
        "details": {"file_type": "Android APK", "size": 4512000}
    },
    "CVE-2024-21413": {
        "verdict": "MALICIOUS",
        "score": 98.0,
        "detections": 1,
        "total_engines": 1,
        "malware_family": "Microsoft Outlook RCE Exploit",
        "associated_actors": ["APT28", "PhantomRaven"],
        "mitre_techniques": ["T1566.001"],
        "details": {"cvss": 9.8, "epss": 0.82, "cisa_kev": True}
    },
    "+919876543210": {
        "verdict": "MALICIOUS",
        "score": 90.0,
        "detections": 14,
        "total_engines": 15,
        "associated_actors": ["PhantomRaven"],
        "details": {"reports": 45, "carrier": "Airtel India", "spam_type": "Bank KYC Phishing"}
    },
    "sbikyc.verify@okhdfcbank": {
        "verdict": "MALICIOUS",
        "score": 94.0,
        "detections": 18,
        "total_engines": 18,
        "associated_actors": ["PhantomRaven"],
        "details": {"frozen": False, "bank": "HDFC UPI Handle", "reports": 82}
    }
}


class MockThreatIntelProvider(ThreatIntelProvider):
    name: str = "DeterministicMockIntel"

    def get_status(self) -> ProviderStatus:
        return ProviderStatus.ONLINE

    async def _lookup(self, indicator: str, indicator_type: str) -> ProviderResult:
        clean_key = indicator.strip().lower()
        if indicator in KNOWN_OFFLINE_IOCS or clean_key in KNOWN_OFFLINE_IOCS:
            data = KNOWN_OFFLINE_IOCS.get(indicator) or KNOWN_OFFLINE_IOCS.get(clean_key)
            return ProviderResult(
                provider_name=self.name,
                status=ProviderStatus.ONLINE,
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=data.get("verdict", "MALICIOUS"),
                score=data.get("score", 85.0),
                detections=data.get("detections", 15),
                total_engines=data.get("total_engines", 70),
                malware_family=data.get("malware_family"),
                associated_actors=data.get("associated_actors", []),
                mitre_techniques=data.get("mitre_techniques", []),
                raw_data=data.get("details", {})
            )
        else:
            return ProviderResult(
                provider_name=self.name,
                status=ProviderStatus.ONLINE,
                indicator=indicator,
                indicator_type=indicator_type,
                verdict="CLEAN",
                score=0.0,
                detections=0,
                total_engines=70,
                raw_data={"status": "No malicious reports in offline intelligence feed"}
            )

    async def lookup_ip(self, ip: str) -> ProviderResult:
        return await self._lookup(ip, "IP")

    async def lookup_domain(self, domain: str) -> ProviderResult:
        return await self._lookup(domain, "DOMAIN")

    async def lookup_url(self, url: str) -> ProviderResult:
        return await self._lookup(url, "URL")

    async def lookup_hash(self, hash_val: str) -> ProviderResult:
        return await self._lookup(hash_val, "HASH")

    async def lookup_cve(self, cve: str) -> ProviderResult:
        return await self._lookup(cve, "CVE")

    async def lookup_phone(self, phone: str) -> ProviderResult:
        return await self._lookup(phone, "PHONE")

    async def lookup_email(self, email: str) -> ProviderResult:
        return await self._lookup(email, "EMAIL")
