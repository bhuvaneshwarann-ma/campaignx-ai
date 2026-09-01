import json
import httpx
from typing import Optional, Dict, Any
from backend.app.providers.base import ThreatIntelProvider, ProviderResult, ProviderStatus
from backend.app.core.config import settings
from backend.app.core.logging import logger


SYSTEM_PROMPT = """You are an authoritative cybersecurity threat intelligence analyst. 
Analyze the provided Indicator of Compromise (IOC) or suspicious entity.
Provide a strictly structured JSON response with keys:
- "verdict": "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "UNKNOWN"
- "score": number between 0.0 and 100.0 (where >=80 is critical/malicious)
- "detections": integer estimated detection engines (0 to 90)
- "total_engines": 90
- "malware_family": string name or null
- "associated_actors": list of threat actor strings or []
- "mitre_techniques": list of MITRE ATT&CK technique IDs (e.g. ["T1566.002", "T1071.001"]) or []
- "summary": string explanation of threat findings
Do not output markdown code fences, only raw valid JSON.
"""


class GeminiThreatIntelProvider(ThreatIntelProvider):
    name: str = "Google Gemini Intelligence"

    def get_status(self) -> ProviderStatus:
        if not settings.GEMINI_API_KEY:
            return ProviderStatus.NOT_CONFIGURED
        return ProviderStatus.ONLINE

    async def _analyze_with_gemini(self, indicator: str, indicator_type: str) -> ProviderResult:
        if not settings.GEMINI_API_KEY:
            return ProviderResult(
                provider_name=self.name,
                status=ProviderStatus.NOT_CONFIGURED,
                indicator=indicator,
                indicator_type=indicator_type,
                verdict="UNKNOWN",
                message="GEMINI_API_KEY not configured"
            )

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={settings.GEMINI_API_KEY}"
        payload = {
            "contents": [{
                "parts": [{"text": f"{SYSTEM_PROMPT}\n\nAnalyze Indicator Type: {indicator_type}\nValue: {indicator}"}]
            }]
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(url, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
                    if text.startswith("```"):
                        text = text.split("```")[1].replace("json", "").strip()
                    parsed = json.loads(text)
                    return ProviderResult(
                        provider_name=self.name,
                        status=ProviderStatus.ONLINE,
                        indicator=indicator,
                        indicator_type=indicator_type,
                        verdict=parsed.get("verdict", "SUSPICIOUS"),
                        score=float(parsed.get("score", 75.0)),
                        detections=int(parsed.get("detections", 10)),
                        total_engines=90,
                        malware_family=parsed.get("malware_family"),
                        associated_actors=parsed.get("associated_actors", []),
                        mitre_techniques=parsed.get("mitre_techniques", []),
                        raw_data={"ai_analysis": parsed.get("summary", "")}
                    )
                return ProviderResult(
                    provider_name=self.name,
                    status=ProviderStatus.DEGRADED,
                    indicator=indicator,
                    indicator_type=indicator_type,
                    message=f"Gemini returned HTTP {res.status_code}"
                )
        except Exception as e:
            logger.warning(f"Gemini IOC lookup failed: {e}")
            return ProviderResult(
                provider_name=self.name,
                status=ProviderStatus.OFFLINE,
                indicator=indicator,
                indicator_type=indicator_type,
                message=str(e)
            )

    async def lookup_ip(self, ip: str) -> ProviderResult:
        return await self._analyze_with_gemini(ip, "IP")

    async def lookup_domain(self, domain: str) -> ProviderResult:
        return await self._analyze_with_gemini(domain, "DOMAIN")

    async def lookup_url(self, url: str) -> ProviderResult:
        return await self._analyze_with_gemini(url, "URL")

    async def lookup_hash(self, hash_val: str) -> ProviderResult:
        return await self._analyze_with_gemini(hash_val, "HASH")

    async def lookup_cve(self, cve: str) -> ProviderResult:
        return await self._analyze_with_gemini(cve, "CVE")

    async def lookup_phone(self, phone: str) -> ProviderResult:
        return await self._analyze_with_gemini(phone, "PHONE")

    async def lookup_email(self, email: str) -> ProviderResult:
        return await self._analyze_with_gemini(email, "EMAIL")


class OpenRouterThreatIntelProvider(ThreatIntelProvider):
    name: str = "OpenRouter Intelligence"

    def get_status(self) -> ProviderStatus:
        if not settings.OPENROUTER_API_KEY:
            return ProviderStatus.NOT_CONFIGURED
        return ProviderStatus.ONLINE

    async def _analyze_with_openrouter(self, indicator: str, indicator_type: str) -> ProviderResult:
        if not settings.OPENROUTER_API_KEY:
            return ProviderResult(
                provider_name=self.name,
                status=ProviderStatus.NOT_CONFIGURED,
                indicator=indicator,
                indicator_type=indicator_type,
                verdict="UNKNOWN",
                message="OPENROUTER_API_KEY not configured"
            )

        headers = {"Authorization": f"Bearer {settings.OPENROUTER_API_KEY}", "Content-Type": "application/json"}
        payload = {
            "model": "anthropic/claude-3.5-sonnet",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyze Indicator Type: {indicator_type}\nValue: {indicator}"}
            ]
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    text = data["choices"][0]["message"]["content"].strip()
                    if text.startswith("```"):
                        text = text.split("```")[1].replace("json", "").strip()
                    parsed = json.loads(text)
                    return ProviderResult(
                        provider_name=self.name,
                        status=ProviderStatus.ONLINE,
                        indicator=indicator,
                        indicator_type=indicator_type,
                        verdict=parsed.get("verdict", "SUSPICIOUS"),
                        score=float(parsed.get("score", 75.0)),
                        detections=int(parsed.get("detections", 15)),
                        total_engines=90,
                        malware_family=parsed.get("malware_family"),
                        associated_actors=parsed.get("associated_actors", []),
                        mitre_techniques=parsed.get("mitre_techniques", []),
                        raw_data={"ai_analysis": parsed.get("summary", "")}
                    )
                return ProviderResult(
                    provider_name=self.name,
                    status=ProviderStatus.DEGRADED,
                    indicator=indicator,
                    indicator_type=indicator_type,
                    message=f"OpenRouter HTTP {res.status_code}"
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
        return await self._analyze_with_openrouter(ip, "IP")

    async def lookup_domain(self, domain: str) -> ProviderResult:
        return await self._analyze_with_openrouter(domain, "DOMAIN")

    async def lookup_url(self, url: str) -> ProviderResult:
        return await self._analyze_with_openrouter(url, "URL")

    async def lookup_hash(self, hash_val: str) -> ProviderResult:
        return await self._analyze_with_openrouter(hash_val, "HASH")

    async def lookup_cve(self, cve: str) -> ProviderResult:
        return await self._analyze_with_openrouter(cve, "CVE")

    async def lookup_phone(self, phone: str) -> ProviderResult:
        return await self._analyze_with_openrouter(phone, "PHONE")

    async def lookup_email(self, email: str) -> ProviderResult:
        return await self._analyze_with_openrouter(email, "EMAIL")
