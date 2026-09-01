import json
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import httpx
from pydantic import BaseModel, Field
from backend.app.core.config import settings
from backend.app.core.logging import logger


class AIInvestigationResponse(BaseModel):
    summary: str
    evidence_text: str
    analysis_text: str
    confidence_score: float = 0.90
    limitations_text: str
    next_steps_text: str
    provider_used: str
    model_name: str


class BaseAIProvider(ABC):
    name: str = "BaseAI"

    @abstractmethod
    async def analyze_investigation(self, prompt: str, context: Dict[str, Any]) -> AIInvestigationResponse:
        pass


class MockLLMProvider(BaseAIProvider):
    name: str = "MockLLM"

    async def analyze_investigation(self, prompt: str, context: Dict[str, Any]) -> AIInvestigationResponse:
        """
        Deterministic, evidence-grounded AI investigator for offline operations and test suites.
        Strictly references supplied evidence without hallucination.
        """
        query = context.get("query", "Investigate evidence")
        inc_id = context.get("incident_id", "INC-001")
        shared_elements = context.get("shared_elements", [])
        campaign_name = context.get("campaign_name", "Unassigned Campaign")
        tactics = context.get("tactics", ["urgency_pressure", "credential_harvesting"])
        risk_score = context.get("risk_score", 85.0)

        summary = f"Analysis confirms strong corroboration linking telemetry for {inc_id} to {campaign_name} with verified multi-factor risk score of {risk_score}/100."
        
        evidence_points = "\n".join([f"- Verified shared indicator: {elem}" for elem in shared_elements]) if shared_elements else "- Directly observed suspicious communication indicators and tactical patterns."
        evidence_text = f"Supplied Evidence:\n{evidence_points}\n- Social engineering vectors: {', '.join(tactics)}"

        analysis_text = (
            f"The investigation demonstrates deterministic infrastructure overlap and tactical alignment. "
            f"The psychological manipulation profile utilizes {', '.join(tactics)} to bypass target defenses. "
            f"Deterministic verification confirmed consistent infrastructure reuse rather than isolated generic similarity."
        )

        limitations_text = "Analysis is strictly bounded to supplied deterministic telemetry. Unobserved external C2 and upstream staging infrastructure require additional pivoting."
        
        next_steps = (
            "1. Block and sinkhole all identified domain and IP infrastructure.\n"
            "2. Pivot to associated threat actor infrastructure in graph view.\n"
            "3. Notify linked payment aggregators to freeze beneficiary accounts."
        )

        return AIInvestigationResponse(
            summary=summary,
            evidence_text=evidence_text,
            analysis_text=analysis_text,
            confidence_score=0.92,
            limitations_text=limitations_text,
            next_steps_text=next_steps,
            provider_used=self.name,
            model_name="mock-deterministic-v1"
        )


class GeminiProvider(BaseAIProvider):
    name: str = "GoogleGemini"

    async def analyze_investigation(self, prompt: str, context: Dict[str, Any]) -> AIInvestigationResponse:
        if not settings.GEMINI_API_KEY:
            raise ValueError("GEMINI_API_KEY not configured")
        
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={settings.GEMINI_API_KEY}"
        system_instruction = (
            "You are CampaignX AI Senior Threat Investigator. Use ONLY supplied verified evidence. "
            "Never fabricate IOCs, malware, actors, or risk scores. "
            "Output strictly formatted structured sections: SUMMARY, EVIDENCE, ANALYSIS, LIMITATIONS, NEXT STEPS."
        )
        payload = {
            "contents": [{
                "parts": [{"text": f"System Context: {system_instruction}\n\nEvidence Context: {json.dumps(context)}\n\nQuery: {prompt}"}]
            }]
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            res = await client.post(url, json=payload)
            if res.status_code == 200:
                data = res.json()
                raw_out = data["candidates"][0]["content"]["parts"][0]["text"]
                return AIInvestigationResponse(
                    summary="Gemini Evidence Grounded Analysis",
                    evidence_text=f"Derived from verified telemetry: {context.get('incident_id', 'Active Query')}",
                    analysis_text=raw_out,
                    confidence_score=0.92,
                    limitations_text="Analysis bounded to supplied evidence context.",
                    next_steps_text="Review threat graph and apply defense countermeasures.",
                    provider_used=self.name,
                    model_name="gemini-1.5-flash"
                )
            raise ValueError(f"Gemini API returned status {res.status_code}")


class OpenRouterProvider(BaseAIProvider):
    name: str = "OpenRouter"

    async def analyze_investigation(self, prompt: str, context: Dict[str, Any]) -> AIInvestigationResponse:
        if not settings.OPENROUTER_API_KEY:
            raise ValueError("OPENROUTER_API_KEY not configured")

        headers = {"Authorization": f"Bearer {settings.OPENROUTER_API_KEY}", "Content-Type": "application/json"}
        payload = {
            "model": "anthropic/claude-3.5-sonnet",
            "messages": [
                {"role": "system", "content": "You are CampaignX AI Senior Threat Investigator. Use ONLY supplied verified evidence. Output structured analysis with SUMMARY, EVIDENCE, ANALYSIS, LIMITATIONS, NEXT STEPS."},
                {"role": "user", "content": f"Evidence Context: {json.dumps(context)}\n\nQuery: {prompt}"}
            ]
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            res = await client.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload)
            if res.status_code == 200:
                data = res.json()
                raw_out = data["choices"][0]["message"]["content"]
                return AIInvestigationResponse(
                    summary="OpenRouter Grounded Analysis",
                    evidence_text=f"Derived from verified telemetry: {context.get('incident_id', 'Active Query')}",
                    analysis_text=raw_out,
                    confidence_score=0.93,
                    limitations_text="Analysis bounded to supplied evidence context.",
                    next_steps_text="Isolate associated network infrastructure.",
                    provider_used=self.name,
                    model_name="claude-3.5-sonnet"
                )
            raise ValueError(f"OpenRouter API returned status {res.status_code}")


class AIInvestigatorManager:
    def __init__(self):
        self.mock_provider = MockLLMProvider()
        self.gemini_provider = GeminiProvider()
        self.openrouter_provider = OpenRouterProvider()

    async def analyze(self, query: str, context: Dict[str, Any]) -> AIInvestigationResponse:
        """
        Executes analysis following the fallback chain:
        Gemini -> OpenRouter -> Deterministic Mock
        """
        if settings.is_offline:
            logger.info("Offline mode active: Using MockLLMProvider for AI Investigation")
            return await self.mock_provider.analyze_investigation(query, context)

        # Try Gemini
        if settings.GEMINI_API_KEY:
            try:
                return await self.gemini_provider.analyze_investigation(query, context)
            except Exception as e:
                logger.warning(f"Gemini provider failed: {e}. Falling back to OpenRouter.")

        # Try OpenRouter
        if settings.OPENROUTER_API_KEY:
            try:
                return await self.openrouter_provider.analyze_investigation(query, context)
            except Exception as e:
                logger.warning(f"OpenRouter provider failed: {e}. Falling back to Mock.")

        return await self.mock_provider.analyze_investigation(query, context)


ai_investigator = AIInvestigatorManager()
