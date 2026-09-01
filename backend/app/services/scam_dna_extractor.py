import re
from typing import Optional
from backend.app.schemas.scam_dna import ScamDNASchema, AllowedImpersonationTarget, AllowedTactics, AllowedPaymentMethod
from backend.app.services.language_detector import detect_language
from backend.app.services.entity_resolver import extract_and_resolve_entities

# Keywords for taxonomy mapping
IMPERSONATION_RULES = [
    ("bank", ["bank", "sbi", "hdfc", "icici", "axis", "pnb", "kotak", "netbanking", "debit card", "credit card", "khata", "saving account"]),
    ("telecom", ["telecom", "jio", "airtel", "vi", "sim", "esim", "electricity", "power", "bijli", "bill", "disconnect", "meter"]),
    ("delivery_courier", ["indiapost", "bluedart", "delhivery", "dtdc", "fedex", "courier", "parcel", "customs", "delivery", "address"]),
    ("employer", ["part-time", "part time", "job", "recruiter", "work from home", "daily earning", "rating", "telegram group", "shortlisted"]),
    ("law_enforcement", ["cbi", "police", "cyber crime", "narcotics", "court", "arrest", "digital arrest", "customs clearance", "affidavit"]),
    ("government_tax", ["income tax", "it department", "tax refund", "aadhaar", "pan card", "epfo", "pf transfer"]),
    ("tech_support", ["microsoft", "anydesk", "teamviewer", "quicksupport", "virus detected", "tech support", "security warning"])
]

URGENCY_KEYWORDS = [
    "urgent", "immediately", "today", "tonight", "hours", "expire", "suspended", "block",
    "turant", "aaj", "jaldi", "udane", "kavanam", "avasiyam", "warning", "alert"
]

FEAR_KEYWORDS = [
    "blocked", "suspended", "disconnected", "arrest", "police", "legal action", "penalty",
    "cut", "deduct", "unauthorized", "stolen", "breach", "court"
]

AUTHORITY_KEYWORDS = [
    "official", "officer", "manager", "cbi", "cyber cell", "rbi", "government",
    "headquarters", "inspector", "nodal officer"
]


def extract_scam_dna(raw_text: str, channel: str = "sms") -> ScamDNASchema:
    """
    Deterministically analyzes raw scam communications and extracts structured ScamDNA
    strictly adhering to the allowed taxonomy.
    """
    text_lower = raw_text.lower()
    
    # 1. Detect language
    lang, lang_conf = detect_language(raw_text)
    
    # 2. Extract entities
    entities = extract_and_resolve_entities(raw_text)
    phones = [e.canonical_value for e in entities if e.type == "PHONE"]
    upis = [e.canonical_value for e in entities if e.type == "UPI"]
    urls = [e.canonical_value for e in entities if e.type == "URL"]
    domains = [e.canonical_value for e in entities if e.type == "DOMAIN"]
    emails = [e.canonical_value for e in entities if e.type == "EMAIL"]
    
    # 3. Determine Impersonation Target & Detail
    impersonation_target: AllowedImpersonationTarget = "other"
    impersonation_detail = None
    
    for target_cat, keywords in IMPERSONATION_RULES:
        for kw in keywords:
            if kw in text_lower:
                impersonation_target = target_cat  # type: ignore
                impersonation_detail = kw.title()
                break
        if impersonation_target != "other":
            break
            
    # Check if totally benign / no match
    if impersonation_target == "other" and not (phones or upis or urls):
        impersonation_target = "none"

    # 4. Psychological & Structural Scores
    urgency_matches = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
    urgency_score = min(1.0, round(0.3 + (urgency_matches * 0.25), 2)) if urgency_matches > 0 else 0.1

    fear_matches = sum(1 for kw in FEAR_KEYWORDS if kw in text_lower)
    fear_score = min(1.0, round(0.2 + (fear_matches * 0.25), 2)) if fear_matches > 0 else 0.0

    authority_matches = sum(1 for kw in AUTHORITY_KEYWORDS if kw in text_lower)
    authority_score = min(1.0, round(0.3 + (authority_matches * 0.3), 2)) if authority_matches > 0 else 0.1

    # 5. Tactics mapping
    tactics: list[AllowedTactics] = []
    if urgency_score >= 0.5:
        tactics.append("urgency_pressure")
    if authority_score >= 0.5:
        tactics.append("authority_impersonation")
    if fear_score >= 0.4:
        tactics.append("fear_induction")
    if "earning" in text_lower or "shortlisted" in text_lower or "reward" in text_lower:
        tactics.append("artificial_scarcity")
    if "telegram" in text_lower or "whatsapp" in text_lower:
        tactics.append("isolation_tactic")
    if urls or "login" in text_lower or "kyc" in text_lower or "pan" in text_lower:
        tactics.append("credential_harvesting")
    if upis or "fee" in text_lower or "pay" in text_lower:
        tactics.append("payment_redirection")

    # Payment method
    payment_method: AllowedPaymentMethod = "none"
    if upis:
        payment_method = "upi"
    elif "bank" in text_lower or "transfer" in text_lower or "account" in text_lower:
        payment_method = "bank_transfer"
    elif "gift card" in text_lower:
        payment_method = "gift_card"
    elif "crypto" in text_lower or "usdt" in text_lower:
        payment_method = "crypto"

    credential_req = bool(urls or "otp" in text_lower or "password" in text_lower or "kyc" in text_lower or "pan" in text_lower)
    payment_req = bool(upis or "pay" in text_lower or "fee" in text_lower or "₹" in raw_text or "rs." in text_lower)

    # Key script features
    script_features = []
    if urgency_score > 0.5:
        script_features.append("Urgent time-bound ultimatum")
    if credential_req:
        script_features.append("External redirection for identity or credential capture")
    if payment_req:
        script_features.append("Direct fee or verification payment redirection")
    if impersonation_detail:
        script_features.append(f"Brand impersonation of {impersonation_detail}")

    confidence = round(min(0.98, max(0.65, 0.70 + (0.1 if phones else 0) + (0.1 if urls or upis else 0))), 2)

    return ScamDNASchema(
        language=lang,
        channel=channel,
        impersonation_target=impersonation_target,
        impersonation_target_detail=impersonation_detail,
        urgency=urgency_score,
        fear=fear_score,
        authority_pressure=authority_score,
        credential_request=credential_req,
        payment_request=payment_req,
        payment_method=payment_method,
        requested_action="Click malicious URL" if urls else ("Send UPI payment" if upis else "Call phone number"),
        social_engineering_tactics=tactics,
        target_type="individual",
        script_features=script_features,
        infrastructure_indicators=[e.canonical_value for e in entities],
        phone_numbers=phones,
        upi_ids=upis,
        urls=urls,
        domains=domains,
        emails=emails,
        extraction_confidence=confidence
    )
