import re
import urllib.parse
from typing import List, Dict, Any, Optional
from backend.app.core.logging import hash_token

# Regex extractors
PHONE_REGEX = re.compile(r'(?:\+?91[\-\s]?)?[6-9]\d{9}\b|\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}')
UPI_REGEX = re.compile(r'\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b')
EMAIL_REGEX = re.compile(r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b')
URL_REGEX = re.compile(r'https?://[^\s<>"\',;]+')
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
HASH_SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
HASH_SHA1_REGEX = re.compile(r'\b[a-fA-F0-9]{40}\b')
HASH_MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
CVE_REGEX = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')


def normalize_phone(raw: str) -> str:
    """Normalize phone number to international standard format."""
    digits = re.sub(r'\D', '', raw)
    if len(digits) == 10 and digits[0] in '6789':
        return f"+91{digits}"
    elif len(digits) == 12 and digits.startswith("91"):
        return f"+{digits}"
    elif len(digits) == 11 and digits.startswith("0"):
        return f"+91{digits[1:]}"
    return f"+{digits}" if digits else raw.strip()


def normalize_upi(raw: str) -> str:
    """Normalize UPI handles to lowercase trimmed representation."""
    return raw.strip().lower()


def normalize_email(raw: str) -> str:
    """Normalize email address to lowercase standard."""
    return raw.strip().lower()


def normalize_url(raw: str) -> str:
    """Normalize URL format and casing for scheme and hostname."""
    parsed = urllib.parse.urlparse(raw.strip())
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    query = parsed.query
    normalized = f"{scheme}://{netloc}{path}"
    if query:
        normalized = f"{normalized}?{query}"
    return normalized


def normalize_domain(raw: str) -> str:
    """Strip protocol and trailing paths, return lowercase domain name."""
    clean = raw.strip().lower()
    if clean.startswith("http://") or clean.startswith("https://"):
        parsed = urllib.parse.urlparse(clean)
        clean = parsed.netloc
    clean = clean.split("/")[0].split(":")[0]
    return clean


def normalize_cve(raw: str) -> str:
    """Normalize CVE identifiers to uppercase format."""
    return raw.strip().upper()


def normalize_hash(raw: str) -> str:
    """Normalize file hashes to lowercase."""
    return raw.strip().lower()


class ExtractedEntity:
    def __init__(self, entity_type: str, raw_value: str, canonical_value: str, masked_value: str, confidence: float = 1.0):
        self.type = entity_type
        self.raw_value = raw_value
        self.canonical_value = canonical_value
        self.masked_value = masked_value
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "raw_value": self.raw_value,
            "canonical_value": self.canonical_value,
            "masked_value": self.masked_value,
            "confidence": self.confidence,
        }


def extract_and_resolve_entities(text: str) -> List[ExtractedEntity]:
    """
    Extracts, normalizes, and resolves all canonical entities from text with PII masking.
    Returns list of ExtractedEntity objects.
    """
    entities: List[ExtractedEntity] = []
    seen = set()

    def add_entity(etype: str, raw: str, canonical: str, prefix: str):
        key = (etype, canonical)
        if key not in seen and canonical:
            seen.add(key)
            masked = hash_token(canonical, prefix)
            entities.append(ExtractedEntity(etype, raw, canonical, masked))

    # 1. Extract CVEs
    for match in CVE_REGEX.finditer(text):
        cve = normalize_cve(match.group(0))
        add_entity("CVE", match.group(0), cve, "CVE")

    # 2. Extract Hashes
    for match in HASH_SHA256_REGEX.finditer(text):
        h = normalize_hash(match.group(0))
        add_entity("HASH", match.group(0), h, "HASH")
    for match in HASH_SHA1_REGEX.finditer(text):
        h = normalize_hash(match.group(0))
        add_entity("HASH", match.group(0), h, "HASH")
    for match in HASH_MD5_REGEX.finditer(text):
        h = normalize_hash(match.group(0))
        add_entity("HASH", match.group(0), h, "HASH")

    # 3. Extract URLs
    for match in URL_REGEX.finditer(text):
        url = normalize_url(match.group(0))
        add_entity("URL", match.group(0), url, "URL")
        # Extract domain from URL
        domain = normalize_domain(url)
        if domain and not IPV4_REGEX.match(domain):
            add_entity("DOMAIN", domain, domain, "DOMAIN")

    # 4. Extract Emails
    for match in EMAIL_REGEX.finditer(text):
        raw_e = match.group(0)
        # Avoid treating UPI as email if it matches UPI bank handles
        if any(raw_e.lower().endswith(h) for h in ["@okhdfcbank", "@okaxis", "@oksbi", "@paytm", "@ybl", "@ibl", "@upi"]):
            continue
        email = normalize_email(raw_e)
        add_entity("EMAIL", raw_e, email, "EMAIL")

    # 5. Extract UPI IDs
    for match in UPI_REGEX.finditer(text):
        upi = normalize_upi(match.group(0))
        add_entity("UPI", match.group(0), upi, "UPI")

    # 6. Extract IP Addresses
    for match in IPV4_REGEX.finditer(text):
        ip = match.group(0).strip()
        add_entity("IP", ip, ip, "IP")

    # 7. Extract Phone Numbers
    for match in PHONE_REGEX.finditer(text):
        phone_raw = match.group(0)
        phone = normalize_phone(phone_raw)
        # Verify valid digit count
        digits = re.sub(r'\D', '', phone)
        if 10 <= len(digits) <= 15:
            add_entity("PHONE", phone_raw, phone, "PHONE")

    return entities
