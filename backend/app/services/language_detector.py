import re
from typing import Tuple

# Devanagari Unicode block (U+0900 to U+097F)
DEVANAGARI_REGEX = re.compile(r'[\u0900-\u097F]')

# Tamil Unicode block (U+0B80 to U+0BFF)
TAMIL_REGEX = re.compile(r'[\u0B80-\u0BFF]')

# Common romanized Hindi (Hinglish) keyword signals
HINGLISH_KEYWORDS = {
    "aapka", "karein", "turant", "gaya", "karo", "nahi", "rahe", "hai", "hain", "ke", "liye",
    "pe", "se", "hum", "yeh", "kripya", "karna", "ho", "aayi", "debit", "paisa", "khata", "bhejo",
    "bijli", "kaat", "aayega", "milega"
}

# Common romanized Tamil (Tanglish) keyword signals
TANGLISH_KEYWORDS = {
    "unga", "panunga", "irunthu", "pannalam", "aagiruchu", "illana", "kudunga", "panna",
    "vanthurukku", "aachu", "romba", "mudiyum", "ippo", "naalaiku", "kitta", "kadaiyathu"
}


def detect_language(text: str) -> Tuple[str, float]:
    """
    Detects language of input text: english, hindi, hinglish, tamil, tanglish.
    Returns (language_code, confidence).
    """
    if not text or not text.strip():
        return "unknown", 0.0

    total_chars = len(text)
    
    # Check for Devanagari script (Hindi)
    devanagari_count = len(DEVANAGARI_REGEX.findall(text))
    if devanagari_count / total_chars > 0.15:
        return "hindi", min(0.99, 0.7 + (devanagari_count / total_chars) * 0.3)

    # Check for Tamil script (Tamil)
    tamil_count = len(TAMIL_REGEX.findall(text))
    if tamil_count / total_chars > 0.15:
        return "tamil", min(0.99, 0.7 + (tamil_count / total_chars) * 0.3)

    # For Roman script, tokenize words and check Hinglish / Tanglish signals
    words = re.findall(r'\b[a-zA-Z]+\b', text.lower())
    if not words:
        return "english", 0.6

    hinglish_matches = sum(1 for w in words if w in HINGLISH_KEYWORDS)
    tanglish_matches = sum(1 for w in words if w in TANGLISH_KEYWORDS)

    if tanglish_matches >= 2 or (tanglish_matches >= 1 and len(words) <= 10):
        confidence = min(0.95, 0.65 + (tanglish_matches / len(words)) * 0.5)
        return "tanglish", confidence

    if hinglish_matches >= 2 or (hinglish_matches >= 1 and len(words) <= 10):
        confidence = min(0.95, 0.65 + (hinglish_matches / len(words)) * 0.5)
        return "hinglish", confidence

    return "english", 0.90
