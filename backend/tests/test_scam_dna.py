import pytest
from backend.app.services.language_detector import detect_language
from backend.app.services.entity_resolver import extract_and_resolve_entities, normalize_phone, normalize_upi
from backend.app.services.scam_dna_extractor import extract_scam_dna


def test_language_detector_multilingual():
    en = "URGENT: Your SBI bank account is blocked due to pending KYC."
    hi = "आवश्यक सूचना: आपका बैंक खाता बंद हो जाएगा।"
    hing = "Aapka bank account block ho gaya hai. Turant verify karein."
    ta = "முக்கிய அறிவிப்பு: உங்கள் வங்கி கணக்கு முடக்கப்பட்டுள்ளது."
    tang = "Unga bank account KYC expire aagiruchu. Udane update pannunga."

    assert detect_language(en)[0] == "english"
    assert detect_language(hi)[0] == "hindi"
    assert detect_language(hing)[0] == "hinglish"
    assert detect_language(ta)[0] == "tamil"
    assert detect_language(tang)[0] == "tanglish"


def test_entity_normalization():
    assert normalize_phone("+91 98765 43210") == "+919876543210"
    assert normalize_phone("09876543210") == "+919876543210"
    assert normalize_phone("9876543210") == "+919876543210"
    assert normalize_upi("ScamKYC.Pay@OkHDFCBank") == "scamkyc.pay@okhdfcbank"


def test_scam_dna_extraction_and_taxonomy():
    msg = "URGENT ALERT: Your SBI bank account #XX1234 is suspended. Pay ₹25 verification fee to UPI sbi.kyc@okhdfcbank or call +919876543210."
    dna = extract_scam_dna(msg, channel="sms")

    assert dna.impersonation_target == "bank"
    assert dna.urgency >= 0.5
    assert dna.payment_request is True
    assert dna.payment_method == "upi"
    assert "+919876543210" in dna.phone_numbers
    assert "sbi.kyc@okhdfcbank" in dna.upi_ids
    assert "urgency_pressure" in dna.social_engineering_tactics
    assert "payment_redirection" in dna.social_engineering_tactics
    assert dna.extraction_confidence > 0.8
