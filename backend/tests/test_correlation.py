import pytest
from backend.app.services.scam_dna_extractor import extract_scam_dna
from backend.app.correlation.engine import correlation_engine


def test_positive_correlation_shared_infrastructure():
    msg_a = "URGENT: SBI Account KYC suspended. Visit https://sbi-kyc-verify-online.com or call +919876543210."
    msg_b = "Aapka SBI account block ho gaya hai. Link: https://sbi-kyc-verify-online.com/login call +919876543210."

    dna_a = extract_scam_dna(msg_a)
    dna_b = extract_scam_dna(msg_b)

    result = correlation_engine.correlate_incidents("INC-001", dna_a, msg_a, "INC-002", dna_b, msg_b)

    assert result.is_verified is True
    assert result.relationship_confidence >= 0.90
    assert result.evidence is not None
    assert result.evidence.type == "OBSERVED"
    assert any("Phone:" in elem or "Domain:" in elem for elem in result.shared_elements)


def test_negative_control_false_positive_rejection():
    # Both messages have generic bank / KYC keywords, but zero shared infrastructure
    msg_a = "URGENT: Your SBI bank KYC is pending. Visit https://sbi-kyc-verify-online.com or call +919876543210."
    msg_b = "URGENT: Your HDFC bank account KYC expired. Please visit your local bank branch immediately."

    dna_a = extract_scam_dna(msg_a)
    dna_b = extract_scam_dna(msg_b)

    result = correlation_engine.correlate_incidents("INC-001", dna_a, msg_a, "INC-NEG-001", dna_b, msg_b)

    assert result.is_verified is False
    assert result.relationship_confidence == 0.0
    assert "Generic behavioral similarity was insufficient to establish campaign membership." in result.verification_reason
