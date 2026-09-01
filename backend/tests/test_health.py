import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.config import settings

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == settings.PROJECT_NAME
    assert "version" in data
    assert "tagline" in data
    assert data["mode"] == settings.MODE


def test_health_check_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app"] == "CampaignX AI"
    assert "mode" in data
    assert "timestamp" in data
    assert "services" in data
    assert data["services"]["database"] == "available"


def test_docs_accessible():
    response = client.get("/docs")
    assert response.status_code == 200


def test_pii_logging_masker():
    from backend.app.core.logging import PIIMaskingFormatter
    import logging

    formatter = PIIMaskingFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="Contact user at test@example.com and +919876543210 or admin@bank.upi",
        args=(),
        exc_info=None
    )
    formatted = formatter.format(record)
    assert "test@example.com" not in formatted
    assert "+919876543210" not in formatted
    assert "admin@bank.upi" not in formatted
    assert "EMAIL_" in formatted or "PHONE_" in formatted or "UPI_" in formatted
