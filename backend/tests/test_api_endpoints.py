import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_dashboard_stats_endpoint():
    res = client.get("/api/v1/stats/dashboard")
    assert res.status_code == 200
    data = res.json()
    assert "summary" in data
    assert data["summary"]["total_incidents"] > 0
    assert data["summary"]["total_campaigns"] > 0
    assert "provider_health" in data


def test_list_and_get_campaigns():
    res = client.get("/api/v1/campaigns")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] > 0
    camp_id = data["items"][0]["campaign_id"]

    # Get single campaign
    single = client.get(f"/api/v1/campaigns/{camp_id}")
    assert single.status_code == 200
    camp_data = single.json()
    assert camp_data["campaign_id"] == camp_id
    assert "why_campaign" in camp_data

    # Get campaign graph
    graph_res = client.get(f"/api/v1/campaigns/{camp_id}/graph")
    assert graph_res.status_code == 200
    gdata = graph_res.json()
    assert "nodes" in gdata
    assert "edges" in gdata


def test_universal_ioc_search():
    res = client.post("/api/v1/ioc/lookup", json={"query": "185.220.101.5", "depth": 2})
    assert res.status_code == 200
    data = res.json()
    assert data["detected_type"] == "IP"
    assert data["risk_assessment"]["risk_score"] > 80.0
    assert len(data["providers"]) > 0
    assert "graph" in data


def test_threat_hunting_endpoint():
    res = client.post("/api/v1/hunting", json={"seed_indicator": "+919876543210", "mode": "DEEP", "depth": 3})
    assert res.status_code == 200
    data = res.json()
    assert data["pivots_discovered"] > 0
    assert "graph" in data
    assert "recommendations" in data


def test_ai_investigator_grounded_analysis():
    res = client.post("/api/v1/ai/analyze", json={
        "query": "Why are these incidents connected?",
        "incident_id": "INC-0001",
        "context": {"shared_elements": ["Phone: +919876543210", "UPI: sbikyc.verify@okhdfcbank"]}
    })
    assert res.status_code == 200
    data = res.json()
    assert "summary" in data
    assert "evidence_text" in data
    assert "analysis_text" in data
    assert "limitations_text" in data
    assert "next_steps_text" in data
    assert data["confidence_score"] > 0.8


def test_evaluation_engine():
    res = client.post("/api/v1/evaluation/run")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "COMPLETED"
    assert "metrics" in data
    assert data["metrics"]["scam_dna_f1"] > 0.85
    assert data["metrics"]["false_campaign_rate"] < 0.05
    assert "latency" in data["metrics"]


def test_export_reports():
    res_json = client.get("/api/v1/reports/export?format=json")
    assert res_json.status_code == 200
    assert "report_title" in res_json.json()

    res_csv = client.get("/api/v1/reports/export?format=csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]

    res_stix = client.get("/api/v1/reports/export?format=stix")
    assert res_stix.status_code == 200
    assert res_stix.json()["type"] == "bundle"
