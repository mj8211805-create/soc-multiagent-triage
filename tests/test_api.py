"""API endpoint tests using FastAPI TestClient."""

from fastapi.testclient import TestClient
from server.app import app

client = TestClient(app)


def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert "IngestionAgent" in data["agents"]


def test_api_list_scenarios():
    res = client.get("/api/scenarios")
    assert res.status_code == 200
    data = res.json()
    assert len(data["scenarios"]) >= 4


def test_api_pipeline_run_scenario():
    res = client.post("/api/pipeline/run", json={"scenario_name": "apt29"})
    assert res.status_code == 200
    data = res.json()
    assert data["is_completed"] is True
    assert len(data["incident_reports"]) >= 1


def test_api_malware_analysis():
    res = client.post("/api/malware/analyze", json={
        "file_name": "lockbit.exe",
        "command_line": "vssadmin.exe Delete Shadows /All /Quiet"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["is_malicious"] is True
    assert data["risk_score"] >= 50.0


def test_api_benchmark_run():
    res = client.post("/api/benchmark/run", json={
        "dataset_name": "mixed",
        "total_alerts": 20
    })
    assert res.status_code == 200
    data = res.json()
    assert "multi_agent_system" in data
    assert "single_llm_baseline" in data
