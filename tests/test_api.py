"""
FastAPI Endpoint Integration Tests
"""

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_analyze_endpoint():
    log_sample = 'Oct 25 14:00:01 host sshd[100]: Failed password for admin from 198.51.100.1 port 22 ssh2'
    res = client.post("/api/analyze", json={"raw_content": log_sample})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["result"]["summary"]["total_lines"] == 1


def test_benchmark_endpoint():
    res = client.post("/api/benchmarks", json={"line_count": 1000})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "throughput_lines_sec" in data["benchmark"]
