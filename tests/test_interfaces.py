import json

from fastapi.testclient import TestClient

from phishguard.api import MAX_BATCH_SIZE, app
from phishguard.cli import main

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_index_serves_ui():
    response = client.get("/")
    assert response.status_code == 200
    assert "PhishGuard" in response.text


def test_analyze_endpoint():
    response = client.post("/analyze", json={"url": "https://paypa1.com/login"})
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] in ("suspicious", "phishing")
    assert body["findings"]


def test_analyze_rejects_invalid_url():
    assert client.post("/analyze", json={"url": "http://"}).status_code == 422
    assert client.post("/analyze", json={"url": ""}).status_code == 422
    assert client.post("/analyze", json={"url": "x" * 5000}).status_code == 422


def test_batch_reports_errors_per_item():
    response = client.post("/analyze/batch", json={"urls": ["https://google.com", "http://"]})
    assert response.status_code == 200
    first, second = response.json()
    assert first["report"]["verdict"] == "low_risk"
    assert second["error"]


def test_batch_size_is_limited():
    urls = ["https://example.com"] * (MAX_BATCH_SIZE + 1)
    assert client.post("/analyze/batch", json={"urls": urls}).status_code == 422


def test_cli_json_output(capsys):
    assert main(["--json", "https://paypa1.com"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["registered_domain"] == "paypa1.com"


def test_cli_fail_on(capsys):
    assert main(["--fail-on", "suspicious", "https://paypa1-login.xyz"]) == 1
    assert main(["--fail-on", "phishing", "https://www.google.com"]) == 0


def test_cli_reads_file(tmp_path, capsys):
    urls = tmp_path / "urls.txt"
    urls.write_text("# comentario\nhttps://google.com\n\nhttps://paypa1.com\n", encoding="utf-8")
    assert main(["--json", "-f", str(urls)]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 2


def test_cli_invalid_url_exit_code(capsys):
    assert main(["http://"]) == 2
