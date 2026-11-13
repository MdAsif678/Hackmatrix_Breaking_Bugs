import pytest
from fastapi.testclient import TestClient

from app.config import settings


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Every test gets its own empty SQLite file."""
    monkeypatch.setattr(settings, "db_path", tmp_path / "test.db")
    monkeypatch.setattr(settings, "mock_analyzers", False)
    monkeypatch.setattr(settings, "llm_api_key", "")  # never call the real AI from tests
    monkeypatch.setattr(settings, "urlhaus_auth_key", "")  # never call real threat-intel APIs from tests
    monkeypatch.setattr(settings, "google_safe_browsing_api_key", "")
    monkeypatch.setattr(settings, "sepolia_rpc_url", "")  # never send real blockchain transactions
    monkeypatch.setattr(settings, "database_url", "")  # always the temporary SQLite file, never a real database
    monkeypatch.setattr(settings, "rate_limit_enabled", False)  # tests call the API many times


@pytest.fixture
def offline_analyzers(monkeypatch):
    """Replace the URL analyzers with offline stubs so API tests never touch the network."""
    from app import pipeline
    from app.analyzers.base import skipped

    def stub(name):
        async def analyze(target):
            return skipped(name, "offline test stub")
        return analyze

    monkeypatch.setattr(pipeline, "URL_ANALYZERS", [(name, stub(name)) for name, _ in pipeline.URL_ANALYZERS])


@pytest.fixture
def client(offline_analyzers):
    from app.main import app

    with TestClient(app) as c:
        yield c
