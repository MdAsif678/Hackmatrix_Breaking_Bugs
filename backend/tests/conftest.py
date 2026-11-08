import pytest
from fastapi.testclient import TestClient

from app.config import settings


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Every test gets its own empty SQLite file."""
    monkeypatch.setattr(settings, "db_path", tmp_path / "test.db")
    monkeypatch.setattr(settings, "mock_analyzers", False)


@pytest.fixture
def client():
    from app.main import app

    with TestClient(app) as c:
        yield c
