"""App settings, read from the repo-root `.env` file (see .env.example). Owner: P1."""
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BACKEND_DIR.parent
DATA_DIR = BACKEND_DIR / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(REPO_ROOT / ".env", BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # AI (Gemini) — wrapper in ai/llm.py
    llm_provider: str = ""
    llm_api_key: str = ""
    llm_model: str = ""
    llm_timeout_seconds: float = 20.0

    # Threat intel (P2)
    google_safe_browsing_api_key: str = ""
    urlhaus_auth_key: str = ""

    # Blockchain (P4)
    sepolia_rpc_url: str = ""
    registry_private_key: str = ""
    registry_contract_address: str = ""
    # A report may only be registered on-chain within this many hours of being created, and Verify rejects
    # seals added later than that (stops someone editing a report and sealing the fake version afterwards).
    registration_window_hours: float = 24.0

    # General
    check_timeout_seconds: float = 8.0
    mock_analyzers: bool = False
    max_message_urls: int = 3
    db_path: Path = DATA_DIR / "app.db"
    # Websites allowed to call this API from a browser. Local dev is always allowed; add the live frontend with
    # CORS_ORIGINS=https://your-app.vercel.app (comma-separated for several).
    cors_origins: str = ""

    @property
    def allowed_origins(self) -> list[str]:
        local = ["http://localhost:5173", "http://127.0.0.1:5173"]
        extra = [o.strip().rstrip("/") for o in self.cors_origins.split(",") if o.strip()]
        return local + extra


settings = Settings()
