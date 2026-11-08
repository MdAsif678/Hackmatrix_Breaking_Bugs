"""Single LLM wrapper — the only place that talks to an AI provider. Owner: P3.

Provider, key and model come from .env (LLM_PROVIDER, LLM_API_KEY, LLM_MODEL).

Rules (AGENTS.md §8):
- user messages / webpage text are UNTRUSTED: wrap them in clear delimiters and tell the model
  to ignore any instructions inside them
- parse the reply as JSON and validate it with the given Pydantic model
- on any failure return None so callers fall back to rule-based results
- mask personal data that the model doesn't need
"""
from typing import Optional, TypeVar

from pydantic import BaseModel

from app.config import settings

T = TypeVar("T", bound=BaseModel)


def llm_available() -> bool:
    return bool(settings.llm_provider and settings.llm_api_key)


async def llm_json(system: str, user: str, schema: type[T]) -> Optional[T]:
    """Ask the LLM for JSON matching `schema`. Returns None if unavailable or invalid."""
    if not llm_available():
        return None
    # TODO(P3): call the provider, parse JSON, validate with schema.model_validate_json(...)
    return None
