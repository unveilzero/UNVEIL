"""Model keys a signed-in user adds for their own account.

Any account can connect its own provider key here. The connection belongs to
that account only: it is never shared, the provider address comes from a fixed
list (the caller cannot supply one), and nothing global is changed.
"""

import json
import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Body, HTTPException, Request

from core.database import ModelEndpoint, SessionLocal
from src.auth_helpers import _auth_disabled, get_current_user

logger = logging.getLogger(__name__)

PERSONAL_KEY_PROVIDERS = {
    "anthropic": ("Anthropic", "https://api.anthropic.com/v1"),
    "openai": ("OpenAI", "https://api.openai.com/v1"),
    "openrouter": ("OpenRouter", "https://openrouter.ai/api/v1"),
    "groq": ("Groq", "https://api.groq.com/openai/v1"),
    "gemini": ("Gemini", "https://generativelanguage.googleapis.com/v1beta/openai"),
    "xai": ("xAI", "https://api.x.ai/v1"),
    "deepseek": ("DeepSeek", "https://api.deepseek.com/v1"),
    "nvidia": ("NVIDIA", "https://integrate.api.nvidia.com/v1"),
}
MAX_PERSONAL_KEYS = 8
_URL_TO_PROVIDER = {url: key for key, (_name, url) in PERSONAL_KEY_PROVIDERS.items()}


def _list_provider_models(base_url: str, api_key: str) -> list:
    """Ask the provider which models this key can use. Empty means it was refused."""
    from routes.model_routes import _probe_endpoint
    return _probe_endpoint(base_url, api_key, timeout=15) or []


def _caller(request: Request) -> str:
    user = get_current_user(request)
    if not user or user in {"api", "internal-tool"}:
        raise HTTPException(401, "Sign in to manage your model keys")
    return user


def _row(ep: ModelEndpoint) -> dict:
    try:
        models = json.loads(ep.cached_models or "[]")
    except (TypeError, ValueError):
        models = []
    return {
        "id": ep.id,
        "name": ep.name,
        "provider": _URL_TO_PROVIDER.get(ep.base_url, ""),
        "has_key": bool(ep.api_key),
        "models": models if isinstance(models, list) else [],
    }


def setup_my_keys_routes(invalidate_models_cache=None) -> APIRouter:
    router = APIRouter(prefix="/api/my", tags=["my-keys"])

    def _invalidate() -> None:
        if invalidate_models_cache:
            try:
                invalidate_models_cache()
            except Exception:
                logger.debug("model cache invalidation failed", exc_info=True)

    @router.get("/model-keys")
    def list_my_keys(request: Request):
        user = _caller(request)
        db = SessionLocal()
        try:
            rows = db.query(ModelEndpoint).filter(ModelEndpoint.owner == user).all()
            return {"keys": [_row(ep) for ep in rows], "providers": sorted(PERSONAL_KEY_PROVIDERS)}
        finally:
            db.close()

    @router.post("/model-keys")
    def add_my_key(request: Request, body: dict = Body(...)):
        if _auth_disabled():
            raise HTTPException(400, "Personal keys need sign-in to be turned on")
        user = _caller(request)
        provider = str(body.get("provider") or "").strip().lower()
        if provider == "google":
            provider = "gemini"
        if provider not in PERSONAL_KEY_PROVIDERS:
            raise HTTPException(400, "Unknown provider. Choose one of: " + ", ".join(sorted(PERSONAL_KEY_PROVIDERS)))
        api_key = str(body.get("api_key") or "").strip()
        if not (8 <= len(api_key) <= 512) or any(ch.isspace() for ch in api_key):
            raise HTTPException(400, "That does not look like an API key")
        name, base_url = PERSONAL_KEY_PROVIDERS[provider]

        models = _list_provider_models(base_url, api_key)
        if not models:
            raise HTTPException(400, f"{name} did not accept that key, or returned no models")

        db = SessionLocal()
        try:
            ep: Optional[ModelEndpoint] = (
                db.query(ModelEndpoint)
                .filter(ModelEndpoint.owner == user, ModelEndpoint.base_url == base_url)
                .first()
            )
            if ep is None:
                owned = db.query(ModelEndpoint).filter(ModelEndpoint.owner == user).count()
                if owned >= MAX_PERSONAL_KEYS:
                    raise HTTPException(400, f"You can keep up to {MAX_PERSONAL_KEYS} keys. Remove one first.")
                ep = ModelEndpoint(
                    id=str(uuid.uuid4())[:8],
                    name=name,
                    base_url=base_url,
                    is_enabled=True,
                    model_type="llm",
                    endpoint_kind="api",
                    owner=user,
                )
                db.add(ep)
            ep.api_key = api_key
            ep.is_enabled = True
            ep.cached_models = json.dumps(models)
            db.commit()
            result = _row(ep)
        finally:
            db.close()
        _invalidate()
        return result

    @router.delete("/model-keys/{key_id}")
    def remove_my_key(key_id: str, request: Request):
        user = _caller(request)
        db = SessionLocal()
        try:
            ep = (
                db.query(ModelEndpoint)
                .filter(ModelEndpoint.id == key_id, ModelEndpoint.owner == user)
                .first()
            )
            if ep is None:
                raise HTTPException(404, "No such key on your account")
            db.delete(ep)
            db.commit()
        finally:
            db.close()
        _invalidate()
        return {"ok": True}

    return router
