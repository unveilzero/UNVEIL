"""A signed-in account can add model keys for itself, and only for itself."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from core.database import ModelEndpoint


def _request(user):
    return SimpleNamespace(state=SimpleNamespace(current_user=user))


@pytest.fixture
def keys(monkeypatch):
    import routes.my_keys_routes as mk

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    ModelEndpoint.__table__.create(engine)
    Session = sessionmaker(bind=engine)
    monkeypatch.setattr(mk, "SessionLocal", Session)
    monkeypatch.setattr(mk, "_auth_disabled", lambda: False)
    probes = []

    def fake_probe(base_url, api_key):
        probes.append((base_url, api_key))
        return [] if api_key == "sk-rejected-key" else ["model-a", "model-b"]

    monkeypatch.setattr(mk, "_list_provider_models", fake_probe)
    cleared = []
    router = mk.setup_my_keys_routes(lambda: cleared.append(1))
    routes = {(r.path, next(iter(r.methods))): r.endpoint for r in router.routes}
    return SimpleNamespace(
        add=routes[("/api/my/model-keys", "POST")],
        list=routes[("/api/my/model-keys", "GET")],
        remove=routes[("/api/my/model-keys/{key_id}", "DELETE")],
        Session=Session, probes=probes, cleared=cleared,
    )


def test_key_is_stored_for_the_caller_only(keys):
    made = keys.add(_request("alice"), {"provider": "anthropic", "api_key": "sk-ant-alice-key"})
    assert made["provider"] == "anthropic" and made["models"] == ["model-a", "model-b"]
    assert "api_key" not in made and "sk-ant-alice-key" not in str(made)
    assert keys.probes == [("https://api.anthropic.com/v1", "sk-ant-alice-key")]
    assert keys.cleared

    db = keys.Session()
    row = db.query(ModelEndpoint).one()
    assert row.owner == "alice" and row.base_url == "https://api.anthropic.com/v1"
    db.close()

    assert [k["id"] for k in keys.list(_request("alice"))["keys"]] == [made["id"]]
    assert keys.list(_request("bob"))["keys"] == []


def test_another_account_cannot_remove_or_replace_it(keys):
    made = keys.add(_request("alice"), {"provider": "openai", "api_key": "sk-proj-alice-key"})
    with pytest.raises(HTTPException) as err:
        keys.remove(made["id"], _request("bob"))
    assert err.value.status_code == 404

    keys.add(_request("bob"), {"provider": "openai", "api_key": "sk-proj-bob-key-1"})
    db = keys.Session()
    by_owner = {r.owner: r.api_key for r in db.query(ModelEndpoint).all()}
    db.close()
    assert by_owner == {"alice": "sk-proj-alice-key", "bob": "sk-proj-bob-key-1"}

    assert keys.remove(made["id"], _request("alice")) == {"ok": True}
    assert keys.list(_request("alice"))["keys"] == []


def test_adding_the_same_provider_again_replaces_the_key(keys):
    first = keys.add(_request("alice"), {"provider": "groq", "api_key": "gsk_first_key"})
    second = keys.add(_request("alice"), {"provider": "groq", "api_key": "gsk_second_key"})
    assert first["id"] == second["id"]
    db = keys.Session()
    assert [r.api_key for r in db.query(ModelEndpoint).all()] == ["gsk_second_key"]
    db.close()


@pytest.mark.parametrize(
    "body",
    [
        {"provider": "http://127.0.0.1:8000/v1", "api_key": "sk-something-long"},
        {"provider": "anthropic", "api_key": ""},
        {"provider": "anthropic", "api_key": "short"},
        {"provider": "anthropic", "api_key": "has a space in it"},
        {"provider": "anthropic", "api_key": "sk-rejected-key"},
        {"provider": "anthropic", "base_url": "http://10.0.0.5/v1", "api_key": ""},
    ],
)
def test_bad_requests_store_nothing(keys, body):
    with pytest.raises(HTTPException) as err:
        keys.add(_request("alice"), body)
    assert err.value.status_code == 400
    db = keys.Session()
    assert db.query(ModelEndpoint).count() == 0
    db.close()


def test_caller_supplied_address_is_ignored(keys):
    keys.add(_request("alice"), {"provider": "anthropic", "base_url": "http://10.0.0.5/v1", "api_key": "sk-ant-alice-key"})
    assert keys.probes == [("https://api.anthropic.com/v1", "sk-ant-alice-key")]


@pytest.mark.parametrize("user", [None, "", "api", "internal-tool"])
def test_requires_a_signed_in_account(keys, user):
    for call in (
        lambda: keys.list(_request(user)),
        lambda: keys.add(_request(user), {"provider": "anthropic", "api_key": "sk-ant-some-key"}),
        lambda: keys.remove("abc", _request(user)),
    ):
        with pytest.raises(HTTPException) as err:
            call()
        assert err.value.status_code == 401


def test_key_count_is_capped(keys, monkeypatch):
    import routes.my_keys_routes as mk
    monkeypatch.setattr(mk, "MAX_PERSONAL_KEYS", 2)
    keys.add(_request("alice"), {"provider": "anthropic", "api_key": "sk-ant-alice-key"})
    keys.add(_request("alice"), {"provider": "openai", "api_key": "sk-proj-alice-key"})
    with pytest.raises(HTTPException) as err:
        keys.add(_request("alice"), {"provider": "groq", "api_key": "gsk_alice_key"})
    assert err.value.status_code == 400


def test_admin_connections_can_be_kept_from_other_accounts(keys, monkeypatch):
    from src import auth_helpers, tool_security

    db = keys.Session()
    db.add(ModelEndpoint(id="shared1", name="Shared", base_url="https://api.anthropic.com/v1", owner=None, is_enabled=True))
    db.add(ModelEndpoint(id="alice1", name="Mine", base_url="https://api.openai.com/v1", owner="alice", is_enabled=True))
    db.commit()
    monkeypatch.setattr(tool_security, "owner_is_admin_or_single_user", lambda u: u == "root")

    def visible(user):
        q = auth_helpers.owner_filter(db.query(ModelEndpoint), ModelEndpoint, user)
        return sorted(r.id for r in q.all())

    monkeypatch.delenv("UNVEIL_SHARE_ADMIN_MODELS", raising=False)
    assert visible("alice") == ["alice1", "shared1"]

    monkeypatch.setenv("UNVEIL_SHARE_ADMIN_MODELS", "false")
    assert visible("alice") == ["alice1"]
    assert visible("bob") == []
    assert visible("root") == ["shared1"]
    db.close()
