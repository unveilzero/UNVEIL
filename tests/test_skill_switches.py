"""Per-user on/off switches for skills."""

import pytest

from services.memory.builtin_skills import install_builtin_skills
from services.memory.skills import SkillsManager


@pytest.fixture
def manager(tmp_path, monkeypatch):
    prefs = {}
    import routes.prefs_routes as prefs_routes

    monkeypatch.setattr(prefs_routes, "_load_for_user", lambda user=None: dict(prefs.get(user, {})))
    manager = SkillsManager(str(tmp_path))
    install_builtin_skills(manager, owners=())
    manager.prefs = prefs
    return manager


def _names(rows):
    return {row["name"] for row in rows}


def test_every_skill_is_on_by_default(manager):
    rows = manager.load(owner="george")
    assert rows and all(row["enabled"] is True for row in rows)
    assert "developer-docs" in _names(manager.index_for(owner="george"))


def test_a_switched_off_skill_stays_listed_but_is_hidden_from_the_agent(manager):
    manager.prefs["george"] = {"skills_off": ["developer-docs"]}
    rows = {row["name"]: row for row in manager.load(owner="george")}
    assert rows["developer-docs"]["enabled"] is False
    assert rows["terminal-recovery"]["enabled"] is True
    assert "developer-docs" not in _names(manager.index_for(owner="george"))
    assert "terminal-recovery" in _names(manager.index_for(owner="george"))
    assert manager.is_enabled("developer-docs", owner="george") is False


def test_relevance_search_skips_switched_off_skills(manager):
    query = "how does this library API work, check the developer documentation"
    found = manager.get_relevant_skills(query, skills=manager.load(owner="george"), threshold=0.05)
    assert "developer-docs" in _names(found)
    manager.prefs["george"] = {"skills_off": ["developer-docs"]}
    found = manager.get_relevant_skills(query, skills=manager.load(owner="george"), threshold=0.05)
    assert "developer-docs" not in _names(found)


def test_one_users_switch_does_not_affect_another_user(manager):
    manager.prefs["george"] = {"skills_off": ["developer-docs"]}
    assert "developer-docs" in _names(manager.index_for(owner="someone-else"))
    assert manager.is_enabled("developer-docs", owner="someone-else") is True


@pytest.mark.parametrize("value", [None, "developer-docs", 7, {"developer-docs": True}, [None, 3, ""]])
def test_a_malformed_preference_switches_nothing_off(manager, value):
    manager.prefs["george"] = {"skills_off": value}
    assert all(row["enabled"] is True for row in manager.load(owner="george"))


def test_the_agent_cannot_open_a_switched_off_skill(manager, monkeypatch):
    import src.tools.system as system

    source = open(system.__file__, encoding="utf-8").read()
    assert "is switched off for this account" in source
    assert source.index("sm.is_enabled(name, owner=owner)") < source.index("md = sm.read_skill_md(name, owner=owner)")


def test_the_shared_catalog_is_not_modified_by_a_switch(manager):
    manager.prefs["george"] = {"skills_off": ["developer-docs"]}
    manager.load(owner="george")
    assert all("enabled" not in row for row in manager.load_all())
