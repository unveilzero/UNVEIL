"""web_fetch result shaping: passage selection and the JSON field view."""

import asyncio
import json

from src.agent_tools.web_tools import WebFetchTool


def _two_table_page():
    filler = [f"Background sentence number {i} about something else." for i in range(60)]
    standard = [
        "Model pricing",
        "Model | Input | Output",
        "Alpha 5 | $8 / MTok | $40 / MTok",
        "Beta 5 | $2 / MTok | $10 / MTok",
    ]
    discounted = [
        "Batch processing",
        "Model | Batch input | Batch output | Cached | Saved",
        "Alpha 5 | $4 / MTok | $20 / MTok | $0.40 | 50 | 2026",
        "Beta 5 | $1 / MTok | $5 / MTok | $0.10 | 50 | 2026",
    ]
    return "\n".join([*filler, *standard, *filler, *discounted, *filler])


def test_focused_passages_show_every_table_that_matches_in_page_order():
    focused = WebFetchTool._focused_passages(_two_table_page(), "Alpha 5, Beta 5", 9000)
    assert "Alpha 5 | $8 / MTok | $40 / MTok" in focused
    assert "Alpha 5 | $4 / MTok | $20 / MTok" in focused
    assert focused.index("Model pricing") < focused.index("Batch processing")
    assert "matching passage 1 of 2" in focused and "matching passage 2 of 2" in focused


def test_focused_passages_cover_terms_found_in_different_places():
    lines = [f"filler {i}" for i in range(200)]
    lines[20] = "Zeta appears only here"
    lines[150] = "Omega appears only here"
    focused = WebFetchTool._focused_passages("\n".join(lines), "Zeta, Omega, Missing", 6000)
    assert "Zeta appears only here" in focused and "Omega appears only here" in focused
    assert "no match on this page for: Missing" in focused


def test_focused_passages_stay_inside_the_budget_and_say_what_was_left_out():
    lines = [f"filler line {i} with some padding text to take up room" for i in range(900)]
    for index in range(40, 900, 120):
        lines[index] = f"Target row {index}"
    focused = WebFetchTool._focused_passages("\n".join(lines), "Target", 5000)
    assert len(focused) <= 5200
    assert "Target row 40" in focused
    assert "more matching passage(s) not shown" in focused


def _api_body():
    related = {"description": "Parent text", "default_branch": "main", "html_url": "https://example.test/parent"}
    body = {"id": 7, "name": "demo", "description": "Own text"}
    body.update({f"thing_{i}_url": f"https://example.test/{i}" for i in range(80)})
    body.update({"pushed_at": "2026-11-12T02:52:59Z", "license": {"spdx_id": "AGPL-3.0"}, "default_branch": "dev", "parent": related})
    return json.dumps(body, indent=2)


def test_json_view_lists_own_fields_before_nested_ones_and_drops_link_fields():
    view = WebFetchTool._structured_view(_api_body(), "", 9000)
    assert view.index('default_branch: "dev"') < view.index('parent.default_branch: "main"')
    assert 'description: "Own text"' in view and 'license.spdx_id: "AGPL-3.0"' in view
    assert "thing_3_url" not in view
    assert "81 link fields ending in url omitted" in view
    assert len(view) < len(_api_body()) // 3


def test_json_view_with_a_query_returns_only_matching_fields_labelled_by_path():
    view = WebFetchTool._structured_view(_api_body(), "description, default_branch, stars", 9000)
    assert 'description: "Own text"' in view and 'parent.description: "Parent text"' in view
    assert 'default_branch: "dev"' in view
    assert "pushed_at" not in view and "thing_3_url" not in view
    assert "no field matched: stars" in view


def test_json_view_can_list_link_fields_when_asked():
    view = WebFetchTool._structured_view(_api_body(), "html_url", 9000)
    assert 'parent.html_url: "https://example.test/parent"' in view


def test_json_view_leaves_short_bodies_and_other_text_alone():
    assert WebFetchTool._structured_view('{"ok": true}', "", 9000) is None
    assert WebFetchTool._structured_view("{not json at all " * 400, "", 9000) is None
    assert WebFetchTool._structured_view("Plain page text " * 400, "page", 9000) is None
    assert WebFetchTool._structured_view(_api_body(), "nothing-matches-this", 9000) is None


def test_web_fetch_uses_the_json_view_end_to_end(monkeypatch):
    import services.search.content as content

    def fake(url, timeout=5, retry_attempt=0, max_bytes=None):
        return {"url": url, "title": "demo", "content": _api_body(), "success": True, "error": ""}

    monkeypatch.setattr(content, "fetch_webpage_content", fake)
    payload = {"urls": ["https://example.test/a", "https://example.test/b"], "query": "description, default_branch, license"}
    result = asyncio.run(WebFetchTool().execute(json.dumps(payload), {}))
    assert result["exit_code"] == 0 and result["successful"] == 2
    assert result["output"].count('default_branch: "dev"') == 2
    assert result["output"].count('license.spdx_id: "AGPL-3.0"') == 2
    assert "batch item truncated" not in result["output"]
