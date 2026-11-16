"""The page helper that writes messages into a session and tells the caller what to show when a write is not kept.

Driven through `node --input-type=module` (same approach as test_match_model_key_js.py); skips when `node` is not installed.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
_HELPER = _REPO / "static" / "js" / "sessionWrite.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node binary not on PATH")


def _write(fetch_js):
    """Run the helper with a stand-in for fetch. Returns what the helper returned and the request it made."""
    js = (
        f"import {{ writeSessionMessages }} from '{_HELPER.as_posix()}';"
        "let request = null;"
        f"globalThis.fetch = async (url, options) => {{ request = {{ url, method: options.method, body: JSON.parse(options.body) }}; {fetch_js} }};"
        "const problem = await writeSessionMessages('/base', 'abc', [{ role: 'user', content: 'Hello' }]);"
        "console.log(JSON.stringify({ problem, request }));"
    )
    proc = subprocess.run(["node", "--input-type=module"], input=js, capture_output=True, text=True, cwd=str(_REPO), timeout=30)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip())


def test_kept_write_gives_nothing_to_show():
    out = _write("return { ok: true, status: 200, json: async () => ({ ok: true }) };")
    assert out["problem"] == ""
    assert out["request"] == {"url": "/base/api/session/abc/inject_messages", "method": "POST",
                              "body": {"messages": [{"role": "user", "content": "Hello"}]}}


def test_refused_write_gives_the_reason_from_the_server():
    reason = "UNVEIL did not send this message to a model."
    out = _write("return { ok: false, status: 403, json: async () => ({ detail: { error: 'UNVEIL_GUARD_BLOCKED', message: "
                 + json.dumps(reason) + " } }) };")
    assert out["problem"] == reason


@pytest.mark.parametrize("fetch_js", [
    "return { ok: false, status: 500, json: async () => { throw new Error('not JSON'); } };",
    "return { ok: false, status: 404, json: async () => ({ detail: 'Session not found' }) };",
])
def test_write_that_failed_with_no_reason_gives_the_status(fetch_js):
    out = _write(fetch_js)
    assert out["problem"].startswith("These messages were not saved to the chat (HTTP ")


def test_write_that_did_not_reach_the_server_gives_the_error():
    out = _write("throw new Error('offline');")
    assert out["problem"] == "These messages were not saved to the chat: offline"
