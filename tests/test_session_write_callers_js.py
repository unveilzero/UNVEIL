"""An action that makes a session and then writes its first messages stops when the server does not keep them.

The action removes the sessions that it made and tells the person why. The page functions run in node with
stand-ins for fetch and for the page; the tests skip when `node` is not installed.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from tests.helpers.js_modules import js_function_source

ROOT = Path(__file__).resolve().parents[1]
REASON = "UNVEIL did not keep this text."

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node binary not on PATH")

# The stand-in server: it makes sessions s1, s2, ... and does not keep the write with the number `refusedWrite`.
_PAGE = r'''
import { writeSessionMessages, removeSessions } from './static/js/sessionWrite.js';
const source = JSON.parse(process.argv[1]).replace(/^export /gm, ''), refusedWrite = JSON.parse(process.argv[2]);
const API_BASE = 'http://app', requests = [], shown = [], selected = [], stored = {};
let sessions = 0, writes = 0, closed = false, indicator = null;
globalThis.fetch = async (url, options = {}) => {
  requests.push((options.method || 'GET') + ' ' + url.replace(API_BASE, ''));
  if (url.endsWith('/api/session')) return { ok: true, status: 200, json: async () => ({ id: 's' + (++sessions) }) };
  if (url.endsWith('/inject_messages') && ++writes === refusedWrite) {
    return { ok: false, status: 403, json: async () => ({ detail: { message: 'UNVEIL did not keep this text.' } }) };
  }
  return { ok: true, status: 200, json: async () => ({}) };
};
globalThis.localStorage = { setItem(key, value) { stored[key] = value; }, removeItem(key) { delete stored[key]; } };
globalThis.history = { replaceState() {} };
globalThis.window = {
  sessionModule: { setCurrentSessionId() {}, async loadSessions() {}, async selectSession(id) { selected.push(id); } },
  _syncGroupIndicator(on) { indicator = on; },
};
const uiModule = { showError(text) { shown.push(text); }, showToast(text) { shown.push(text); } };
'''


def _node(script, *args):
    result = subprocess.run(["node", "--input-type=module", "-e", script, *map(json.dumps, args)],
                            cwd=ROOT, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _start_group(refused_write):
    source = (ROOT / "static/js/group.js").read_text()
    functions = "\n".join(js_function_source(name, source) for name in ["startGroup", "stopGroup", "_saveState"])
    return _node(_PAGE + r'''
const Storage = { getJSON(key, fallback) { return fallback; } }, GROUP_STATE_KEY = 'odysseus-group-state';
let _models = [], _active = false, _roundRobinIdx = 0, _participantSessions = [], _parentSessionId = null,
    _abortControllers = [], _mode = 'parallel';
const models = [{ mid: 'model-a', display: 'Model A', url: 'http://a' },
                { mid: 'model-b', display: 'Model B', url: 'http://b',
                  character: { characterName: 'Persona B', characterPrompt: 'You are Persona B.' } }];
eval(source + '\nglobalThis.run = async () => ({ started: await startGroup(models, "group-1"), active: _active });');
console.log(JSON.stringify({ ...(await globalThis.run()), requests, shown, selected, indicator, saved: 'odysseus-group-state' in stored }));
''', functions, refused_write)


def test_group_start_keeps_its_sessions_when_each_participant_got_its_instructions():
    out = _start_group(0)
    assert out["started"] is True and out["active"] is True and out["saved"] is True and out["shown"] == []
    assert out["requests"] == ["POST /api/session", "POST /api/session", "POST /api/session/s2/inject_messages",
                               "POST /api/session", "POST /api/session/s3/inject_messages"]
    assert out["selected"] == ["s1"]


@pytest.mark.parametrize("refused_write, made", [(1, ["s1", "s2"]), (2, ["s1", "s2", "s3"])])
def test_group_start_stops_when_a_participant_did_not_get_its_instructions(refused_write, made):
    out = _start_group(refused_write)
    assert out["started"] is False and out["active"] is False and out["saved"] is False and out["indicator"] is False
    assert out["shown"] == [f"The group chat did not start. {REASON}"] and out["selected"] == []
    assert out["requests"][-len(made):] == [f"DELETE /api/session/{sid}" for sid in made]
    assert sum(request.endswith("/inject_messages") for request in out["requests"]) == refused_write


def _open_task_result(refused_write):
    source = js_function_source("_openResultInChat", (ROOT / "static/js/tasks.js").read_text())
    return _node(_PAGE + r'''
function closeTasks() { closed = true; }
eval(source + '\nglobalThis.run = () => _openResultInChat({ taskName: "Daily summary", result: "Done." });');
await globalThis.run();
console.log(JSON.stringify({ requests, shown, selected, closed }));
''', source, refused_write)


def test_task_result_opens_in_a_chat_when_the_server_kept_it():
    out = _open_task_result(0)
    assert out == {"requests": ["GET /api/default-chat", "POST /api/session", "POST /api/session/s1/inject_messages"],
                   "shown": [], "selected": ["s1"], "closed": True}


def test_task_result_chat_is_removed_when_the_server_did_not_keep_the_result():
    out = _open_task_result(1)
    assert out == {"requests": ["GET /api/default-chat", "POST /api/session", "POST /api/session/s1/inject_messages",
                                "DELETE /api/session/s1"],
                   "shown": [REASON], "selected": [], "closed": False}
