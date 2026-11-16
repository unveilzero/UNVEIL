"""Peer injections retain their context role but hydrate as the named agent."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from tests.helpers.js_modules import js_function_source

ROOT = Path(__file__).resolve().parents[1]


def _node(script, *args):
    result = subprocess.run(['node', '--input-type=module', '-e', script, *map(json.dumps, args)],
                            cwd=ROOT, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _sync(mode, participants, response):
    """Run the group chat sync with a stand-in for fetch. Returns the writes it sent and the errors it showed."""
    source = (ROOT / 'static/js/group.js').read_text()
    functions = '\n'.join(js_function_source(name, source)
                          for name in ['_writeToSession', '_syncAllResponses', '_sendRoundRobin'])
    return _node(r'''
import { writeSessionMessages } from './static/js/sessionWrite.js';
const source=JSON.parse(process.argv[1]),mode=JSON.parse(process.argv[2]);
const _models=[{mid:'model-a',display:'Model A',_groupName:'Persona A'}, {mid:'model-b',display:'Model B'},
               {mid:'model-c',display:'Model C'}].slice(0, JSON.parse(process.argv[3]));
const _participantSessions=['a','b','c'].slice(0, _models.length),API_BASE='http://app',sent=[],shown=[];
let _abortControllers=[];
const uiModule={scrollHistory(){}, showError(text){shown.push(text);}};
function _createGroupBubble(model){return {dataset:{raw:'Reply from '+model.mid}};}
async function _streamToHolder(){} function _saveState(){}
const response=JSON.parse(process.argv[4]);
globalThis.fetch=async (url,options)=>{sent.push({url,...JSON.parse(options.body)});return {...response, json: async()=>response.body};};
eval(source+'\nglobalThis.runSync=async()=> mode==="parallel" ? _syncAllResponses(_models.map(_createGroupBubble)) : _sendRoundRobin("Hi",null);');
await globalThis.runSync();console.log(JSON.stringify({sent, shown}));
''', functions, mode, participants, response)


@pytest.mark.skipif(not shutil.which('node'), reason='node not installed')
@pytest.mark.parametrize('mode', ['parallel', 'round-robin'])
def test_peer_sync_shows_the_reason_when_a_write_is_not_kept(mode):
    reason = 'UNVEIL did not keep this text.'
    result = _sync(mode, 3, {'ok': False, 'status': 403, 'body': {'detail': {'message': reason}}})
    # Each of the 3 replies goes to 2 other participants. The first write that is not kept ends the sync of that reply.
    assert len(result['sent']) == 3 and result['shown'] == [reason] * 3


@pytest.mark.skipif(not shutil.which('node'), reason='node not installed')
@pytest.mark.parametrize('mode', ['parallel', 'round-robin'])
def test_peer_sync_persists_explicit_identity(mode):
    result = _sync(mode, 2, {'ok': True, 'status': 200, 'body': {'ok': True}})
    data = result['sent']
    assert len(data) == 2 and result['shown'] == []
    for item in data:
        message = item['messages'][0]
        assert message['role'] == 'user'  # Model context must retain peer attribution.
        peer = 'model-b' if item['url'].endswith('/a/inject_messages') else 'model-a'
        name = 'Model B' if peer == 'model-b' else 'Persona A'
        assert message['content'] == f'[{name}]: Reply from {peer}'
        assert message['metadata'] == {'group_peer': True, 'group_model': name, 'model': peer}


@pytest.mark.skipif(not shutil.which('node'), reason='node not installed')
@pytest.mark.parametrize('role,content,meta,expected_role,expected_content', [
    ('user', '[Persona A]: Reply', {'group_peer': True, 'group_model': 'Persona A'}, 'assistant', 'Reply'),
    ('user', '[Persona A]: Human text', {}, 'user', '[Persona A]: Human text'),
    ('user', 'Human text', {}, 'user', 'Human text'),
    ('assistant', 'Parent reply', {'group_model': 'Persona A'}, 'assistant', 'Parent reply'),
    ('user', 'No matching prefix', {'group_peer': True, 'group_model': 'Persona A'}, 'user', 'No matching prefix'),
    ('user', '[3]: Human text', {'group_peer': True, 'group_model': 3}, 'user', '[3]: Human text'),
    ('user', '[Persona A]: Human text', {'group_peer': False, 'group_model': 'Persona A'}, 'user', '[Persona A]: Human text'),
])
def test_history_uses_explicit_peer_identity_only(role, content, meta, expected_role, expected_content):
    source = js_function_source('_renderHistoryMessage', (ROOT / 'static/js/sessions.js').read_text())
    result = _node(r'''
const source=JSON.parse(process.argv[1]),message=JSON.parse(process.argv[2]);
function _displayHistoryContent(text){return text;}function _stripUserVisionBlocks(text){return text;}
function _addHistoryMessageWithFullRenderer(role,content,model,metadata){return {role,content,metadata};}
const run=eval('('+source+')');console.log(JSON.stringify(run(message,'session-model')));
''', source, {'role': role, 'content': content, 'metadata': meta})
    assert result['role'] == expected_role
    assert result['content'] == expected_content
    assert result['metadata'] == {**meta, '_fromHistory': True}
