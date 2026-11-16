// Writes messages into a session.
// Returns '' when the server kept them. Otherwise it returns the text to show the person.
export async function writeSessionMessages(apiBase, sessionId, messages) {
  let res;
  try {
    res = await fetch(`${apiBase}/api/session/${sessionId}/inject_messages`, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages }),
    });
  } catch (e) {
    return `These messages were not saved to the chat: ${e.message || e}`;
  }
  if (res.ok) return '';
  const body = await res.json().catch(() => null);
  return body?.detail?.message || `These messages were not saved to the chat (HTTP ${res.status}).`;
}

// Removes the sessions that an action made and did not finish, so that none stays behind half done.
// Returns '' when the server removed each one. Otherwise it returns the text to show the person.
export async function removeSessions(apiBase, sessionIds) {
  const problems = (await Promise.all(sessionIds.map(async (id) => {
    try {
      const res = await fetch(`${apiBase}/api/session/${id}`, { method: 'DELETE', credentials: 'same-origin' });
      return res.ok ? '' : `HTTP ${res.status}`;
    } catch (e) {
      return String(e.message || e);
    }
  }))).filter(Boolean);
  return problems.length ? `${problems.length} unfinished chat(s) could not be removed (${problems[0]}).` : '';
}
