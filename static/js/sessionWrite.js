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
