// UNVEIL security layer status.
// Shows whether the ARAD guard is clear or has blocked something, and lists
// recent decisions with the reason. It polls /api/unveil/security/status.
// A person can release one withheld result of their own from the list.

const POLL_MS = 15000;
let panelOpen = false;
let lastReport = null;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

function timeOf(seconds) {
  try { return new Date(seconds * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  catch (_) { return ''; }
}

function summarize(report) {
  if (!report) return { state: 'unknown', label: 'Shield offline', detail: 'Security status could not be read.' };
  if (report.lockdown) return { state: 'blocked', label: 'Lockdown', detail: 'All agent actions are stopped: ' + report.lockdown };
  const last = report.last_block;
  if (report.state === 'blocked' && last) {
    return { state: 'blocked', label: 'Blocked', detail: 'Blocked ' + last.tool + ' at ' + timeOf(last.at) + '.' };
  }
  return { state: 'cleared', label: 'Cleared', detail: 'Every agent action is being checked.' };
}

// Two taps: the first asks, the second releases.
function releaseButton(row, refresh) {
  const button = el('button', 'unveil-shield-release', 'Release this result');
  button.type = 'button';
  let asked = false;
  button.addEventListener('click', async (event) => {
    event.stopPropagation();
    if (!asked) { asked = true; button.textContent = 'Tap again to let the agent read it'; return; }
    button.disabled = true;
    let released = false;
    try {
      const response = await fetch('/api/unveil/security/release/' + encodeURIComponent(row.release_id),
        { method: 'POST', credentials: 'same-origin' });
      released = response.ok;
    } catch (_) { /* shown below */ }
    if (released) refresh();
    else button.textContent = 'Could not release. The result is no longer kept.';
  });
  return button;
}

function renderPanel(panel, report, refresh) {
  panel.replaceChildren();
  const summary = summarize(report);
  panel.appendChild(el('div', 'unveil-shield-panel-title', 'UNVEIL security layer'));
  panel.appendChild(el('div', 'unveil-shield-panel-detail', summary.detail));
  if (!report) return;
  const facts = el('div', 'unveil-shield-facts');
  const watch = report.watch;
  [
    ['Allowed', report.counts.allowed],
    ['Blocked', report.counts.blocked],
    ['Mode', report.mode + ' · ' + report.profile],
    ['Background watch', watch && watch.last_run ? (watch.ok ? 'ok at ' : 'failed at ') + timeOf(watch.last_run) : 'starting'],
  ].forEach(([name, value]) => {
    const row = el('div', 'unveil-shield-fact');
    row.appendChild(el('span', 'unveil-shield-fact-name', name));
    row.appendChild(el('span', 'unveil-shield-fact-value', String(value)));
    facts.appendChild(row);
  });
  panel.appendChild(facts);
  const list = el('div', 'unveil-shield-list');
  if (!report.recent.length) list.appendChild(el('div', 'unveil-shield-empty', 'No agent actions yet.'));
  report.recent.forEach((row) => {
    const blocked = row.decision !== 'ALLOW';
    const item = el('div', 'unveil-shield-item' + (blocked ? ' is-blocked' : ''));
    item.appendChild(el('span', 'unveil-shield-item-dot'));
    item.appendChild(el('span', 'unveil-shield-item-tool', row.tool));
    item.appendChild(el('span', 'unveil-shield-item-time', timeOf(row.at)));
    if (blocked) item.appendChild(el('div', 'unveil-shield-item-reason', row.reason));
    if (row.excerpt) item.appendChild(el('div', 'unveil-shield-item-excerpt', row.excerpt));
    if (row.released) item.appendChild(el('div', 'unveil-shield-item-note', 'Released. Ask the agent to read it again.'));
    else if (row.release_id) item.appendChild(releaseButton(row, refresh));
    list.appendChild(item);
  });
  panel.appendChild(list);
}

function apply(button, panel, report) {
  lastReport = report;
  const summary = summarize(report);
  button.dataset.state = summary.state;
  button.querySelector('.unveil-shield-label').textContent = summary.label;
  button.title = summary.detail;
  const mini = document.getElementById('unveil-shield-mini');
  if (mini) { mini.dataset.state = summary.state; mini.title = summary.label + '. ' + summary.detail; }
  document.documentElement.dataset.unveilShield = summary.state;
  if (panelOpen) renderPanel(panel, report, () => poll(button, panel));
}

async function poll(button, panel) {
  let report = null;
  try {
    const response = await fetch('/api/unveil/security/status', { credentials: 'same-origin', cache: 'no-store' });
    if (response.ok) report = await response.json();
  } catch (_) { /* shown as offline */ }
  apply(button, panel, report);
}

function mount() {
  const header = document.querySelector('.sidebar-header');
  if (!header || document.getElementById('unveil-shield-btn')) return;
  const button = el('button', 'unveil-shield-btn');
  button.id = 'unveil-shield-btn';
  button.type = 'button';
  button.setAttribute('aria-haspopup', 'dialog');
  button.setAttribute('aria-expanded', 'false');
  button.dataset.state = 'unknown';
  button.appendChild(el('span', 'unveil-shield-dot'));
  button.appendChild(el('span', 'unveil-shield-label', 'Shield'));
  const panel = el('div', 'unveil-shield-panel');
  panel.id = 'unveil-shield-panel';
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', 'UNVEIL security layer');
  panel.hidden = true;
  header.appendChild(button);
  document.body.appendChild(panel);
  // On phones the sidebar is closed by default, so the state is also shown
  // as a small dot that stays on screen.
  const mini = el('button', 'unveil-shield-mini');
  mini.id = 'unveil-shield-mini';
  mini.type = 'button';
  mini.setAttribute('aria-label', 'UNVEIL security layer status');
  mini.dataset.state = 'unknown';
  mini.appendChild(el('span', 'unveil-shield-dot'));
  document.body.appendChild(mini);

  const close = () => { panelOpen = false; panel.hidden = true; button.setAttribute('aria-expanded', 'false'); };
  const toggle = (anchor) => (event) => {
    event.stopPropagation();
    panelOpen = !panelOpen;
    panel.hidden = !panelOpen;
    button.setAttribute('aria-expanded', String(panelOpen));
    if (panelOpen) {
      const box = anchor.getBoundingClientRect();
      panel.style.top = Math.round(box.bottom + 8) + 'px';
      panel.style.left = Math.round(Math.max(8, Math.min(box.left, window.innerWidth - 328))) + 'px';
      renderPanel(panel, lastReport, () => poll(button, panel));
      poll(button, panel);
    }
  };
  button.addEventListener('click', toggle(button));
  mini.addEventListener('click', toggle(mini));
  document.addEventListener('click', (event) => { if (panelOpen && !panel.contains(event.target)) close(); });
  document.addEventListener('keydown', (event) => { if (event.key === 'Escape' && panelOpen) close(); });

  poll(button, panel);
  setInterval(() => { if (!document.hidden) poll(button, panel); }, POLL_MS);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(button, panel); });
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
else mount();
