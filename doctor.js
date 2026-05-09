/**
 * doctor — Solid pod diagnostics
 *
 * B.0: Read-only LWS / W3C Controlled Identifiers v1.0 profile-shape check.
 *
 * Fetches a WebID URL with Accept: application/ld+json and runs a series
 * of structural checks against the parsed JSON-LD profile. No mutations,
 * no auth — just a read. The output is a green/yellow/red checklist.
 */

import { runLwsCidChecks } from './lib/lws-cid.js';

const form     = document.getElementById('check-form');
const input    = document.getElementById('webid');
const button   = form.querySelector('button[type="submit"]');
const results  = document.getElementById('results');
const checksEl = document.getElementById('checks');
const rawEl    = document.getElementById('raw-body');

// Allow ?webid=… in the URL to pre-fill (handy for sharing / bookmarks).
const params = new URLSearchParams(window.location.search);
if (params.has('webid')) {
  input.value = params.get('webid');
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = input.value.trim();
  if (!url) return;

  // Reflect the current target in the URL so refreshes / bookmarks survive.
  const newParams = new URLSearchParams({ webid: url });
  history.replaceState(null, '', `${window.location.pathname}?${newParams.toString()}`);

  button.disabled = true;
  button.textContent = 'Running…';
  checksEl.innerHTML = '';
  rawEl.textContent = '';
  results.hidden = false;

  try {
    const checks = await runAll(url);
    renderChecks(checks);
  } catch (err) {
    renderChecks([{
      status: 'fail',
      label: 'Diagnostics crashed',
      detail: String(err?.message || err),
    }]);
  } finally {
    button.disabled = false;
    button.textContent = 'Run diagnostics';
  }
});

async function runAll(webIdUrl) {
  const checks = [];

  // 1. Resolve the document URL — strip the fragment.
  let docUrl;
  try {
    docUrl = new URL(webIdUrl);
    docUrl.hash = '';
  } catch (err) {
    checks.push({ status: 'fail', label: 'WebID is a valid URL', detail: err.message });
    return checks;
  }
  checks.push({ status: 'pass', label: 'WebID is a valid URL', detail: docUrl.toString() });

  // 2. Fetch as JSON-LD. We avoid Accept: text/turtle so the conneg layer
  //    doesn't transform the document — we want to validate the JSON-LD
  //    representation directly.
  let res, body, contentType;
  try {
    res = await fetch(docUrl.toString(), {
      headers: { 'Accept': 'application/ld+json' },
    });
    contentType = (res.headers.get('content-type') || '').toLowerCase();
  } catch (err) {
    checks.push({ status: 'fail', label: 'Profile is reachable', detail: err.message });
    return checks;
  }

  if (!res.ok) {
    checks.push({
      status: 'fail',
      label: 'Profile is reachable',
      detail: `HTTP ${res.status} from ${docUrl}`,
    });
    return checks;
  }
  checks.push({
    status: 'pass',
    label: 'Profile is reachable',
    detail: `${res.status} ${res.statusText}`,
  });

  if (!contentType.includes('json')) {
    checks.push({
      status: 'warn',
      label: 'Content-Type is JSON-LD',
      detail: `Got "${contentType || '(none)'}" — wanted application/ld+json. Server may not honor Accept; we'll try parsing anyway.`,
    });
  } else {
    checks.push({
      status: 'pass',
      label: 'Content-Type is JSON-LD',
      detail: contentType,
    });
  }

  // 3. Parse JSON.
  const text = await res.text();
  rawEl.textContent = text;
  let profile;
  try {
    profile = JSON.parse(text);
  } catch (err) {
    checks.push({
      status: 'fail',
      label: 'Profile parses as JSON',
      detail: err.message,
    });
    return checks;
  }
  checks.push({ status: 'pass', label: 'Profile parses as JSON' });

  // 4. Run LWS-CID structural checks.
  for (const c of runLwsCidChecks(profile, { webIdUrl, docUrl: docUrl.toString() })) {
    checks.push(c);
  }

  return checks;
}

function renderChecks(checks) {
  checksEl.innerHTML = '';
  for (const c of checks) {
    const li = document.createElement('li');
    li.className = `check ${c.status}`;
    const symbols = { pass: '✓', warn: '!', fail: '✗', skip: '·' };
    li.innerHTML = `
      <span class="icon">${symbols[c.status] ?? '?'}</span>
      <div class="body">
        <div class="label"></div>
        ${c.detail ? `<div class="detail"></div>` : ''}
      </div>
    `;
    li.querySelector('.label').textContent = c.label;
    if (c.detail) li.querySelector('.detail').textContent = c.detail;
    checksEl.appendChild(li);
  }
}
