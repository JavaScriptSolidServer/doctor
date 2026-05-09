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
import { buildNostrVerificationMethod } from './lib/multikey.js';

const form     = document.getElementById('check-form');
const input    = document.getElementById('webid');
const button   = form.querySelector('button[type="submit"]');
const results  = document.getElementById('results');
const checksEl = document.getElementById('checks');
const rawEl    = document.getElementById('raw-body');

const addKeySection  = document.getElementById('add-key');
const signerStatus   = document.getElementById('signer-status');
const connectButton  = document.getElementById('connect-signer');
const signerOutput   = document.getElementById('signer-output');
const pubkeyHexEl    = document.getElementById('pubkey-hex');
const pubkeyMbEl     = document.getElementById('pubkey-multibase');
const snippetEl      = document.getElementById('snippet');
const snippetTarget  = document.getElementById('snippet-target');
const copyButton     = document.getElementById('copy-snippet');
const copyStatus     = document.getElementById('copy-status');

let lastWebId = null;
let lastDocUrl = null;

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
    const { checks, profileFetched, webId, docUrl } = await runAll(url);
    renderChecks(checks);
    if (profileFetched && webId) {
      lastWebId = webId;
      lastDocUrl = docUrl;
      revealAddKeySection();
    } else {
      hideAddKeySection();
    }
  } catch (err) {
    renderChecks([{
      status: 'fail',
      label: 'Diagnostics crashed',
      detail: String(err?.message || err),
    }]);
    hideAddKeySection();
  } finally {
    button.disabled = false;
    button.textContent = 'Run diagnostics';
  }
});

async function runAll(webIdUrl) {
  const checks = [];
  const result = { checks, profileFetched: false, docUrl: null, webId: null };

  // 1. Resolve the document URL — strip the fragment.
  let docUrl;
  try {
    docUrl = new URL(webIdUrl);
    docUrl.hash = '';
  } catch (err) {
    checks.push({ status: 'fail', label: 'WebID is a valid URL', detail: err.message });
    return result;
  }
  checks.push({ status: 'pass', label: 'WebID is a valid URL', detail: docUrl.toString() });

  // 2. Fetch as JSON-LD. We avoid Accept: text/turtle so the conneg layer
  //    doesn't transform the document — we want to validate the JSON-LD
  //    representation directly.
  let res, contentType;
  try {
    res = await fetch(docUrl.toString(), {
      headers: { 'Accept': 'application/ld+json' },
    });
    contentType = (res.headers.get('content-type') || '').toLowerCase();
  } catch (err) {
    checks.push({ status: 'fail', label: 'Profile is reachable', detail: err.message });
    return result;
  }

  if (!res.ok) {
    checks.push({
      status: 'fail',
      label: 'Profile is reachable',
      detail: `HTTP ${res.status} from ${docUrl}`,
    });
    return result;
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
    return result;
  }
  checks.push({ status: 'pass', label: 'Profile parses as JSON' });

  // Profile was fetched and parsed — safe to root a snippet against this URL.
  // Take the canonical WebID from the profile's own @id (absolutized
  // against the document URL), but only when its fragmentless form
  // matches the URL we actually fetched — otherwise the snippet's VM
  // id would be rooted at one document while the UI tells the user to
  // patch a different one. Untrusted input, so the URL parse is
  // wrapped: malformed @id falls back to the user-supplied URL.
  const profileId = profile['@id'] || profile.id;
  let canonicalWebId = webIdUrl;
  if (profileId) {
    try {
      const resolved = new URL(profileId, docUrl);
      const resolvedNoHash = new URL(resolved);
      resolvedNoHash.hash = '';
      if (resolvedNoHash.toString() === docUrl.toString()) {
        canonicalWebId = resolved.toString();
      }
    } catch {
      // malformed @id; fall through to user-supplied URL
    }
  }
  result.profileFetched = true;
  result.docUrl = docUrl.toString();
  result.webId = canonicalWebId;

  // 4. Run LWS-CID structural checks.
  for (const c of runLwsCidChecks(profile, { webIdUrl })) {
    checks.push(c);
  }

  return result;
}

// --- B.2: connect Nostr signer & compute Multikey VM -----------------

function revealAddKeySection() {
  addKeySection.hidden = false;
  detectSigner();
}

function hideAddKeySection() {
  addKeySection.hidden = true;
  clearSignerOutput();
  lastWebId = null;
  lastDocUrl = null;
}

function clearSignerOutput() {
  signerOutput.hidden = true;
  pubkeyHexEl.textContent = '';
  pubkeyMbEl.textContent = '';
  snippetEl.textContent = '';
  snippetTarget.textContent = '';
  connectButton.textContent = 'Connect signer';
  copyStatus.textContent = '';
  copyStatus.className = 'copy-status';
}

function detectSigner() {
  if (typeof window.nostr?.getPublicKey === 'function') {
    setSignerStatus('ready', 'NIP-07 signer detected (window.nostr).');
    connectButton.disabled = false;
  } else {
    setSignerStatus('absent',
      'No NIP-07 signer found. Install xlogin or another window.nostr provider, then reload.');
    connectButton.disabled = true;
  }
}

function setSignerStatus(state, text) {
  signerStatus.className = `signer-status ${state}`;
  signerStatus.querySelector('.text').textContent = text;
}

connectButton.addEventListener('click', async () => {
  if (!lastWebId) return;
  connectButton.disabled = true;
  connectButton.textContent = 'Connecting…';
  try {
    const xOnlyHex = await window.nostr.getPublicKey();
    if (!/^[0-9a-f]{64}$/i.test(xOnlyHex)) {
      throw new Error(`Signer returned an unexpected pubkey: ${xOnlyHex}`);
    }
    renderSnippet(xOnlyHex, lastWebId, lastDocUrl);
    signerOutput.hidden = false;
    setSignerStatus('ready', 'Connected. The snippet below is ready to paste into your profile.');
    connectButton.textContent = 'Reconnect signer';
  } catch (err) {
    clearSignerOutput();
    setSignerStatus('error', `Could not read pubkey: ${err.message || err}`);
  } finally {
    connectButton.disabled = false;
  }
});

function renderSnippet(xOnlyHex, webId, docUrl) {
  const vm = buildNostrVerificationMethod({ webId, xOnlyHex });
  pubkeyHexEl.textContent = xOnlyHex;
  pubkeyMbEl.textContent  = vm.publicKeyMultibase;
  // Write target is the document URL (no fragment) — you can't PUT/PATCH
  // a fragment URI. The VM's `controller` keeps the WebID-with-fragment.
  snippetTarget.textContent = docUrl;

  // Show the three additions a CID v1 profile needs together: the
  // verificationMethod itself, plus authentication / assertionMethod
  // arrays referencing it. JSON-LD doesn't have "patch" syntax, so we
  // present it as a partial document the user can merge manually.
  const partial = {
    verificationMethod: [vm],
    authentication: [vm.id],
    assertionMethod: [vm.id],
  };
  snippetEl.textContent = JSON.stringify(partial, null, 2);
}

copyButton.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(snippetEl.textContent);
    copyStatus.className = 'copy-status success';
    copyStatus.textContent = 'Copied.';
  } catch (err) {
    copyStatus.className = 'copy-status error';
    copyStatus.textContent = `Couldn't copy: ${err.message || err}`;
  }
  setTimeout(() => {
    copyStatus.textContent = '';
    copyStatus.className = 'copy-status';
  }, 2500);
});

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
