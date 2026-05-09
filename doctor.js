/**
 * doctor — Solid pod diagnostics
 *
 * B.0: Read-only LWS / W3C Controlled Identifiers v1.0 profile-shape check.
 *
 * Fetches a WebID URL with Accept: application/ld+json and runs a series
 * of structural checks against the parsed JSON-LD profile. No mutations,
 * no auth — just a read. The output is a green/yellow/red checklist.
 */

import { runLwsCidChecks, normalizeControllers } from './lib/lws-cid.js';
import { buildNostrVerificationMethod } from './lib/multikey.js';
import { buildEs256kVerificationMethod, signLwsCidJwt, validatePrivKey } from './lib/lws-cid-client.js';
import { Session } from 'https://esm.sh/solid-oidc@0.0.8';

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
let lastController = null;
let lastIssuer = null;
let lastVmKid = null;
let memPrivKey = null; // 32-byte secp256k1 privkey, in-memory only

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
  // Hide the add-key UI immediately so a stale snippet from a previous
  // run can't be copied or have its connect button clicked while the
  // new diagnostics are in flight.
  hideAddKeySection();
  hideLwsAuthSection();

  try {
    const { checks, profileFetched, webId, docUrl, controller, issuer } = await runAll(url);
    renderChecks(checks);
    if (profileFetched && webId) {
      lastWebId = webId;
      lastDocUrl = docUrl;
      lastController = controller;
      lastIssuer = issuer;
      revealAddKeySection();
      revealLwsAuthSection();
    } else {
      hideAddKeySection();
      hideLwsAuthSection();
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
  const result = { checks, profileFetched: false, docUrl: null, webId: null, controller: null };

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
  // JSON.parse accepts null, primitives, and arrays — none of which are
  // a usable JSON-LD profile document. Bail out before downstream code
  // tries to read `@id`/`controller` and throws.
  if (profile === null || typeof profile !== 'object' || Array.isArray(profile)) {
    checks.push({
      status: 'fail',
      label: 'Profile parses as JSON',
      detail: `Top-level value is ${profile === null ? 'null' : Array.isArray(profile) ? 'an array' : typeof profile}; expected a JSON object.`,
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
  // Derive the controller IRI from the profile's declared `controller`
  // (handling all four JSON-LD shapes), falling back to the canonical
  // WebID when controller is absent. Generated VMs use this so that on
  // delegated-control profiles the snippet matches the profile's own
  // controller predicate (and passes the validator).
  const declaredCtrls = normalizeControllers(profile.controller, docUrl.toString());
  const controllerIri = declaredCtrls[0] ?? canonicalWebId;

  result.profileFetched = true;
  result.docUrl = docUrl.toString();
  result.webId = canonicalWebId;
  result.controller = controllerIri;
  result.issuer = extractIssuer(profile);

  // 4. Run LWS-CID structural checks.
  for (const c of runLwsCidChecks(profile, { webIdUrl })) {
    checks.push(c);
  }

  return result;
}

// --- B.2: connect Nostr signer & compute Multikey VM -----------------

function revealAddKeySection() {
  addKeySection.hidden = false;
  // The WebID may have changed since the section was last shown; clear
  // any prior pubkey/snippet so the user can't accidentally copy a
  // snippet rooted at the previous WebID.
  clearSignerOutput();
  detectSigner();
}

function hideAddKeySection() {
  addKeySection.hidden = true;
  clearSignerOutput();
  lastWebId = null;
  lastDocUrl = null;
  lastController = null;
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
  // Re-check presence: a NIP-07 provider can be uninstalled or
  // disabled between detection and click. Throwing a raw TypeError
  // from `window.nostr.getPublicKey()` would surface a confusing
  // error.
  if (typeof window.nostr?.getPublicKey !== 'function') {
    setSignerStatus('absent',
      'No NIP-07 signer found. Install xlogin or another window.nostr provider, then reload.');
    connectButton.disabled = true;
    return;
  }
  connectButton.disabled = true;
  connectButton.textContent = 'Connecting…';
  try {
    const xOnlyHex = await window.nostr.getPublicKey();
    if (!/^[0-9a-f]{64}$/i.test(xOnlyHex)) {
      throw new Error(`Signer returned an unexpected pubkey: ${xOnlyHex}`);
    }
    renderSnippet(xOnlyHex, lastWebId, lastDocUrl, lastController);
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

function renderSnippet(xOnlyHex, webId, docUrl, controller) {
  const vm = buildNostrVerificationMethod({ webId, xOnlyHex, controller });
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

// --- B.3: strict LWS-CID auth (Solid-OIDC sign-in + ES256K JWT) ----

const lwsAuthSection  = document.getElementById('lws-auth');
const oidcStatusEl    = document.getElementById('oidc-status');
const oidcSignInBtn   = document.getElementById('oidc-signin');
const oidcSignOutBtn  = document.getElementById('oidc-signout');
const patchSection    = document.getElementById('patch-section');
const privkeyInput    = document.getElementById('privkey');
const patchButton     = document.getElementById('patch-button');
const patchResult     = document.getElementById('patch-result');
const testSection     = document.getElementById('test-section');
const testButton      = document.getElementById('test-button');
const testResult      = document.getElementById('test-result');

const session = new Session({
  onStateChange: (e) => {
    const isActive = e?.detail?.isActive;
    const webId = e?.detail?.webId;
    setOidcStatus(isActive ? 'signed-in' : null,
      isActive ? `Signed in as ${webId}` : 'Not signed in.');
    oidcSignInBtn.hidden = !!isActive;
    oidcSignOutBtn.hidden = !isActive;
    patchSection.hidden = !isActive;
    if (!isActive) {
      // Drop any pasted privkey + cached VM kid the moment the session
      // ends. The UI promises sign-out clears state, and a privkey
      // sitting in a tab that's no longer authenticated is just
      // exposure with no purpose.
      memPrivKey = null;
      lastVmKid = null;
      privkeyInput.value = '';
      testSection.hidden = true;
      patchResult.textContent = '';
      patchResult.className = 'patch-result';
      testResult.textContent = '';
      testResult.className = 'test-result';
    }
  },
});

// Restore any prior session (saved in IndexedDB by solid-oidc) and
// handle the redirect-back from the IdP if we just landed on one.
session.restore().catch(() => { /* no prior session — fine */ });
session.handleRedirectFromLogin().catch((err) => {
  setOidcStatus('error', `Sign-in callback failed: ${err.message || err}`);
});

function setOidcStatus(state, text) {
  oidcStatusEl.className = `oidc-status${state ? ' ' + state : ''}`;
  oidcStatusEl.querySelector('.text').textContent = text;
}

function revealLwsAuthSection() {
  lwsAuthSection.hidden = false;
  // Only enable sign-in if we have an issuer to point at.
  oidcSignInBtn.disabled = !lastIssuer;
  if (!lastIssuer) {
    setOidcStatus('error',
      'Profile declares no oidcIssuer — cannot start a Solid-OIDC sign-in.');
  }
}

function hideLwsAuthSection() {
  lwsAuthSection.hidden = true;
  patchResult.textContent = '';
  patchResult.className = 'patch-result';
  testResult.textContent = '';
  testResult.className = 'test-result';
  testSection.hidden = true;
  memPrivKey = null;
  lastVmKid = null;
}

oidcSignInBtn.addEventListener('click', async () => {
  if (!lastIssuer) return;
  try {
    // Persist current target across the redirect — strip any login
    // params on the way back.
    const returnUrl = `${window.location.pathname}?webid=${encodeURIComponent(lastWebId)}`;
    await session.login(lastIssuer, new URL(returnUrl, window.location.origin).toString());
  } catch (err) {
    setOidcStatus('error', `Could not start sign-in: ${err.message || err}`);
  }
});

oidcSignOutBtn.addEventListener('click', async () => {
  try {
    await session.logout();
  } catch (err) {
    setOidcStatus('error', `Sign-out failed: ${err.message || err}`);
  }
});

patchButton.addEventListener('click', async () => {
  patchResult.className = 'patch-result info';
  patchResult.textContent = 'Working…';
  try {
    if (!session.isActive) throw new Error('not signed in');
    if (!session.webId) throw new Error('signed-in session has no webId');
    if (session.webId !== lastWebId) {
      throw new Error(
        `signed-in WebID (${session.webId}) doesn't match the diagnosed one (${lastWebId})`);
    }
    const priv = validatePrivKey(privkeyInput.value);
    memPrivKey = priv;

    const { vm, kid } = buildEs256kVerificationMethod({
      privKey: priv,
      webId: lastWebId,
      // For delegated-control profiles use the diagnosed controller,
      // not the WebID — otherwise the VM's controller will mismatch
      // the profile's outer controller predicate and verifiers reject.
      controller: lastController ?? lastWebId,
    });
    lastVmKid = kid;

    // Read-modify-write: GET via authFetch (so we see the
    // authoritative current state, including any private triples),
    // merge our VM into verificationMethod / authentication, PUT back.
    const getRes = await session.authFetch(lastDocUrl, {
      headers: { Accept: 'application/ld+json' },
    });
    if (!getRes.ok) throw new Error(`GET profile: HTTP ${getRes.status}`);
    const etag = getRes.headers.get('etag');
    const current = await getRes.json();

    const merged = mergeVerificationMethod(current, vm);

    const putHeaders = { 'Content-Type': 'application/ld+json' };
    // Use If-Match to defeat lost-update on concurrent edits. JSS
    // returns ETags on profile resources; servers without ETag support
    // fall through with no header.
    if (etag) putHeaders['If-Match'] = etag;

    const putRes = await session.authFetch(lastDocUrl, {
      method: 'PUT',
      headers: putHeaders,
      body: JSON.stringify(merged, null, 2),
    });
    if (putRes.status === 412 || putRes.status === 409) {
      throw new Error(
        `profile changed since GET (HTTP ${putRes.status}). Re-run diagnostics and try again.`,
      );
    }
    if (!putRes.ok) throw new Error(`PUT profile: HTTP ${putRes.status}`);

    patchResult.className = 'patch-result ok';
    patchResult.textContent =
      `Added ${kid} to verificationMethod and authentication.\n` +
      `Profile updated. You can now test LWS-CID auth below.`;
    testSection.hidden = false;
    privkeyInput.value = '';
  } catch (err) {
    patchResult.className = 'patch-result error';
    patchResult.textContent = `Failed: ${err.message || err}`;
    memPrivKey = null;
  }
});

testButton.addEventListener('click', async () => {
  testResult.className = 'test-result info';
  testResult.textContent = 'Signing JWT and calling pod…';
  try {
    if (!memPrivKey) throw new Error('no privkey in memory — re-run the PATCH step');
    if (!lastVmKid)  throw new Error('no VM id captured — re-run the PATCH step');

    const audience = new URL(lastDocUrl).origin;
    const jwt = await signLwsCidJwt({
      privKey: memPrivKey,
      kid: lastVmKid,
      webId: lastWebId,
      audience,
    });

    // Hit the WebID's own resource. The doctor's plain `fetch` (NOT
    // session.authFetch) so the only auth on the wire is the JWT we
    // just minted — that's what we want to test.
    const res = await fetch(lastDocUrl, {
      headers: {
        Accept: 'application/ld+json',
        Authorization: `Bearer ${jwt}`,
      },
    });

    const wacAllow = res.headers.get('wac-allow') || '(none)';
    const summary = [
      `Status: ${res.status} ${res.statusText}`,
      `WAC-Allow: ${wacAllow}`,
      '',
      `JWT (truncated): ${jwt.slice(0, 80)}…`,
    ].join('\n');

    if (res.ok) {
      testResult.className = 'test-result ok';
      testResult.textContent = `LWS10-CID auth round-trip OK!\n\n${summary}`;
    } else {
      // Even on 4xx the response can carry useful diagnostics in the body.
      const body = await res.text().catch(() => '');
      testResult.className = 'test-result error';
      testResult.textContent =
        `Pod rejected the JWT.\n\n${summary}\n\nResponse body:\n${body.slice(0, 500)}`;
    }
  } catch (err) {
    testResult.className = 'test-result error';
    testResult.textContent = `Failed: ${err.message || err}`;
  }
});

/**
 * Merge a verificationMethod entry into a profile.
 *
 * Idempotent on re-runs of the SAME key: replaces the existing entry
 * (same id, same publicKeyJwk) so we don't grow duplicates.
 *
 * Refuses to clobber a different key sitting at the same fragment —
 * an existing VM with the same id but DIFFERENT publicKeyJwk throws.
 * The user can pick another fragment if they want to keep both keys
 * (key rotation should happen at a fresh fragment, e.g. `lws-key-2`,
 * with the old one removed from `authentication` once rotation is
 * complete).
 *
 * Handles string-IRI verificationMethod entries (which JSON-LD
 * permits) — finds them by IRI equality so the entry isn't duplicated.
 */
function mergeVerificationMethod(profile, vm) {
  const out = { ...profile };
  const vms = Array.isArray(out.verificationMethod) ? [...out.verificationMethod]
            : out.verificationMethod ? [out.verificationMethod]
            : [];
  const idx = vms.findIndex((v) => entryMatchesId(v, vm.id));
  if (idx >= 0) {
    const existing = vms[idx];
    // String-IRI entries don't carry inline material — replacing
    // them with our embedded VM is fine. For embedded entries with a
    // different publicKeyJwk, refuse to overwrite.
    if (typeof existing === 'object' && existing !== null) {
      const existingJwk = existing.publicKeyJwk;
      if (existingJwk && !sameJwk(existingJwk, vm.publicKeyJwk)) {
        throw new Error(
          `verificationMethod ${vm.id} already exists with a different public key — ` +
          `pick a new fragment (e.g. lws-key-2) or remove the existing entry first`,
        );
      }
    }
    vms[idx] = vm;
  } else {
    vms.push(vm);
  }
  out.verificationMethod = vms;

  const auth = Array.isArray(out.authentication) ? [...out.authentication]
             : out.authentication ? [out.authentication]
             : [];
  if (!auth.some((a) => (typeof a === 'string' ? a : a?.['@id'] || a?.id) === vm.id)) {
    auth.push(vm.id);
  }
  out.authentication = auth;
  return out;
}

function entryMatchesId(entry, id) {
  if (typeof entry === 'string') return entry === id;
  if (entry && typeof entry === 'object') return (entry.id || entry['@id']) === id;
  return false;
}

function sameJwk(a, b) {
  // Compare the public-key material, not auxiliary fields like `kid`,
  // `alg`, or `use`. Two VMs are "the same key" iff x and y match.
  return a && b
    && a.kty === b.kty
    && a.crv === b.crv
    && a.x === b.x
    && a.y === b.y;
}

function extractIssuer(profile) {
  // JSS emits oidcIssuer in compact form via the profile @context. Some
  // clients use the full predicate URI or the prefixed form; support all.
  const raw = profile?.oidcIssuer
           ?? profile?.['solid:oidcIssuer']
           ?? profile?.['http://www.w3.org/ns/solid/terms#oidcIssuer'];
  if (!raw) return null;
  if (typeof raw === 'string') return raw;
  if (typeof raw === 'object') return raw['@id'] || raw.id || null;
  return null;
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
