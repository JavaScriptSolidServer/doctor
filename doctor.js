/**
 * doctor — connect a Nostr key to a Solid pod.
 *
 * The one task on the page: sign in to the pod with Solid-OIDC, take the public key
 * from the NIP-07 signer, write it into the WebID profile as a Multikey
 * verificationMethod referenced from `authentication`, then prove it with a NIP-98
 * request. JSS then treats that key as the pod owner (src/auth/nostr.js), so apps
 * signing with it need no further sign-in.
 *
 * Under "Advanced": the LWS / CID v1 profile checks and the ES256K JWT test client,
 * unchanged from before, loaded only when used.
 */
import { Session } from './vendor/solid-oidc.js';
import { buildNostrVerificationMethod, multikeyToNostrPubkey } from './lib/multikey.js';
import { runLwsCidChecks, normalizeControllers } from './lib/lws-cid.js';

const $ = (id) => document.getElementById(id);
const el = {
  form: $('link-form'), pod: $('pod'), go: $('go'), signer: $('signer'), steps: $('steps'),
  done: $('done'), doneDid: $('done-did'), doneWebId: $('done-webid'), again: $('again'),
  check: $('check'), checks: $('checks'), raw: $('raw'), rawBody: $('raw-body'),
  privkey: $('privkey'), jwtAdd: $('jwt-add'), jwtTest: $('jwt-test'), jwtOut: $('jwt-out'),
  sessionWebId: $('session-webid'), signout: $('signout'),
};

const ICONS = { pass: '✓', warn: '!', fail: '✗', busy: '…', skip: '·' };

// ---------- Solid-OIDC session (one per page) ----------

const session = new Session({
  onStateChange: (e) => {
    const active = !!e?.detail?.isActive;
    el.sessionWebId.textContent = active ? e.detail.webId : 'nobody';
    el.signout.hidden = !active;
  },
});
await session.restore().catch(() => {});
const resumed = await session.handleRedirectFromLogin().then(() => true, (err) => {
  step('fail', 'Signing in to the pod', String(err.message || err));
  return false;
});

// ---------- Inputs ----------

const params = new URLSearchParams(location.search);
el.pod.value = params.get('webid') || params.get('pod') || sessionStorage.getItem('doctor:pod') || '';

// Extensions inject window.nostr a moment after the page runs; give them two seconds.
async function signer(timeoutMs = 2000) {
  const until = Date.now() + timeoutMs;
  while (typeof window.nostr?.getPublicKey !== 'function') {
    if (Date.now() > until) return null;
    await new Promise((r) => setTimeout(r, 100));
  }
  return window.nostr;
}
const signerFound = !!(await signer());
el.signer.className = `signer ${signerFound ? 'ok' : 'missing'}`;
el.signer.querySelector('.text').innerHTML = signerFound
  ? 'Nostr signer found (NIP-07). It will ask you to share your public key and to sign one request.'
  : 'No Nostr signer in this browser. Install <a href="https://github.com/JavaScriptSolidServer/podkey" target="_blank" rel="noopener">podkey</a> (or any NIP-07 extension), then reload.';
el.go.disabled = !signerFound;

el.form.addEventListener('submit', (e) => {
  e.preventDefault();
  run();
});
el.again.addEventListener('click', () => run());
el.signout.addEventListener('click', () => session.logout().catch(() => {}));
// Back from the identity provider: carry on where we left off.
if (resumed && session.isActive && sessionStorage.getItem('doctor:pending') && el.pod.value) run();

// ---------- The task ----------


function step(status, label, detail) {
  el.steps.hidden = false;
  const li = document.createElement('li');
  li.innerHTML = '<span class="icon"></span><div class="body"><div class="label"></div><div class="detail"></div></div>';
  li.querySelector('.label').textContent = label;
  el.steps.appendChild(li);
  const set = (newStatus, newDetail) => {
    li.className = `step ${newStatus}`;
    li.querySelector('.icon').textContent = ICONS[newStatus] ?? '?';
    const d = li.querySelector('.detail');
    d.textContent = newDetail ?? '';
    d.hidden = !newDetail;
  };
  set(status, detail);
  return set;
}

let profileCache = null; // the last profile fetched: { webId, docUrl, profile, raw, issuer, controller }

async function run() {
  const input = el.pod.value.trim();
  if (!input) return;
  sessionStorage.setItem('doctor:pod', input);
  history.replaceState(null, '', `${location.pathname}?webid=${encodeURIComponent(input)}`);
  el.steps.innerHTML = '';
  el.done.hidden = true;
  el.go.disabled = true;
  try {
    // 1. The profile.
    const finding = step('busy', 'Finding your profile');
    let found;
    try {
      found = await findProfile(input);
    } catch (err) {
      return finding('fail', err.message);
    }
    profileCache = found;
    finding('pass', found.webId);

    // 2. The key.
    const nostr = await signer();
    if (!nostr) return step('fail', 'Reading your Nostr key', 'No NIP-07 signer in this browser.');
    const pubkey = String(await nostr.getPublicKey()).toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(pubkey)) return step('fail', 'Reading your Nostr key', `The signer returned something that is not a key: ${pubkey}`);
    step('pass', 'Reading your Nostr key', `did:nostr:${pubkey}`);

    // 3. Already in the (public) profile? Then nothing needs writing and no sign-in is needed.
    const known = linkedAs(found.profile, found.docUrl, pubkey);
    if (known) {
      step('pass', 'Adding the key to your profile', `Already there as ${known}`);
      await prove(found, pubkey);
      return;
    }

    // 4. Signed in to that pod?
    if (!session.isActive || session.webId !== found.webId) {
      if (!found.issuer) return step('fail', 'Signing in to the pod', 'This profile names no sign-in service (solid:oidcIssuer), so doctor cannot write to it. Ask the pod provider, or add the key to the profile by hand.');
      step('busy', 'Signing in to the pod', `Going to ${found.issuer} and coming back here.`);
      sessionStorage.setItem('doctor:pending', '1');
      await session.login(found.issuer, `${location.origin}${location.pathname}?webid=${encodeURIComponent(input)}`);
      return; // the page navigates away
    }
    sessionStorage.removeItem('doctor:pending');
    step('pass', 'Signed in to the pod', `as ${session.webId}`);

    // 5. Write it into the profile (idempotent: an existing method with the same key is kept).
    const writing = step('busy', 'Adding the key to your profile');
    let outcome;
    try {
      outcome = await addKeyToProfile(found, pubkey);
    } catch (err) {
      return writing('fail', err.message);
    }
    writing('pass', outcome.existing ? `Already there as ${outcome.vmId}` : `Added as ${outcome.vmId}`);
    await prove(found, pubkey);
  } finally {
    el.go.disabled = !signerFound;
  }
}

// The last step: a NIP-98-signed request to the pod must come back as the owner.
async function prove(found, pubkey) {
  const proving = step('busy', 'Checking the pod recognises the key');
  try {
    const allow = await proveWithNip98(found.docUrl);
    if (/\b(write|control)\b/.test(allow.user)) proving('pass', `A request signed with this key is answered as you (WAC-Allow user="${allow.user}").`);
    else proving('warn', `The pod answered, but as a stranger (WAC-Allow user="${allow.user || 'none'}"). Some pods cache profiles briefly; try "Check again" in a minute.`);
  } catch (err) {
    proving('warn', `Could not verify: ${err.message}. The key is in your profile; a pod that understands NIP-98 will accept it.`);
  }
  el.doneDid.textContent = `did:nostr:${pubkey}`;
  el.doneWebId.textContent = found.webId;
  el.done.hidden = false;
}

// The id of the verificationMethod that already holds this key and is usable for
// authentication, or null.
function linkedAs(profile, docUrl, pubkey) {
  const auth = asList(profile.authentication).map((a) => absolute(idOf(a), docUrl));
  for (const v of asList(profile.verificationMethod)) {
    const decoded = typeof v === 'object' && v?.publicKeyMultibase ? multikeyToNostrPubkey(v.publicKeyMultibase) : null;
    if (decoded?.xOnlyHex !== pubkey) continue;
    const id = absolute(idOf(v), docUrl);
    if (auth.includes(id)) return id;
  }
  return null;
}

// The WebID profile behind a WebID or a pod address. Pods put the profile at a few
// conventional places; a WebID is used as given.
async function findProfile(input) {
  let url;
  try {
    url = new URL(input);
  } catch {
    throw new Error('That is not a web address.');
  }
  const root = url.href.replace(/\/?$/, '/');
  const candidates = url.hash || /profile\/card/.test(url.pathname)
    ? [url.href]
    : [`${root}profile/card#me`, `${root}profile/card.jsonld#me`, `${url.origin}/profile/card#me`, `${url.origin}/profile/card.jsonld#me`, `${url.origin}/#me`];
  let lastError = 'No profile found at that address.';
  for (const webId of candidates) {
    const docUrl = webId.split('#')[0];
    let res;
    try {
      res = await fetch(docUrl, { headers: { Accept: 'application/ld+json' }, cache: 'no-store' });
    } catch (err) {
      lastError = `${docUrl}: ${err.message}`;
      continue;
    }
    if (!res.ok) {
      lastError = `${docUrl}: HTTP ${res.status}`;
      continue;
    }
    const text = await res.text();
    let profile;
    try {
      profile = JSON.parse(text);
    } catch {
      lastError = `${docUrl} is not JSON-LD (the pod must serve the profile as application/ld+json).`;
      continue;
    }
    if (!profile || typeof profile !== 'object' || Array.isArray(profile)) continue;
    // Prefer the profile's own @id when it lives in this document.
    let resolved = webId;
    const own = profile['@id'] ?? profile.id;
    if (typeof own === 'string') {
      try {
        const abs = new URL(own, docUrl);
        if (abs.href.split('#')[0] === docUrl) resolved = abs.href;
      } catch {}
    }
    const controller = normalizeControllers(profile.controller, docUrl)[0] ?? resolved;
    return { webId: resolved, docUrl, profile, raw: text, issuer: issuerOf(profile), controller };
  }
  throw new Error(lastError);
}

function issuerOf(profile) {
  const raw = profile.oidcIssuer ?? profile['solid:oidcIssuer'] ?? profile['http://www.w3.org/ns/solid/terms#oidcIssuer'];
  for (const v of Array.isArray(raw) ? raw : [raw]) {
    if (typeof v === 'string') return v;
    const id = v?.['@id'] ?? v?.id;
    if (typeof id === 'string') return id;
  }
  return null;
}

// Hoisted: run() may start while the module is still evaluating (resuming after the redirect).
function absolute(u, base) { try { return new URL(u, base).href; } catch { return u; } }
function idOf(entry) { return typeof entry === 'string' ? entry : entry?.id ?? entry?.['@id']; }
function asList(v) { return Array.isArray(v) ? v : v ? [v] : []; }

// Read the live profile with the session: { current, etag }.
async function readLive(found) {
  const res = await session.authFetch(found.docUrl, { headers: { Accept: 'application/ld+json' } });
  if (!res.ok) throw new Error(`Reading the profile failed: HTTP ${res.status}`);
  return { current: JSON.parse(await res.text()), etag: res.headers.get('etag') };
}

// Merge a verificationMethod plus its `authentication` reference into the live profile
// and PUT it back (If-Match when the pod gives an ETag). Shared by the Nostr key and the
// advanced JWK path.
async function writeMethod(found, vm) {
  const { current, etag } = await readLive(found);
  const vms = [...asList(current.verificationMethod)];
  const at = vms.findIndex((v) => absolute(idOf(v), found.docUrl) === vm.id);
  if (at >= 0) vms[at] = vm;
  else vms.push(vm);
  const auth = [...asList(current.authentication)];
  if (!auth.some((a) => absolute(idOf(a), found.docUrl) === vm.id)) auth.push(vm.id);
  const put = await session.authFetch(found.docUrl, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/ld+json', ...(etag ? { 'If-Match': etag } : {}) },
    body: JSON.stringify({ ...current, verificationMethod: vms, authentication: auth }, null, 2),
  });
  if (put.status === 412 || put.status === 409) throw new Error('The profile changed while doctor was working. Try again.');
  if (put.status === 401 || put.status === 403) throw new Error('The pod did not let this session write the profile. Are you signed in as its owner?');
  if (!put.ok) throw new Error(`Writing the profile failed: HTTP ${put.status}`);
}

// Reuse the method that already holds this key; otherwise take the first free #nostr-key-N.
async function addKeyToProfile(found, pubkey) {
  const { current } = await readLive(found);
  const vms = asList(current.verificationMethod);
  const linked = linkedAs(current, found.docUrl, pubkey);
  if (linked) return { vmId: linked, existing: true };
  for (const v of vms) {
    const decoded = typeof v === 'object' && v?.publicKeyMultibase ? multikeyToNostrPubkey(v.publicKeyMultibase) : null;
    if (decoded?.xOnlyHex !== pubkey) continue;
    const vmId = absolute(idOf(v), found.docUrl);
    await writeMethod(found, { ...v, id: vmId }); // known key, not yet usable for authentication
    return { vmId, existing: false };
  }
  const taken = new Set(vms.map((v) => absolute(idOf(v), found.docUrl)));
  let n = 1;
  while (taken.has(`${found.docUrl}#nostr-key-${n}`)) n++;
  const vm = buildNostrVerificationMethod({ webId: found.webId, xOnlyHex: pubkey, controller: found.controller, fragment: `nostr-key-${n}` });
  await writeMethod(found, vm);
  return { vmId: vm.id, existing: false };
}

// A HEAD of the profile document with a NIP-98 header; WAC-Allow says who the pod thinks we are.
async function proveWithNip98(url) {
  const event = await window.nostr.signEvent({
    kind: 27235,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['u', url], ['method', 'HEAD']],
    content: '',
  });
  const token = btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(event))));
  const res = await fetch(url, { method: 'HEAD', headers: { Authorization: `Nostr ${token}` }, cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const header = res.headers.get('WAC-Allow') ?? '';
  return { user: header.match(/user="([^"]*)"/)?.[1] ?? '', public: header.match(/public="([^"]*)"/)?.[1] ?? '' };
}

// ---------- Advanced: profile checks ----------

el.check.addEventListener('click', async () => {
  el.checks.innerHTML = '';
  el.checks.hidden = false;
  el.raw.hidden = true;
  let found;
  try {
    found = await findProfile(el.pod.value.trim());
  } catch (err) {
    return renderChecks([{ status: 'fail', label: 'Profile is reachable', detail: err.message }]);
  }
  profileCache = found;
  el.rawBody.textContent = found.raw;
  el.raw.hidden = false;
  renderChecks([{ status: 'pass', label: 'Profile is reachable', detail: found.docUrl }, ...runLwsCidChecks(found.profile, { webIdUrl: found.webId })]);
});

function renderChecks(checks) {
  for (const c of checks) {
    const li = document.createElement('li');
    li.className = `step ${c.status}`;
    li.innerHTML = '<span class="icon"></span><div class="body"><div class="label"></div><div class="detail"></div></div>';
    li.querySelector('.icon').textContent = ICONS[c.status] ?? '?';
    li.querySelector('.label').textContent = c.label;
    li.querySelector('.detail').textContent = c.detail ?? '';
    li.querySelector('.detail').hidden = !c.detail;
    el.checks.appendChild(li);
  }
}

// ---------- Advanced: strict LWS10-CID (ES256K JWT), loaded on use ----------

let memPrivKey = null;
let jwtKid = null;
const say = (cls, text) => {
  el.jwtOut.hidden = false;
  el.jwtOut.className = cls;
  el.jwtOut.textContent = text;
};

el.jwtAdd.addEventListener('click', async () => {
  try {
    if (!session.isActive) throw new Error('Sign in first (connect your key above, or press "Check again").');
    const found = profileCache?.webId === session.webId ? profileCache : await findProfile(session.webId);
    const lws = await import('./lib/lws-cid-client.js');
    memPrivKey = lws.validatePrivKey(el.privkey.value.trim());
    el.privkey.value = '';
    // Reuse the slot holding the same key; otherwise the first free lws-key-N.
    const { current } = await readLive(found);
    const vms = asList(current.verificationMethod);
    const probe = lws.buildEs256kVerificationMethod({ privKey: memPrivKey, webId: found.webId, controller: found.controller, fragment: 'probe' }).jwk;
    let n = 1;
    for (;;) {
      const existing = vms.find((v) => absolute(idOf(v), found.docUrl) === `${found.docUrl}#lws-key-${n}`);
      if (!existing || (existing.publicKeyJwk?.x === probe.x && existing.publicKeyJwk?.y === probe.y)) break;
      n++;
    }
    const { vm, kid } = lws.buildEs256kVerificationMethod({ privKey: memPrivKey, webId: found.webId, controller: found.controller, fragment: `lws-key-${n}` });
    await writeMethod(found, vm);
    jwtKid = kid;
    say('ok', `Added ${kid} to verificationMethod and authentication.`);
  } catch (err) {
    memPrivKey?.fill?.(0);
    memPrivKey = null;
    jwtKid = null;
    say('error', `Failed: ${err.message || err}`);
  }
});

el.jwtTest.addEventListener('click', async () => {
  try {
    if (!memPrivKey || !jwtKid) throw new Error('Add the JWK method first.');
    const lws = await import('./lib/lws-cid-client.js');
    const docUrl = session.webId.split('#')[0];
    const jwt = await lws.signLwsCidJwt({ privKey: memPrivKey, kid: jwtKid, webId: session.webId, audience: new URL(docUrl).origin });
    const res = await fetch(docUrl, { headers: { Accept: 'application/ld+json', Authorization: `Bearer ${jwt}` }, cache: 'no-store' });
    const body = res.ok ? '' : `\n\n${(await res.text().catch(() => '')).slice(0, 500)}`;
    say(res.ok ? 'ok' : 'error', `${res.ok ? 'LWS10-CID auth round-trip OK.' : 'The pod rejected the JWT.'}\nStatus: ${res.status}\nWAC-Allow: ${res.headers.get('wac-allow') ?? '(none)'}\nJWT: ${jwt.slice(0, 80)}…${body}`);
  } catch (err) {
    say('error', `Failed: ${err.message || err}`);
  }
});
