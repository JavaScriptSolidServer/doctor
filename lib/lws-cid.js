/**
 * LWS / W3C Controlled Identifiers v1.0 profile-shape checks.
 *
 * Returns an array of { status, label, detail? } where status is
 * 'pass' | 'warn' | 'fail' | 'skip'.
 *
 * The checks are deliberately structural — they don't dereference DID
 * documents (Phase B.1 will add that) or attempt cryptographic
 * validation. The goal is to answer: "if an LWS-CID verifier
 * dereferenced this WebID, would it find a usable controlled
 * identifier document?"
 */

const CID_NS = 'https://www.w3.org/ns/cid/v1#';
const CID_TERMS = [
  'controller',
  'verificationMethod',
  'authentication',
  'assertionMethod',
  'publicKeyJwk',
  'publicKeyMultibase',
];

const PROOF_PURPOSES = ['authentication', 'assertionMethod'];

export function runLwsCidChecks(profile, { webIdUrl }) {
  const out = [];

  // --- @id / @context basics ----------------------------------------

  const id = profile['@id'] || profile.id;
  if (!id) {
    out.push({ status: 'fail', label: 'Profile has @id', detail: 'No @id (or id) on the document.' });
  } else {
    out.push({ status: 'pass', label: 'Profile has @id', detail: id });
  }

  // Resolve the WebID's fragment-less form for self-reference checks.
  // Some profiles use "#me" relative; others embed the full URI.
  const requestedNoHash = stripHash(webIdUrl);
  const profileNoHash   = id ? stripHash(absolutize(id, requestedNoHash)) : null;
  if (id && profileNoHash && profileNoHash !== requestedNoHash) {
    out.push({
      status: 'warn',
      label: '@id resolves to the requested document',
      detail: `Requested ${requestedNoHash}, profile says ${profileNoHash}. Some Solid clients accept this; LWS verifiers may not.`,
    });
  } else if (id) {
    out.push({ status: 'pass', label: '@id resolves to the requested document' });
  }

  const ctx = profile['@context'];
  if (!ctx) {
    out.push({ status: 'fail', label: '@context is present' });
    return out; // nothing else makes sense without a context
  }
  out.push({ status: 'pass', label: '@context is present' });

  // CID v1 vocabulary check. The context can be:
  //   - a string (URL imported context)
  //   - an object (inline mapping)
  //   - an array of either
  // We walk all entries and look for CID v1 namespace bindings.
  const cidLoaded = checkCidVocabulary(ctx);
  if (cidLoaded.fullyLoaded) {
    out.push({
      status: 'pass',
      label: '@context declares all six CID v1 terms',
      detail: cidLoaded.method,
    });
  } else if (cidLoaded.partial) {
    out.push({
      status: 'warn',
      label: '@context declares CID v1 partially',
      detail: `Found: ${cidLoaded.found.join(', ') || 'none'}. Missing: ${cidLoaded.missing.join(', ')}.`,
    });
  } else {
    out.push({
      status: 'fail',
      label: '@context declares CID v1 vocabulary',
      detail: 'No CID v1 terms found. LWS-CID verifiers will not be able to resolve this document.',
    });
  }

  // --- self-control: controller === @id -----------------------------

  const controller = profile.controller;
  if (controller === undefined) {
    out.push({
      status: 'fail',
      label: 'Profile declares a controller',
      detail: 'CID v1 requires a controller for verification methods to be usable.',
    });
  } else {
    const ctrl = typeof controller === 'string' ? controller : controller['@id'];
    const ctrlAbs = absolutize(ctrl, requestedNoHash);
    const idAbsolute = absolutize(id, requestedNoHash);
    if (ctrlAbs === idAbsolute) {
      out.push({ status: 'pass', label: 'controller === @id (self-controlled)' });
    } else {
      out.push({
        status: 'warn',
        label: 'controller differs from @id',
        detail: `controller=${ctrlAbs}, @id=${idAbsolute}. Delegated control is allowed by CID v1 but most pods are self-controlled.`,
      });
    }
  }

  // --- verificationMethod -------------------------------------------

  const vms = asArray(profile.verificationMethod);
  if (!profile.verificationMethod) {
    out.push({
      status: 'warn',
      label: 'verificationMethod is populated',
      detail: 'No verificationMethod entries — LWS-CID auth needs at least one to look up by `kid`. Phase B (add-keys app) will populate this.',
    });
  } else if (vms.length === 0) {
    out.push({
      status: 'warn',
      label: 'verificationMethod is populated',
      detail: 'verificationMethod is an empty array.',
    });
  } else {
    out.push({
      status: 'pass',
      label: `verificationMethod has ${vms.length} entr${vms.length === 1 ? 'y' : 'ies'}`,
    });

    // Entry-level checks. VM controllers are compared against the
    // profile's declared `controller` (absolutized), with a fallback
    // to `@id`. Most profiles are self-controlled (controller === @id)
    // so the two are equal; for delegated-control profiles, VMs are
    // expected to be controlled by whoever the profile says controls
    // it, not by the WebID itself.
    const expectedCtrlSource = controller !== undefined
      ? (typeof controller === 'string' ? controller : controller['@id'])
      : id;
    const expectedCtrl = absolutize(expectedCtrlSource, requestedNoHash);
    const seenIds = new Set();
    let allOk = true;
    for (const [i, vm] of vms.entries()) {
      const probs = validateVerificationMethod(vm, requestedNoHash, expectedCtrl);
      if (probs.length === 0) continue;
      allOk = false;
      out.push({
        status: 'fail',
        label: `verificationMethod[${i}] is well-formed`,
        detail: probs.join(' · '),
      });
    }
    if (allOk) {
      out.push({ status: 'pass', label: 'All verificationMethod entries are well-formed' });
    }

    // Uniqueness
    const dupIds = [];
    for (const vm of vms) {
      const vmId = vm.id || vm['@id'];
      if (!vmId) continue;
      if (seenIds.has(vmId)) dupIds.push(vmId);
      else seenIds.add(vmId);
    }
    if (dupIds.length === 0) {
      out.push({ status: 'pass', label: 'verificationMethod ids are unique' });
    } else {
      out.push({
        status: 'fail',
        label: 'verificationMethod ids are unique',
        detail: `Duplicates: ${dupIds.join(', ')}`,
      });
    }
  }

  // --- proof-purpose arrays point at real verificationMethods --------

  const vmIds = new Set(vms.map((vm) => vm.id || vm['@id']).filter(Boolean));
  for (const purpose of PROOF_PURPOSES) {
    const ents = asArray(profile[purpose]);
    if (!profile[purpose]) {
      out.push({
        status: 'skip',
        label: `${purpose} array is present`,
        detail: 'Optional. Phase B will populate when keys are added.',
      });
      continue;
    }
    if (ents.length === 0) {
      out.push({
        status: 'warn',
        label: `${purpose} is populated`,
        detail: 'Empty array.',
      });
      continue;
    }

    // Each entry should be an IRI string referencing a verificationMethod
    // entry by id. Embedded objects are allowed by CID v1 but rare.
    const dangling = [];
    for (const ent of ents) {
      const ref = typeof ent === 'string' ? ent : (ent['@id'] || ent.id);
      if (!ref) {
        dangling.push('(empty)');
        continue;
      }
      if (!vmIds.has(ref)) dangling.push(ref);
    }
    if (dangling.length === 0) {
      out.push({
        status: 'pass',
        label: `All ${purpose} entries point at a verificationMethod`,
        detail: `${ents.length} entr${ents.length === 1 ? 'y' : 'ies'}`,
      });
    } else {
      out.push({
        status: 'fail',
        label: `${purpose} entries are dangling`,
        detail: `Not found in verificationMethod: ${dangling.join(', ')}`,
      });
    }
  }

  // --- alsoKnownAs ---------------------------------------------------

  const akas = asArray(profile.alsoKnownAs);
  if (!profile.alsoKnownAs) {
    out.push({
      status: 'skip',
      label: 'alsoKnownAs declared',
      detail: 'Optional. Used to bind this WebID to one or more DID URIs.',
    });
  } else if (akas.length === 0) {
    out.push({ status: 'warn', label: 'alsoKnownAs is populated', detail: 'Empty array.' });
  } else {
    const bad = akas.filter((a) => {
      const v = typeof a === 'string' ? a : (a['@id'] || a.id);
      return !v || !/^did:[a-z0-9]+:/.test(v);
    });
    if (bad.length === 0) {
      out.push({
        status: 'pass',
        label: 'alsoKnownAs entries look like DIDs',
        detail: akas.map((a) => typeof a === 'string' ? a : a['@id']).join(', '),
      });
    } else {
      out.push({
        status: 'warn',
        label: 'alsoKnownAs entries are not all DIDs',
        detail: `Non-DID entries: ${bad.length}/${akas.length}. Bidirectional DID-doc verification is a Phase B.1 follow-up.`,
      });
    }
  }

  return out;
}

// --- helpers ---------------------------------------------------------

function checkCidVocabulary(ctx) {
  const found = new Set();
  let imported = false;

  walk(ctx);

  function walk(c) {
    if (!c) return;
    if (typeof c === 'string') {
      if (c === 'https://www.w3.org/ns/cid/v1' || c === 'https://www.w3.org/ns/cid/v1#') {
        imported = true;
        // Importing the URL declares all CID terms by reference.
        for (const t of CID_TERMS) found.add(t);
      }
      return;
    }
    if (Array.isArray(c)) {
      for (const e of c) walk(e);
      return;
    }
    if (typeof c === 'object') {
      for (const [k, v] of Object.entries(c)) {
        if (CID_TERMS.includes(k) && expandsToCid(v, c)) {
          found.add(k);
        }
      }
    }
  }

  const missing = CID_TERMS.filter((t) => !found.has(t));
  return {
    fullyLoaded: missing.length === 0,
    partial: found.size > 0 && missing.length > 0,
    found: [...found],
    missing,
    method: imported ? 'imported via https://www.w3.org/ns/cid/v1' : 'declared inline',
  };
}

function expandsToCid(termValue, ctx) {
  const id = typeof termValue === 'string' ? termValue : termValue?.['@id'];
  if (!id) return false;
  // Full IRI form
  if (id.startsWith(CID_NS)) return true;
  // Prefixed form like "cid:controller" — check the cid prefix.
  const colon = id.indexOf(':');
  if (colon > 0) {
    const prefix = id.slice(0, colon);
    const localName = id.slice(colon + 1);
    if (typeof ctx === 'object' && !Array.isArray(ctx)) {
      const expansion = typeof ctx[prefix] === 'string' ? ctx[prefix] : ctx[prefix]?.['@id'];
      if (expansion && expansion.startsWith(CID_NS.replace(/#$/, ''))) {
        // Lazy: any cid: prefix that resolves into the cid/v1 namespace counts.
        return true;
      }
    }
  }
  return false;
}

function validateVerificationMethod(vm, baseUrl, controllerUrl) {
  const probs = [];
  if (typeof vm !== 'object' || vm === null) {
    return ['entry is not an object'];
  }
  const vmId = vm.id || vm['@id'];
  if (!vmId) probs.push('missing id');
  if (!vm.type) probs.push('missing type');
  if (!vm.controller) {
    probs.push('missing controller');
  } else if (controllerUrl) {
    const ctrlAbs = absolutize(typeof vm.controller === 'string' ? vm.controller : vm.controller['@id'], baseUrl);
    if (ctrlAbs !== controllerUrl) {
      probs.push(`controller mismatch: ${ctrlAbs} ≠ ${controllerUrl}`);
    }
  }
  if (!vm.publicKeyJwk && !vm.publicKeyMultibase) {
    probs.push('no publicKeyJwk or publicKeyMultibase');
  }
  return probs;
}

function asArray(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

function stripHash(u) {
  try {
    const url = new URL(u);
    url.hash = '';
    return url.toString();
  } catch {
    return u;
  }
}

function absolutize(u, base) {
  if (!u) return u;
  try {
    return new URL(u, base).toString();
  } catch {
    return u;
  }
}
