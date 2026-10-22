/**
 * Pure helpers for the verification methods in a WebID profile document (JSON-LD as
 * Solid pods serve it): find the method that holds a Nostr key, merge one in, take one
 * out. No network, no DOM; see test/profile-keys.test.js.
 *
 * Entries in `verificationMethod`, `authentication` and `assertionMethod` may be
 * objects or bare IRIs, absolute or relative to the document; every comparison
 * resolves them against `docUrl` first.
 */
import { multikeyToNostrPubkey } from './multikey.js';

export function absolute(u, base) {
  try { return new URL(u, base).href; } catch { return u; }
}

export function idOf(entry) {
  return typeof entry === 'string' ? entry : entry?.id ?? entry?.['@id'];
}

export function asList(v) {
  return Array.isArray(v) ? v : v === undefined || v === null ? [] : [v];
}

const PURPOSES = ['authentication', 'assertionMethod'];

/** Every Multikey method that encodes a Nostr key: [{ id, pubkey, authenticates }]. */
export function nostrMethods(profile, docUrl) {
  const auth = new Set(asList(profile.authentication).map((a) => absolute(idOf(a), docUrl)));
  const out = [];
  for (const v of asList(profile.verificationMethod)) {
    if (!v || typeof v !== 'object' || typeof v.publicKeyMultibase !== 'string') continue;
    const decoded = multikeyToNostrPubkey(v.publicKeyMultibase);
    if (!decoded) continue;
    const id = absolute(idOf(v), docUrl);
    out.push({ id, pubkey: decoded.xOnlyHex, authenticates: auth.has(id) });
  }
  return out;
}

/** The id of the method holding `pubkey` that is usable for authentication, or null. */
export function linkedAs(profile, docUrl, pubkey) {
  return nostrMethods(profile, docUrl).find((m) => m.pubkey === pubkey && m.authenticates)?.id ?? null;
}

/** The id of any method holding `pubkey`, authentication reference or not, or null. */
export function methodFor(profile, docUrl, pubkey) {
  return nostrMethods(profile, docUrl).find((m) => m.pubkey === pubkey)?.id ?? null;
}

/** `${docUrl}#${prefix}-${n}` for the first n whose fragment no method uses yet. */
export function freeFragment(profile, docUrl, prefix) {
  const taken = new Set(asList(profile.verificationMethod).map((v) => absolute(idOf(v), docUrl)));
  let n = 1;
  while (taken.has(`${docUrl}#${prefix}-${n}`)) n++;
  return `${docUrl}#${prefix}-${n}`;
}

/**
 * A copy of the profile with `vm` in verificationMethod (replacing an entry with the
 * same id) and its id listed under authentication. Everything else is left as it is.
 */
export function mergeMethod(profile, docUrl, vm) {
  const vms = [...asList(profile.verificationMethod)];
  const at = vms.findIndex((v) => absolute(idOf(v), docUrl) === vm.id);
  if (at >= 0) vms[at] = vm;
  else vms.push(vm);
  const auth = [...asList(profile.authentication)];
  if (!auth.some((a) => absolute(idOf(a), docUrl) === vm.id)) auth.push(vm.id);
  return { ...profile, verificationMethod: vms, authentication: auth };
}

/** A copy of the profile without the method `vmId` and without any reference to it. */
export function removeMethod(profile, docUrl, vmId) {
  const target = absolute(vmId, docUrl);
  const out = { ...profile };
  const keep = (list) => list.filter((e) => absolute(idOf(e), docUrl) !== target);
  if (profile.verificationMethod !== undefined) out.verificationMethod = keep(asList(profile.verificationMethod));
  for (const purpose of PURPOSES) if (profile[purpose] !== undefined) out[purpose] = keep(asList(profile[purpose]));
  return out;
}
