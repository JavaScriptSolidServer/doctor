import test from 'node:test';
import assert from 'node:assert/strict';
import { freeFragment, linkedAs, mergeMethod, methodFor, nostrMethods, removeMethod } from '../lib/profile-keys.js';
import { buildNostrVerificationMethod, nostrPubkeyToMultikey } from '../lib/multikey.js';

const doc = 'https://pod.example/alice/profile/card.jsonld';
const webId = `${doc}#me`;
const keyA = 'a'.repeat(64);
const keyB = 'b'.repeat(64);

const profile = () => ({
  '@context': { cid: 'https://www.w3.org/ns/cid/v1#' },
  '@id': '#me',
  name: 'Alice',
  controller: '#me',
  verificationMethod: [
    { id: '#nostr-key-1', type: 'Multikey', controller: webId, publicKeyMultibase: nostrPubkeyToMultikey(keyA) },
    { id: `${doc}#lws-key-1`, type: 'JsonWebKey', controller: webId, publicKeyJwk: { kty: 'EC', crv: 'secp256k1', x: 'x', y: 'y' } },
  ],
  authentication: ['#nostr-key-1'],
  assertionMethod: [{ '@id': `${doc}#nostr-key-1` }],
});

test('finds Nostr methods whether ids are relative, absolute, strings or objects', () => {
  assert.deepEqual(nostrMethods(profile(), doc), [{ id: `${doc}#nostr-key-1`, pubkey: keyA, authenticates: true }]);
  assert.equal(linkedAs(profile(), doc, keyA), `${doc}#nostr-key-1`);
  assert.equal(linkedAs(profile(), doc, keyB), null);
  const unlinked = { ...profile(), authentication: [] };
  assert.equal(linkedAs(unlinked, doc, keyA), null, 'a method not listed under authentication does not count');
  assert.equal(methodFor(unlinked, doc, keyA), `${doc}#nostr-key-1`);
  assert.deepEqual(nostrMethods({}, doc), []);
  assert.deepEqual(nostrMethods({ verificationMethod: '#x', authentication: '#x' }, doc), []);
});

test('a free fragment skips the ones in use, under any spelling', () => {
  assert.equal(freeFragment(profile(), doc, 'nostr-key'), `${doc}#nostr-key-2`);
  assert.equal(freeFragment({}, doc, 'nostr-key'), `${doc}#nostr-key-1`);
  assert.equal(freeFragment({ verificationMethod: [{ id: `${doc}#nostr-key-1` }, { id: '#nostr-key-2' }, '#nostr-key-3'] }, doc, 'nostr-key'), `${doc}#nostr-key-4`);
});

test('merging adds a method and its authentication reference once, and keeps the rest', () => {
  const vm = buildNostrVerificationMethod({ webId, xOnlyHex: keyB, controller: webId, fragment: 'nostr-key-2' });
  const merged = mergeMethod(profile(), doc, vm);
  assert.equal(merged.verificationMethod.length, 3);
  assert.deepEqual(merged.authentication, ['#nostr-key-1', `${doc}#nostr-key-2`]);
  assert.equal(merged.name, 'Alice');
  assert.deepEqual(merged.assertionMethod, profile().assertionMethod, 'untouched');
  // Running it again changes nothing.
  const again = mergeMethod(merged, doc, vm);
  assert.deepEqual(again, merged);
  // Replacing an existing id keeps the list length.
  const replaced = mergeMethod(profile(), doc, { ...vm, id: `${doc}#nostr-key-1` });
  assert.equal(replaced.verificationMethod.length, 2);
  assert.equal(replaced.verificationMethod[0].publicKeyMultibase, vm.publicKeyMultibase);
  assert.deepEqual(replaced.authentication, ['#nostr-key-1'], 'the relative reference already covered it');
});

test('a profile with no methods yet gets arrays', () => {
  const vm = buildNostrVerificationMethod({ webId, xOnlyHex: keyA, controller: webId });
  const merged = mergeMethod({ '@id': '#me' }, doc, vm);
  assert.deepEqual(merged.verificationMethod, [vm]);
  assert.deepEqual(merged.authentication, [vm.id]);
});

test('removing a method drops it and every reference, nothing else', () => {
  const out = removeMethod(profile(), doc, '#nostr-key-1');
  assert.deepEqual(out.verificationMethod.map((v) => v.id), [`${doc}#lws-key-1`]);
  assert.deepEqual(out.authentication, []);
  assert.deepEqual(out.assertionMethod, []);
  assert.equal(out.name, 'Alice');
  assert.equal(linkedAs(out, doc, keyA), null);
  // Absent lists stay absent; a single non-array value is handled.
  const single = removeMethod({ verificationMethod: { id: '#k' }, authentication: '#k' }, doc, `${doc}#k`);
  assert.deepEqual(single, { verificationMethod: [], authentication: [] });
  assert.deepEqual(removeMethod({ name: 'x' }, doc, '#k'), { name: 'x' });
});

test('round trip: the method doctor writes is the one it later finds and removes', () => {
  const vm = buildNostrVerificationMethod({ webId, xOnlyHex: keyB, controller: webId, fragment: freeFragment(profile(), doc, 'nostr-key').split('#')[1] });
  assert.equal(vm.id, `${doc}#nostr-key-2`);
  const merged = mergeMethod(profile(), doc, vm);
  assert.equal(linkedAs(merged, doc, keyB), vm.id);
  assert.equal(linkedAs(removeMethod(merged, doc, vm.id), doc, keyB), null);
});
