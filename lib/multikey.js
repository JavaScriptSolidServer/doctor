/**
 * Multikey encoding for Nostr secp256k1 public keys.
 *
 * Per the did:nostr spec (https://nostrcg.github.io/did-nostr/):
 *
 *   1. Start with the x-only Nostr pubkey (32 bytes hex)
 *   2. Prepend a parity byte to form a 33-byte compressed secp256k1 key
 *      (0x02 = even y, 0x03 = odd y; Nostr apps may use either)
 *   3. Prepend the multicodec varint for secp256k1-pub: 0xe7, 0x01
 *   4. Multibase-encode with base16-lower — prefix "f"
 *
 * Result: "f" + "e701" + <parity-hex> + <pubkey-hex>
 */

// Multicodec varint for secp256k1-pub: code 0xe7 → varint bytes 0xe7, 0x01
const MULTICODEC_SECP256K1_PUB = 'e701';

/**
 * Encode a Nostr x-only public key as a CID-v1 publicKeyMultibase.
 *
 * @param {string} xOnlyHex - 64-char hex string (32 bytes)
 * @param {object} [opts]
 * @param {0x02|0x03|'02'|'03'} [opts.parity=0x02] - Compressed-key parity prefix
 * @returns {string} publicKeyMultibase value, e.g. "fe70102..."
 */
export function nostrPubkeyToMultikey(xOnlyHex, opts = {}) {
  const hex = normalizeHex(xOnlyHex);
  if (hex.length !== 64) {
    throw new Error(`Nostr pubkey must be 32 bytes (64 hex chars); got ${hex.length}`);
  }
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error('Nostr pubkey must be hex (0-9, a-f, A-F)');
  }

  let parity = opts.parity ?? 0x02;
  if (typeof parity === 'string') parity = parseInt(parity, 16);
  if (parity !== 0x02 && parity !== 0x03) {
    throw new Error(`Parity byte must be 0x02 or 0x03; got 0x${parity.toString(16)}`);
  }
  const parityHex = parity === 0x02 ? '02' : '03';

  return 'f' + MULTICODEC_SECP256K1_PUB + parityHex + hex;
}

/**
 * Decode a publicKeyMultibase value back into the Nostr x-only pubkey hex,
 * if it represents a secp256k1-pub multikey. Returns null otherwise.
 *
 * Useful for cross-checking that an existing verificationMethod actually
 * encodes a Nostr-compatible key.
 *
 * @param {string} mb - publicKeyMultibase value
 * @returns {{ xOnlyHex: string, parity: 0x02|0x03 } | null}
 */
export function multikeyToNostrPubkey(mb) {
  if (typeof mb !== 'string' || mb.length === 0) return null;
  // base16-lower with 'f' prefix
  if (!mb.startsWith('f')) return null;
  const hex = mb.slice(1).toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex)) return null;
  if (!hex.startsWith(MULTICODEC_SECP256K1_PUB)) return null;
  const rest = hex.slice(MULTICODEC_SECP256K1_PUB.length);
  if (rest.length !== 66) return null; // 1 parity byte + 32 bytes
  const parityHex = rest.slice(0, 2);
  const xOnlyHex  = rest.slice(2);
  if (parityHex !== '02' && parityHex !== '03') return null;
  return { xOnlyHex, parity: parityHex === '02' ? 0x02 : 0x03 };
}

/**
 * Build a CID-v1 verificationMethod entry for a Nostr key.
 *
 * @param {object} args
 * @param {string} args.webId - The full WebID URI (with or without #me).
 *   Used to derive the VM `id` (fragment URI rooted at the document).
 * @param {string} args.xOnlyHex - 32-byte x-only Nostr pubkey, hex
 * @param {string} [args.controller=webId] - The CID document that
 *   controls this verificationMethod. Defaults to the WebID itself
 *   (the common self-controlled case). For delegated-control profiles,
 *   pass the profile's declared `controller` so the VM agrees with the
 *   outer controller predicate.
 * @param {string} [args.fragment='nostr-key-1'] - Fragment id for the VM
 * @param {0x02|0x03} [args.parity=0x02]
 */
export function buildNostrVerificationMethod({
  webId,
  xOnlyHex,
  controller,
  fragment = 'nostr-key-1',
  parity = 0x02,
}) {
  if (typeof webId !== 'string' || webId.length === 0) {
    throw new Error('webId must be a non-empty string');
  }
  const mb = nostrPubkeyToMultikey(xOnlyHex, { parity });
  // The VM id is a fragment URI rooted at the WebID's document. We strip
  // any existing fragment so paths like ".../card.jsonld#me" yield
  // ".../card.jsonld#nostr-key-1".
  const docUrl = stripHash(webId);
  return {
    id: `${docUrl}#${fragment}`,
    type: 'Multikey',
    controller: controller ?? webId,
    publicKeyMultibase: mb,
  };
}

function normalizeHex(s) {
  if (typeof s !== 'string') throw new Error('Pubkey must be a hex string');
  return s.trim().toLowerCase().replace(/^0x/, '');
}

function stripHash(u) {
  if (typeof u !== 'string') return u;
  try {
    const url = new URL(u);
    url.hash = '';
    return url.toString();
  } catch {
    return u.split('#')[0];
  }
}
