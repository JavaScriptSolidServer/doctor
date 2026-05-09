/**
 * Client-side helpers for LWS10-CID authentication with secp256k1.
 *
 * Two responsibilities:
 *
 *   1. Derive a `JsonWebKey` verificationMethod from a secp256k1 private
 *      key (the same curve Nostr uses) so it can be PATCHed into the
 *      user's WebID profile.
 *
 *   2. Sign LWS10-CID JWTs locally — `alg: ES256K` (RFC8812). The
 *      signed JWT is sent as `Authorization: Bearer <jwt>` and the
 *      pod's verifier looks up the VM by `kid`.
 *
 * Same private key, two signature schemes: Schnorr/BIP-340 for Nostr
 * (NIP-98 etc.), ECDSA/secp256k1 for LWS-CID. We use noble's secp256k1
 * primitives via esm.sh.
 */

import { secp256k1 } from 'https://esm.sh/@noble/curves@1.6.0/secp256k1';
import { sha256 }    from 'https://esm.sh/@noble/hashes@1.5.0/sha2';

// --- helpers ---------------------------------------------------------

function hexToBytes(hex) {
  const clean = hex.trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]+$/.test(clean) || clean.length % 2) {
    throw new Error('not a hex string');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function b64u(bytes) {
  // base64url without padding
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function utf8(s) { return new TextEncoder().encode(s); }

// --- key material ----------------------------------------------------

/**
 * Validate a hex secp256k1 private key (32 bytes / 64 hex chars).
 * Returns the bytes if valid, throws otherwise.
 *
 * Note: Nostr's BIP-340 spec uses the same 32-byte secp256k1 secret —
 * the same nsec hex pasted here is the same key Nostr signs with.
 */
export function validatePrivKey(hex) {
  const bytes = hexToBytes(hex);
  if (bytes.length !== 32) {
    throw new Error(`secp256k1 private key must be 32 bytes (64 hex chars); got ${bytes.length}`);
  }
  // secp256k1 requires the privkey to be in [1, n-1]. noble validates on
  // first use; trigger that here so we surface a clear error early.
  secp256k1.getPublicKey(bytes, /*compressed*/false);
  return bytes;
}

/**
 * Build a `JsonWebKey` verificationMethod for ES256K from a privkey.
 *
 * @param {object} args
 * @param {Uint8Array|string} args.privKey - 32-byte privkey (Uint8Array or hex string)
 * @param {string} args.webId - WebID URI used as the VM `id` base
 * @param {string} [args.controller=webId] - The CID document that
 *   controls this verificationMethod. Defaults to the WebID itself
 *   (the common self-controlled case). For delegated-control profiles
 *   pass the profile's declared `controller` so the VM agrees with
 *   the outer controller predicate.
 * @param {string} [args.fragment='lws-key-1'] - VM fragment id
 * @returns {{ vm: object, jwk: object, kid: string }}
 */
export function buildEs256kVerificationMethod({ privKey, webId, controller, fragment = 'lws-key-1' }) {
  const priv = privKey instanceof Uint8Array ? privKey : validatePrivKey(privKey);
  // Uncompressed 65-byte point: 0x04 || x(32) || y(32)
  const pubFull = secp256k1.getPublicKey(priv, /*compressed*/false);
  if (pubFull.length !== 65 || pubFull[0] !== 0x04) {
    throw new Error('unexpected public key encoding');
  }
  const x = pubFull.slice(1, 33);
  const y = pubFull.slice(33, 65);

  const docUrl = stripHash(webId);
  const kid = `${docUrl}#${fragment}`;

  const jwk = {
    kty: 'EC',
    crv: 'secp256k1',
    alg: 'ES256K',
    x: b64u(x),
    y: b64u(y),
    kid,
  };
  const vm = {
    id: kid,
    type: 'JsonWebKey',
    controller: controller ?? webId,
    publicKeyJwk: jwk,
  };
  return { vm, jwk, kid };
}

// --- JWT signing -----------------------------------------------------

/**
 * Sign an LWS10-CID JWT.
 *
 * Per the FPWD §4: sub === iss === client_id (all the WebID URI), aud
 * is the target server origin, exp/iat are required. Lifetime capped
 * at 5 minutes — the verifier rejects > 1h, but short tokens limit
 * the replay window if one leaks anyway.
 *
 * @param {object} args
 * @param {Uint8Array|string} args.privKey
 * @param {string} args.kid - JsonWebKey VM id (fragment URI)
 * @param {string} args.webId - subject WebID
 * @param {string} args.audience - target server origin (e.g. https://pod.example)
 * @param {number} [args.lifetimeSec=300]
 * @returns {Promise<string>} compact JWS
 */
export async function signLwsCidJwt({ privKey, kid, webId, audience, lifetimeSec = 300 }) {
  const priv = privKey instanceof Uint8Array ? privKey : validatePrivKey(privKey);
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'ES256K', typ: 'JWT', kid };
  const payload = {
    sub: webId,
    iss: webId,
    client_id: webId,
    aud: [audience],
    iat: now,
    exp: now + lifetimeSec,
  };
  const h64 = b64u(utf8(JSON.stringify(header)));
  const p64 = b64u(utf8(JSON.stringify(payload)));
  const signingInput = utf8(`${h64}.${p64}`);
  const msgHash = sha256(signingInput);
  const sig = secp256k1.sign(msgHash, priv);
  // Compact 64-byte r||s — what JWS expects for ES256K.
  const sigBytes = sig.toCompactRawBytes();
  return `${h64}.${p64}.${b64u(sigBytes)}`;
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
