# doctor

A diagnostic tool for [Solid](https://solidproject.org/) pods and the surrounding decentralized-web stack.

> **Status:** alpha. First diagnostic ships as the LWS / W3C Controlled Identifiers v1.0 profile-shape check. More will accrete; well-defined ones may extract into focused tools.

**Live:** https://jss.live/doctor/

## What it does today

**1. LWS / CID v1 profile shape check** — drop in a WebID URL, get a pass/warn/fail/skip checklist of what's structurally there and what's missing for [LWS 1.0](https://www.w3.org/TR/2026/WD-lws10-authn-ssi-cid-20260423/) auth conformance:

- Profile fetches as `application/ld+json`?
- `@context` declares the CID v1 vocabulary (controller, verificationMethod, authentication, …)?
- `controller === @id` (CID v1 self-control contract)?
- `verificationMethod` populated?
  - Each entry has `id`, `type`, `controller`, and either `publicKeyJwk` or `publicKeyMultibase`?
  - Each method's `controller` matches the profile's declared `controller` (with fallback to `@id` when `controller` is absent), so delegated-control profiles validate correctly?
  - `id` values unique?
- `authentication` entries point at real verificationMethods?
- `alsoKnownAs` entries are DID URIs?

Read-only — no auth, no mutations, no server roundtrip beyond the GETs.

**2. Nostr verification-method generator** — reads your Nostr pubkey from a [NIP-07](https://github.com/nostr-protocol/nips/blob/master/07.md) signer (e.g. [xlogin](https://xlogin.solid.social/)), encodes it per [did:nostr](https://nostrcg.github.io/did-nostr/)'s Multikey recipe, and emits a copyable JSON snippet to add to your profile. No keys leave your browser.

**3. Strict [LWS10-CID](https://www.w3.org/TR/2026/WD-lws10-authn-ssi-cid-20260423/) auth client** — sign in to your pod via Solid-OIDC (using the [`solid-oidc`](https://www.npmjs.com/package/solid-oidc) package), paste a secp256k1 private key as 64 hex chars (the raw 32-byte key behind your Nostr `nsec1…` bech32 — same key, different signature scheme), and the doctor adds a `JsonWebKey` VM to your profile (read-modify-write via authenticated GET + PUT) and signs an LWS10-CID JWT with `alg: ES256K` to authenticate end-to-end. Pairs with the [JSS server-side verifier](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/pull/398). Privkey is held in memory for the tab only.

## Roadmap (rough)

- ~~**B.0**~~ — Read-only LWS-CID profile validator ✅
- ~~**B.2**~~ — Read pubkey from NIP-07 signer; emit Multikey verificationMethod snippet ✅
- ~~**B.3**~~ — Strict LWS10-CID auth: Solid-OIDC sign-in, ES256K `JsonWebKey` VM written into profile (GET → merge → PUT with `If-Match`), sign real JWTs to authenticate ✅
- **B.1** — Bidirectional `alsoKnownAs` ↔ DID-doc check (resolve `did:nostr:…` and verify the DID points back at this WebID)
- **B.4** — did:key + WebAuthn passkey verification methods
- **B.5** — More diagnostics: ACL inheritance, type-index integrity, OIDC discovery, ActivityPub actor doc, …

## Why a separate repo

This is intentionally not coupled to JSS or any specific Solid server. It runs as a pure browser app against any pod that can serve JSON-LD profile docs.

## Stack

Vanilla JS. No build step. Single HTML entry point + a couple of modules. Deploys as a static site to GitHub Pages from the `gh-pages` branch.

## Refs

- [JSS#386](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/386) — overall convergence tracker for Solid profile-to-key linking
- [JSS#388](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/pull/388) — Phase A (server-side): pod profiles became CID-document-shaped
- [W3C Controlled Identifiers v1.0](https://www.w3.org/TR/cid-1.0/)
- [LWS 1.0 SSI via CID (FPWD 2026-04-23)](https://www.w3.org/TR/2026/WD-lws10-authn-ssi-cid-20260423/)
- [did:nostr](https://nostrcg.github.io/did-nostr/)

## License

[AGPL-3.0-only](./LICENSE) — matches JSS.
