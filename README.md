# doctor

A diagnostic tool for [Solid](https://solidproject.org/) pods and the surrounding decentralized-web stack.

> **Status:** alpha. First diagnostic ships as the LWS / W3C Controlled Identifiers v1.0 profile-shape check. More will accrete; well-defined ones may extract into focused tools.

**Live:** https://javascriptsolidserver.github.io/doctor/

## What it checks today

**LWS / CID v1 profile shape** — drop in a WebID URL, get a green/red checklist of what's structurally there and what's missing for [LWS 1.0](https://www.w3.org/TR/2026/WD-lws10-authn-ssi-cid-20260423/) auth conformance:

- Profile fetches as `application/ld+json`?
- `@context` declares the CID v1 vocabulary (controller, verificationMethod, authentication, …)?
- `controller === @id` (CID v1 self-control contract)?
- `verificationMethod` populated?
  - Each entry has `id`, `type`, `controller`, and either `publicKeyJwk` or `publicKeyMultibase`?
  - `controller` of each method matches the WebID?
  - `id` values unique?
- `authentication` entries point at real verificationMethods?
- `alsoKnownAs` entries are DID URIs?

Read-only — no auth, no mutations, no server roundtrip beyond the GETs.

## Roadmap (rough)

- **B.0** — Read-only LWS-CID profile validator (this commit)
- **B.1** — Bidirectional `alsoKnownAs` ↔ DID-doc check (resolve `did:nostr:…` and verify the DID points back at this WebID)
- **B.2** — xlogin / NIP-07 sign-in to act as a WebID owner
- **B.3** — PATCH `verificationMethod` (Multikey for Nostr secp256k1) into the signed-in user's profile
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
