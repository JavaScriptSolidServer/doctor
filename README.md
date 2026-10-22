# doctor

Connect your Nostr key to your Solid pod. **Live:** https://jss.live/doctor/

Sign in to your pod once and it learns your Nostr key. From then on Nostr apps such as
[Solid Chat](https://solid-chat.com/v2/) write to your pod as you over
[NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md), with no further
sign-in. Nothing secret leaves the browser: the pod only ever sees the public key.

## What it does

1. Finds your WebID profile from a pod address or a WebID.
2. Signs you in to the pod with Solid-OIDC (the `solid:oidcIssuer` named in the profile).
3. Reads your public key from a [NIP-07](https://github.com/nostr-protocol/nips/blob/master/07.md)
   signer such as [podkey](https://github.com/JavaScriptSolidServer/podkey).
4. Writes it into the profile as a `Multikey` `verificationMethod` (the
   [did:nostr](https://nostrcg.github.io/did-nostr/) encoding) referenced from
   `authentication`, by GET, merge, PUT with `If-Match`. Running it again with the same
   key changes nothing.
5. Proves it: a NIP-98-signed `HEAD` of the profile must come back with the owner's
   `WAC-Allow`. [JSS](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer)
   resolves such a key to the pod owner's WebID.

Under **Advanced**: the read-only LWS / W3C Controlled Identifiers v1.0 profile-shape
check, and the strict LWS10-CID test client (ES256K `JsonWebKey` method plus a signed JWT),
loaded only when used.

## Stack

Plain ES modules, no build step, no runtime CDN: `solid-oidc` and the noble secp256k1 and
sha256 code are pinned in `vendor/` with checksums (`cd vendor && sha256sum -c SHA256SUMS`).
The page's Content Security Policy allows scripts from its own origin only. Deploys as a
static site from the `gh-pages` branch.

`?webid=…` or `?pod=…` in the URL prefills the address, so another app can link here.

## Refs

- [JSS#386](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/386) — convergence tracker
- [did:nostr](https://nostrcg.github.io/did-nostr/)
- [W3C Controlled Identifiers v1.0](https://www.w3.org/TR/cid-1.0/)
- [LWS 1.0 authentication](https://www.w3.org/TR/2026/WD-lws10-authn-ssi-cid-20260423/)
