# Vendored libraries

Pinned copies, checked in so the page runs no code from a CDN at runtime.

| File | Source |
|---|---|
| solid-oidc.js | npm `solid-oidc@0.0.10` (AGPL-3.0, `solid-oidc.LICENSE`), the package's single file, unchanged |
| noble.mjs | `@noble/curves@1.6.0` secp256k1 and `@noble/hashes@1.5.0` sha256 (MIT), bundled with esbuild 0.25 from `export { secp256k1 } from '@noble/curves/secp256k1'; export { sha256 } from '@noble/hashes/sha2';` (`--bundle --format=esm --target=es2022 --minify`) |

`SHA256SUMS` records the contents: `cd vendor && sha256sum -c SHA256SUMS`.
