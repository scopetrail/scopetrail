<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `@scopetrail/core`. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [Semantic Versioning](https://semver.org/), with the 0.x rule that a **minor** bump
may carry breaking changes.

## [0.2.0] — 2026-08-12

### Changed — BREAKING

- **Principal identifiers are now validated for conformance, on every principal.**
  `extractContext()` checks `rootPrincipal.id`, `actingPrincipal.id`, and both ends of every hop, and
  requires each to be a conformant W3C DID (per the did-core ABNF) or an absolute URI with a scheme.

  Previously only `rootPrincipal.id` was checked, and only for *shape* — "starts with `did:` or
  contains `://`". Three of the four identifier positions were never inspected at all, and malformed
  DIDs such as `did:web:example.com/users/jim` passed. Slashes are not legal DID characters: `did:web`
  path segments are colon-delimited (`did:web:example.com:users:jim`) and only become slashes when the
  DID is resolved to an HTTPS URL.

  **Migration:** if you pass slash-form `did:web` identifiers, convert them to colon form. Input that
  previously produced a signed receipt may now raise `ContextValidationError`, which reports every
  offending field in one pass.

  Verification is unaffected — `verifyReceipt()` and `verifyFromUri()` do not call `extractContext()`,
  so receipts minted before this release continue to verify unchanged.

### Fixed

- The bundled demo and documentation examples used slash-form `did:web` identifiers throughout
  (README, `src/viewer.ts` render sketch, `scripts/mint-demo-receipt.mjs`, and 23 test fixtures).
  All corrected to colon form.
- `OBO_CONTEXTS` now points at `https://scopetrail.github.io/contexts/obo-receipt/v1.jsonld`, which is
  live. The previous value referenced the pre-rename `schemas.delegation-receipts.dev` domain, which
  does not resolve. This value is embedded in the signed payload, so only newly minted receipts carry
  the corrected context.

### Added

- `CHANGELOG.md` (this file).
- README section documenting identifier conformance, with accepted and rejected examples.

## [0.1.0] — 2026-07-23

- First published release. `extractContext()`, `mintReceipt()`, `verifyReceipt()`, `renderReceipt()`,
  atproto publish/verify (`publishReceipt()`, `verifyFromUri()`), hosted-JWKS keyless verification,
  and the `view-receipt` CLI.
