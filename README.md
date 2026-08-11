# delegation-receipts

**OBO Audit Receipt** — portable, cryptographically signed delegation receipts for AI agents and services acting *on behalf of* (OBO) a human principal.

When an agent acts on your behalf, there is usually no tamper-proof artifact proving *who* authorized it, *what* was delegated, *when*, and *what action* was actually taken. This library captures that full delegation context at action time and seals it into a signed, portable JSON-LD receipt that any verifier can check **statelessly** — no callback to the issuer required.

- **Zero runtime dependencies.** Only Node's built-in `node:crypto` / Web Crypto.
- **Ed25519 / JCS (RFC 8785) / Base58btc** signing, W3C Verifiable Credential–shaped receipts.
- Stateless verification with in-process replay protection.

See the [API surface](#api-surface) table below for the full export list, and the sections that
follow for how the pieces fit together.

## Requirements

- Node.js ≥ 18 (Web Crypto Ed25519 needs ≥ 19 in practice; tested on 22).

## Install

```bash
npm install @scopetrail/core
```

Building from source (this repo):

```bash
npm install      # installs dev deps (typescript, @types/node)
npm run build    # compiles src/ → dist/
npm test         # build + run the test suite (74 tests)
```

## Quickstart: mint → publish → keyless verify

The full round trip — mint a receipt, publish it to an AT Protocol repo, and verify it back with
**nothing but the `at://` URI and a public JWKS URL** (no keys shipped to the verifier, no auth):

```ts
import { mintReceipt } from '@scopetrail/core';
import {
  AtpClient, FetchTransport, AppPasswordAuth, createPlcDidResolver,
  publishReceipt, verifyFromUri,
} from '@scopetrail/core/atproto';

// 1. Mint (issuer side — see "Build the delegation context" below for `context`)
const receipt = await mintReceipt(context, privateKey, 'key-1', 'did:plc:<issuer>');

// 2. Publish
const client = new AtpClient({
  auth: new AppPasswordAuth({ service: process.env.ATP_PDS!, identifier: process.env.ATP_IDENTIFIER!, appPassword: process.env.ATP_APP_PASSWORD! }),
  transport: new FetchTransport(),
  didResolver: createPlcDidResolver(),
});
const uri = await publishReceipt(receipt, client, 'did:plc:<issuer>');
// → at://did:plc:<issuer>/dev.scopetrail.auditReceipt/<rkey>

// 3. Verify — keyless, from anywhere, using the live hosted JWKS
const result = await verifyFromUri(uri, client, {
  jwksUrl: 'https://scopetrail.github.io/.well-known/jwks.json',
});
// → { valid: true, errors: [], receipt, render }
```

Or from the command line with nothing installed and nothing configured — this verifies the live demo
receipt against the hosted public key, and works on a machine that has never seen this project:

```bash
curl -sO https://scopetrail.github.io/.well-known/jwks.json
npx -y --package=@scopetrail/core view-receipt \
  at://did:plc:bty3gmskhla7rwblq5zl5jm5/dev.scopetrail.auditReceipt/00MSNYOYEE8DED5E8457E895C30683 \
  --jwks jwks.json
```

> **Run that from outside a clone of this repo.** This package *is* `@scopetrail/core`, so inside the
> source tree `npx` resolves `--package=@scopetrail/core` to the local project instead of fetching it,
> and npm does not link a root package's own bin — you get `view-receipt: command not found`. From
> within a clone, build first and invoke the CLI directly:
>
> ```bash
> npm ci && npm run build
> curl -s https://scopetrail.github.io/.well-known/jwks.json -o jwks.json
> node dist/cli/view-receipt.js "at://did:plc:…/dev.scopetrail.auditReceipt/<rkey>" --jwks jwks.json
> ```

The rest of this README walks each step in detail.

## The flow at a glance

```
RawContextInput ──extractContext()──► OBOTokenContext ──mintReceipt()──► OBOAuditReceipt (signed)
                                                                              │
                                                          verifyReceipt() ◄───┘
                                                          renderReceipt()  (human-readable view)
```

---

## 1. Build the delegation context — `extractContext()`

`extractContext()` takes raw token input, digests each token (SHA-256 — the raw token is *never* stored), sorts the delegation chain chronologically, and validates every structural rule. It throws a typed `ContextValidationError` (with a per-field error list) if anything is wrong.

```ts
import { extractContext } from '@scopetrail/core';

const now = Date.now();
const iso = (ms: number) => new Date(ms).toISOString();

const context = extractContext({
  rootPrincipal:   { id: 'did:web:org/users/jim', type: 'human', displayName: 'Jim' },
  actingPrincipal: { id: 'did:web:agent/summarizer', type: 'agent', displayName: 'Summarizer' },

  // Ordered delegation hops: human → service → agent
  hops: [
    {
      delegator: { id: 'did:web:org/users/jim', type: 'human' },
      delegate:  { id: 'did:web:org/orchestrator', type: 'service' },
      scopeAtHop: ['read:docs', 'invoke:summarize'],
      rawToken: '<jwt-or-opaque-token>',
      tokenType: 'jwt',
      authorizedAt: iso(now - 2000),
    },
    {
      delegator: { id: 'did:web:org/orchestrator', type: 'service' },
      delegate:  { id: 'did:web:agent/summarizer', type: 'agent' },
      scopeAtHop: ['read:docs', 'invoke:summarize'],
      rawToken: '<leaf-token>',
      tokenType: 'jwt',
      authorizedAt: iso(now - 1000),
    },
  ],

  rawUpstreamToken: '<leaf-token>',     // the token directly authorizing the actor
  upstreamTokenType: 'jwt',
  grantedScopes: ['read:docs', 'invoke:summarize'],
  audience: ['https://api.org/docs'],
  action: {
    verb: 'invoke',
    resourceUri: 'https://api.org/docs/789/summarize',
    parameters: { format: 'bullets' },   // sanitized — never put secrets here
  },
  issuedAt: iso(now),
  expiresAt: iso(now + 3_600_000),       // 1 hour TTL
});
```

Validation enforced for you: chain linkage (each hop's delegate = next hop's delegator, leaf = actor), scope subset at each hop, max chain depth of 5, clock-skew tolerance (5 s), and URI/DID shapes. Catch failures via the typed error:

```ts
import { ContextValidationError } from '@scopetrail/core';

try {
  extractContext(badInput);
} catch (e) {
  if (e instanceof ContextValidationError) {
    console.error(e.errors); // [{ field: 'hops[1].delegator', rule: '...' }, ...]
  }
}
```

---

## 2. Sign & verify — `mintReceipt()` / `verifyReceipt()`

```ts
import { generateKeyPair, mintReceipt, verifyReceipt } from '@scopetrail/core';

// In production the private key lives in an HSM/KMS; this is for local use/testing.
const { privateKey, publicKey } = await generateKeyPair();

const receipt = await mintReceipt(
  context,
  privateKey,
  'key-1',                          // kid — appears in proof.verificationMethod
  'did:web:receipts.your-org.example',
);
// → signed OBOAuditReceipt (JSON-LD). Serialize with JSON.stringify and store/ship it.

const result = await verifyReceipt(receipt, publicKey);
console.log(result); // { valid: true, errors: [] }
```

`verifyReceipt()` is stateless apart from an in-process nonce store for replay protection. It checks, in order: nonce replay, Ed25519 signature over the JCS canonical form, expiry, clock skew, chain integrity, and scope subset. Any single-byte mutation to a non-`proof` field flips `valid` to `false`:

```ts
receipt.action.verb = 'delete';                 // tamper
await verifyReceipt(receipt, publicKey);        // { valid: false, errors: ['SIGNATURE_INVALID'] }
```

### Custom / shared nonce store

The default store is a singleton. For tests or isolated verifiers, pass your own:

```ts
import { NonceStore } from '@scopetrail/core';

const store = new NonceStore();
await verifyReceipt(receipt, publicKey, store);  // first call → valid
await verifyReceipt(receipt, publicKey, store);  // second call → { valid: false, errors: ['NONCE_REPLAY'] }
```

> For multi-replica deployments, back replay protection with a shared store (Redis/DB). See PRD_ARCH §5 open question Q3.

---

## 3. Publish public keys — `buildJwks()`

Verifiers fetch your public keys to check signatures. `buildJwks()` produces a JWKS document ready to serve at `/.well-known/jwks.json`:

```ts
import { buildJwks } from '@scopetrail/core';

const jwks = await buildJwks([
  { kid: 'key-1', publicKey },        // active
  { kid: 'key-0', publicKey: retired }, // keep retired keys until their window closes
]);

// Serve as application/json at https://receipts.your-org.example/.well-known/jwks.json
// { "keys": [{ "kty": "OKP", "crv": "Ed25519", "kid": "key-1", "use": "sig", "x": "..." }, ...] }
```

---

## 4. Human-readable view — CLI & `renderReceipt()`

### CLI: `view-receipt`

Renders the delegation chain as an ASCII flow diagram, an action box, proof metadata, and a verification banner.

```bash
# From a file
node dist/cli/view-receipt.js receipt.json

# Piped via stdin
cat receipt.json | node dist/cli/view-receipt.js

# Markdown output (fenced, paste-into-docs friendly)
node dist/cli/view-receipt.js receipt.json --markdown

# Supply a public key to actually verify the signature
node dist/cli/view-receipt.js receipt.json --jwks ./jwks.json
```

Exit codes: `0` = valid or unverified, `1` = invalid signature / structural error. Without `--jwks` the signature is not checked and the banner shows `[ UNVERIFIED — no key supplied ]`.

Example output:

```
═══ OBO AUDIT RECEIPT ═══

ROOT  did:web:org/users/jim  [human]
  │   authorizedAt: 2026-06-18T14:20:00Z
  │   token: sha256:845e3044… (jwt / expires 16:00:00Z)
  ▼   scopes: read:docs, invoke:summarize
HOP 1  did:web:org/orchestrator  [service]
  │   authorizedAt: 2026-06-18T14:22:00Z
  │   token: sha256:7d1b4186… (opaque)
  ▼   scopes: read:docs, invoke:summarize
ACTOR  did:web:agent/summarizer  [agent]

┌─ ACTION ─────────────────────────────────────────┐
│  verb:         invoke                            │
│  resource:     https://api.org/docs/789/summarize│
└──────────────────────────────────────────────────┘

[ VERIFIED ]

═════════════════════════
```

### Programmatic: `renderReceipt()`

```ts
import { renderReceipt, verifyReceipt } from '@scopetrail/core';

const result = await verifyReceipt(receipt, publicKey);
const ascii    = renderReceipt(receipt, result, 'ascii');
const markdown = renderReceipt(receipt, result, 'markdown');
// Pass null as the result to render an "unverified" view.
```

---

## 5. HTTP issuer service

Hosted / self-managed issuer — coming (ScopeTrail ops).

## 6. Publish to atproto — `publishReceipt()` / `verifyFromUri()`

A minted receipt can be published as a record in an **AT Protocol** repository, giving it a public, addressable, tamper-evident home. Any third party can then verify it from its `at://` URI with **no keys shipped and no auth** — the existing Ed25519 verification runs unchanged on fetch. See PRD_ARCH §8 for the design.

Key design points:

- **Verbatim storage.** The record wrapper (`dev.scopetrail.auditReceipt`, lexicon in `lexicons/`) stores the complete signed receipt as an opaque JSON string (`receiptJson`), so DAG-CBOR re-serialization can never break the JCS signature. Indexed mirror fields (`issuer`, `subject`, dates, `summary`) exist for discovery only and are cross-checked against the payload on read.
- **Two identities.** The atproto `did:plc` says *where the receipt lives*; the issuer's `key-1` (JWKS) says *what proves it authentic*. Publication adds discovery, not a new trust model.
- **Record keys.** `receipt.id` is `urn:obo-receipt:<id>`; colons aren't allowed in atproto rkeys, so the bare id (`rkeyFor(receipt)`) is the rkey and `atUriFor()` builds the matching URI.

```ts
import { mintReceipt } from '@scopetrail/core';
import {
  AtpClient, FetchTransport, AppPasswordAuth, createPlcDidResolver,
  publishReceipt, verifyFromUri,
} from '@scopetrail/core/atproto';

// Publish (issuer side — needs an app password on the PDS account)
const client = new AtpClient({
  auth: new AppPasswordAuth({ service: process.env.ATP_PDS!, identifier: process.env.ATP_IDENTIFIER!, appPassword: process.env.ATP_APP_PASSWORD! }),
  transport: new FetchTransport(),
  didResolver: createPlcDidResolver(),
});
const uri = await publishReceipt(receipt, client, 'did:plc:<issuer>');
// → at://did:plc:<issuer>/dev.scopetrail.auditReceipt/<rkey>

// Verify (anyone, anywhere — no auth; only the issuer's public JWKS)
const result = await verifyFromUri(uri, client, jwks);
// → { valid, errors, receipt, render }
```

`verifyFromUri` checks, in order: URI shape and collection (`MALFORMED_URI` / `WRONG_COLLECTION`), record existence (`RECORD_NOT_FOUND`), mirror integrity (`MIRROR_MISMATCH`), then hands the verbatim payload to the unchanged `verifyReceipt()` (`SIGNATURE_INVALID`, `RECEIPT_EXPIRED`, `NONCE_REPLAY`, …). One flat error vocabulary across both layers.

### No-keys verification — resolve the key from a hosted JWKS URL

Sprint 03's live publish still had to hand `verifyFromUri` the issuer's public `CryptoKey` in-process, because there was nowhere to fetch it from. That gap is closed: `verifyFromUri`'s third argument now also accepts a **JWKS URL** (a `JwksUrlRef`) instead of an in-process key/JWKS. A verifier with *zero* key material — only the `at://` URI and a URL — can now do the whole thing:

```ts
import { verifyFromUri } from '@scopetrail/core/atproto';

// Nothing but the at:// URI and the hosted JWKS URL — no CryptoKey, no JsonWebKeySet, no auth.
const result = await verifyFromUri(uri, client, {
  jwksUrl: 'https://scopetrail.example/.well-known/jwks.json',
});
// → { valid, errors, receipt, render }
```

`jwksUrl` is fetched with `fetch` (injectable via an optional `fetchFn`, defaulting to `globalThis.fetch` — tests supply a stub so no real network is ever touched), the key matching the receipt's `verificationMethod` kid is selected and imported (`crypto.subtle.importKey('jwk', jwk, 'Ed25519', false, ['verify'])`), and the rest of the pipeline — mirror check, `verifyReceipt()` — runs unchanged. A bad URL, unreachable host, or a JWKS with the wrong/missing kid never throws; it comes back as the same typed `KEY_IMPORT_FAILED` result used everywhere else in this module.

**Producing the JWKS artifact.** `scripts/emit-jwks.mjs` calls the existing `buildJwks()` (src/signer.ts, untouched) and writes its output verbatim to `.well-known/jwks.json` — a static file, servable with no server running (gh-pages, S3, the scopetrail domain, …):

```bash
npm run build
node scripts/emit-jwks.mjs --jwk-file ./issuer-public-jwk.json --kid key-1 --out .well-known/jwks.json
```

The `.well-known/jwks.json` committed in this repo is an **EXAMPLE**, generated from a throwaway demo keypair (`node scripts/emit-jwks.mjs` with no `--jwk-file`) — it does **not** correspond to any real receipt or issuer. Jim regenerates it from the real issuer public key at deploy time and points `jwksUrl` at wherever it's actually hosted.

### CLI

`view-receipt` accepts an `at://` URI in place of a file; `--jwks` is required in this mode:

```bash
node dist/cli/view-receipt.js "at://did:plc:…/dev.scopetrail.auditReceipt/<rkey>" --jwks ./jwks.json
```

### Testing without a network

The full pipeline is exercised against an in-memory **mock PDS** (`MockPds`) implementing the real `putRecord`/`getRecord` XRPC shapes — CI needs no live account. The CLI mock mode: `ATP_MOCK=1 ATP_MOCK_STORE=<seed.json>`. A single live publish against a real PDS is a deliberate manual step (sprint 03 Task 5); swapping mock→real is pure config (`FetchTransport` + `createPlcDidResolver` + `AppPasswordAuth`).

## API surface

| Export | Module | Purpose |
|---|---|---|
| `extractContext` | builder | Build + validate `OBOTokenContext` from raw input |
| `digestToken`, `extractJwtClaims`, `sortChain`, `validateChain`, `generateNonce` | builder | Lower-level building blocks |
| `mintReceipt`, `verifyReceipt` | signer | Sign / stateless-verify receipts |
| `generateKeyPair`, `exportPublicKeyAsJwk`, `buildJwks` | signer | Key management & JWKS |
| `canonicalize`, `hashDocument`, `base58btcEncode`, `base58btcDecode` | signer | Crypto primitives (RFC 8785, Base58btc) |
| `NonceStore`, `defaultNonceStore` | signer | Replay protection |
| `renderReceipt`, `renderChain`, `renderAction`, `renderProof`, `renderVerificationResult` | viewer | Human-readable rendering |
| `ContextValidationError`, plus all interfaces (`OBOTokenContext`, `OBOAuditReceipt`, `Principal`, …) | types | Types & typed errors |
| `fetchJwks`, `selectAndImportKey`, `resolveKeyFromJwksUrl`, `JwksFetchError` | atproto/jwks | Fetch-by-URL JWKS resolution (no-keys verification) |

## Security notes

- Receipts embed only a **SHA-256 digest** of each token — never the raw token.
- `action.parameters` must be sanitized before minting (no bearer tokens, passwords, or PII).
- Default design is revocation-free: short TTLs *are* the revocation. See PRD_ARCH §5.7 for optional revocation mechanisms.
- Verifiers should maintain a **trusted-issuer allowlist** — a mathematically valid signature from an unknown issuer should still be rejected.

## Project status

Core library, HTTP issuer service design, AT Protocol publication + verify-from-`at://` (mock-PDS
tested), and fetch-by-URL JWKS resolution (true no-keys verification) are complete — 74 tests
green. The public JWKS is live at https://scopetrail.github.io/.well-known/jwks.json, and a real
receipt has been published under the `dev.scopetrail.auditReceipt` collection and verified keyless
against that URL. Deferred: Redis-backed nonce store, key rotation/persistence, a published atproto
lexicon schema record, OAuth replacing app-password auth.

See also: the launch post and positioning page (linked here once published) for how ScopeTrail
compares to adjacent projects, and [`docs/positioning.md`](docs/positioning.md) for the short
version.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

"ScopeTrail" (name and logo) is a trademark of the ScopeTrail project; the license covers the code,
not the name. See [`TRADEMARK.md`](TRADEMARK.md) before using the ScopeTrail name for a fork,
distribution, or hosted service. Contributions: see [`CONTRIBUTING.md`](CONTRIBUTING.md) (DCO
sign-off, no CLA).
