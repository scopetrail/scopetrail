# Sprint 01 — OBO Audit Receipt: Core Library

**Sprint goal:** Ship a working, testable TypeScript library that can ingest raw token context, sign it into a portable JSON-LD receipt, and render the delegation chain in a terminal.

**Source spec:** [`../.bmad/docs/PRD_ARCH.md`](../docs/PRD_ARCH.md)
**Status key:** `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

---

## Task 1 — Token Extraction & Chain Sorting Module

> **Scope (PRD_ARCH §3):** Parse raw token input, populate the `OBOTokenContext` type tree, sort the delegation chain by `authorizedAt`, and validate all structural rules before the receipt is minted.

**Acceptance criteria:** Given any valid combination of JWT and/or opaque tokens describing a delegation chain, `extractContext()` returns a fully populated, validated `OBOTokenContext` with hops in ascending chronological order. Invalid input throws a typed `ContextValidationError` with a per-field error list.

### Subtasks

#### 1.1 — Type definitions
- [ ] Export `Principal`, `DelegationHop`, `TokenRef`, `ActionDescriptor`, and `OBOTokenContext` interfaces from `src/types.ts`
- [ ] Export `ContextValidationError` class with `field: string` and `rule: string` properties
- [ ] Add JSDoc referencing the PRD_ARCH field registry table for each interface member

#### 1.2 — Token digest helper
- [ ] Implement `digestToken(rawToken: string): string` → returns `sha256:<lowercase hex>`
- [ ] Use `node:crypto` `createHash('sha256')` (no external dep)
- [ ] Validate output format matches regex `/^sha256:[0-9a-f]{64}$/`

#### 1.3 — JWT claim extractor
- [ ] Implement `extractJwtClaims(jwt: string): JwtClaims` — base64url-decode header + payload, no signature verification (verification is the caller's concern)
- [ ] Map `iss` → `TokenRef.issuer`, `exp` → `TokenRef.tokenExpiresAt` (Unix epoch → ISO-8601), `jti` → `TokenRef.tokenId`
- [ ] Throw `ContextValidationError` if JWT is malformed (wrong segment count, invalid base64url)

#### 1.4 — Chain chronological sort
- [ ] Implement `sortChain(hops: DelegationHop[]): DelegationHop[]` — sort ascending by `authorizedAt` ISO-8601 string (lexicographic sort is valid for ISO-8601 UTC)
- [ ] Return a new array; do not mutate the input

#### 1.5 — Chain linkage validator
- [ ] Implement `validateChain(root: Principal, chain: DelegationHop[], actor: Principal): ValidationResult`
- [ ] Rule: `chain[0].delegator.id === root.id`
- [ ] Rule: for each consecutive pair, `chain[i].delegate.id === chain[i+1].delegator.id`
- [ ] Rule: `chain[chain.length - 1].delegate.id === actor.id`
- [ ] Rule: `chain.length <= 5` (max depth from PRD_ARCH §6)
- [ ] Rule: each hop's `scopeAtHop` must be a non-empty subset of the previous hop's `scopeAtHop` (root hop checked against `grantedScopes`)

#### 1.6 — Nonce generator
- [ ] Implement `generateNonce(): string` → UUID v4 using `node:crypto` `randomUUID()`
- [ ] No external dep (`uuid` package not required)

#### 1.7 — Full `extractContext()` assembler
- [ ] Implement `extractContext(input: RawContextInput): OBOTokenContext`
- [ ] Call `digestToken` for each hop's raw token
- [ ] Call `extractJwtClaims` for JWT-type tokens
- [ ] Call `sortChain` on the hop array
- [ ] Call `validateChain` and surface all errors as a single `ContextValidationError`
- [ ] Validate `issuedAt <= now + 5s` and `expiresAt > issuedAt`
- [ ] Validate `action.resourceUri` is a parseable URL
- [ ] Validate `rootPrincipal.id` is non-empty and URI/DID shaped (starts with `did:` or contains `://`)

#### 1.8 — Unit tests
- [ ] Happy path: 2-hop JWT chain → correctly sorted, linked, scopes subset
- [ ] Sort correctness: hops provided out of order → output is chronological
- [ ] Chain break: hop 1 delegate ≠ hop 2 delegator → `ContextValidationError` with correct field
- [ ] Scope inflation: hop grants scope not held by delegator → `ContextValidationError`
- [ ] Max depth: 6-hop chain → `ContextValidationError`
- [ ] Malformed JWT → `ContextValidationError`
- [ ] Clock skew: `issuedAt` 10 s in the future → `ContextValidationError`

---

## Task 2 — Asymmetric Signing Utility

> **Scope (PRD_ARCH §5):** Given a validated `OBOTokenContext`, produce a fully signed `OBOAuditReceipt` JSON-LD using Ed25519 / JCS / Base58btc. Expose a matching `verifyReceipt()` that is stateless except for the in-process nonce store.

**Acceptance criteria:** `mintReceipt()` returns a JSON-LD object whose `proof.proofValue` passes `verifyReceipt()` verification. Any single-byte mutation to any non-`proof` field causes `verifyReceipt()` to return `valid: false`. Nonce replay of an identical receipt returns `valid: false`.

### Subtasks

#### 2.1 — Key generation helper
- [ ] Implement `generateKeyPair(): Promise<{ privateKey: CryptoKey, publicKey: CryptoKey }>` using Web Crypto API (`subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])`)
- [ ] Note: use `node:crypto` `webcrypto.subtle` in Node.js ≥ 19; no polyfill required
- [ ] Implement `exportPublicKeyAsJwk(publicKey: CryptoKey): Promise<JsonWebKey>` — `subtle.exportKey('jwk', publicKey)`

#### 2.2 — JCS canonicalization
- [ ] Implement `canonicalize(obj: Record<string, unknown>): Uint8Array` per RFC 8785
- [ ] Sort object keys recursively by Unicode code point
- [ ] No floating-point mangling (JSON numbers serialized as-is)
- [ ] Return UTF-8 encoded bytes (use `TextEncoder`)
- [ ] Confirm output is byte-for-byte identical to the `jcs` npm package for the PRD_ARCH example receipt (use as a test fixture)

#### 2.3 — SHA-256 document hash
- [ ] Implement `hashDocument(canonical: Uint8Array): Promise<Uint8Array>` using `subtle.digest('SHA-256', canonical)`

#### 2.4 — Base58btc encode/decode
- [ ] Implement `base58btcEncode(bytes: Uint8Array): string` — Bitcoin Base58 alphabet, no checksum
- [ ] Implement `base58btcDecode(str: string): Uint8Array`
- [ ] No external dep; implement the alphabet table and encode/decode loops directly (~30 lines)

#### 2.5 — `mintReceipt()` assembler
- [ ] Implement `mintReceipt(context: OBOTokenContext, privateKey: CryptoKey, keyId: string, issuerDid: string): Promise<OBOAuditReceipt>`
- [ ] Build unsigned receipt JSON-LD from context (ULID for `id` — use `Date.now()` + random suffix if no `ulid` dep available, or accept `ulid` as optional peer dep)
- [ ] Canonicalize unsigned receipt → hash → sign with `subtle.sign('Ed25519', privateKey, documentHash)`
- [ ] Base58btc-encode signature bytes → `proofValue`
- [ ] Attach `proof` block per PRD_ARCH §4.2 schema
- [ ] Return complete `OBOAuditReceipt` object

#### 2.6 — In-process nonce store
- [ ] Implement `NonceStore` class with `add(nonce: string, expiresAt: Date): void` and `has(nonce: string): boolean`
- [ ] Back with a `Map<string, number>` (nonce → expiry epoch ms)
- [ ] Purge expired entries on each `add()` call (lazy eviction — no `setInterval`)
- [ ] Export a default singleton instance

#### 2.7 — `verifyReceipt()` verifier
- [ ] Implement `verifyReceipt(receipt: OBOAuditReceipt, publicKey: CryptoKey, nonceStore: NonceStore): Promise<VerificationResult>`
- [ ] Extract `proof`, remove from receipt copy, re-canonicalize, re-hash
- [ ] Base58btc-decode `proofValue`, call `subtle.verify('Ed25519', publicKey, signature, documentHash)`
- [ ] Structural checks: `expirationDate > now`, `issuanceDate <= now + 5s`
- [ ] Chain integrity check (call Task 1's `validateChain`)
- [ ] Scope subset check
- [ ] Nonce replay check via `nonceStore.has(receipt.nonce)` → if present return `valid: false, errors: ['NONCE_REPLAY']`; if absent and signature passes, call `nonceStore.add(receipt.nonce, new Date(receipt.expirationDate))`
- [ ] Return `VerificationResult { valid: boolean, errors: string[] }`

#### 2.8 — JWKS builder
- [ ] Implement `buildJwks(keys: Array<{ kid: string, publicKey: CryptoKey }>): Promise<{ keys: JsonWebKey[] }>` — `kty: 'OKP'`, `crv: 'Ed25519'`, `use: 'sig'`
- [ ] Output is ready to serve as `/.well-known/jwks.json`

#### 2.9 — Unit tests
- [ ] Round-trip: mint → verify → `valid: true`
- [ ] Tamper detection: mutate `action.verb` in signed receipt → `valid: false`
- [ ] Tamper detection: mutate `proof.proofValue` → `valid: false`
- [ ] Expired receipt: set `expirationDate` to past → `valid: false, errors: ['RECEIPT_EXPIRED']`
- [ ] Nonce replay: verify same receipt twice → second call `valid: false, errors: ['NONCE_REPLAY']`
- [ ] Canonicalization stability: same receipt object in different key insertion order → identical canonical bytes
- [ ] Base58btc: encode then decode known vector → original bytes

---

## Task 3 — Terminal ASCII/Markdown Flow Viewer

> **Scope (PRD_ARCH §5.3, §5.4):** CLI tool that reads a signed receipt JSON-LD and renders the delegation chain as an ASCII flow diagram, prints a summary of the action and proof, and runs `verifyReceipt()` inline — displaying PASS/FAIL clearly.

**Acceptance criteria:** Running `node view-receipt.js <receipt.json>` (or piped via stdin) renders a human-readable delegation chain with scopes at each hop, action summary, proof metadata, and a verification result. `--markdown` flag outputs the same content as fenced Markdown suitable for pasting into docs.

### Subtasks

#### 3.1 — CLI entry point
- [ ] Create `src/cli/view-receipt.ts` with a shebang and `#!/usr/bin/env node`
- [ ] Accept either a file path as positional arg or read stdin if no arg (enable pipe usage)
- [ ] Parse `--markdown` flag for Markdown output mode
- [ ] Parse `--jwks <url-or-file>` flag for supplying public key (optional; skip sig verification if absent, note it in output)
- [ ] Exit code `0` = valid or unverified, `1` = invalid signature or structural error

#### 3.2 — Receipt loader & parser
- [ ] Implement `loadReceipt(source: string | 'stdin'): Promise<OBOAuditReceipt>`
- [ ] Validate top-level JSON structure (must have `@type` including `'OBOAuditReceipt'`)
- [ ] Surface parse errors with a clear `Error: not a valid OBOAuditReceipt — missing field: <x>` message

#### 3.3 — Delegation chain ASCII renderer
- [ ] Implement `renderChain(receipt: OBOAuditReceipt, mode: 'ascii' | 'markdown'): string`
- [ ] Render root principal at top, each hop as a downward arrow with scopes listed inline

**ASCII format:**
```
ROOT  did:web:your-org.example/users/jim  [human]
  │   authorizedAt: 2026-06-18T14:20:00Z
  │   token: sha256:a3f1c9… (jwt / expires 16:00Z)
  ▼   scopes: read:documents, invoke:summarize
HOP 1  did:web:your-org.example/services/orchestrator  [service]
  │   authorizedAt: 2026-06-18T14:22:00Z
  │   token: sha256:b9e2d4… (jwt / expires 15:30Z)
  ▼   scopes: read:documents, invoke:summarize
ACTOR  did:web:agent.your-org.example/agents/summarizer-v2  [agent]
```

- [ ] Truncate token digest display to `sha256:<first 8 chars>…`
- [ ] In `--markdown` mode, wrap in a fenced code block

#### 3.4 — Action summary block
- [ ] Implement `renderAction(receipt: OBOAuditReceipt, mode: 'ascii' | 'markdown'): string`
- [ ] Show `verb`, `resourceUri`, any `parameters`, and `metadata.correlationId` if present
- [ ] In ASCII mode, box it with `┌─ ACTION ─┐` / `└──────────┘` borders
- [ ] In Markdown mode, render as a definition list or table

#### 3.5 — Proof metadata block
- [ ] Implement `renderProof(receipt: OBOAuditReceipt, mode: 'ascii' | 'markdown'): string`
- [ ] Show `cryptosuite`, `verificationMethod`, `created`, and first 16 chars of `proofValue` + `…`

#### 3.6 — Verification result banner
- [ ] Implement `renderVerificationResult(result: VerificationResult | null, mode: 'ascii' | 'markdown'): string`
- [ ] ASCII mode: `[ VERIFIED ]` or `[ INVALID — <errors> ]` or `[ UNVERIFIED — no key supplied ]`
- [ ] Markdown mode: `> **VERIFIED**` / `> **INVALID**` blockquote with error list
- [ ] If `result === null` (no key supplied), output unverified notice without exit code 1

#### 3.7 — Full render pipeline
- [ ] Implement `renderReceipt(receipt, result, mode)` that calls 3.3 → 3.4 → 3.5 → 3.6 and joins with blank lines
- [ ] In ASCII mode, print a top border `═══ OBO AUDIT RECEIPT ═══` and bottom `═════════════════════════`

#### 3.8 — Integration tests
- [ ] Fixture: sign a 2-hop receipt with Task 2's `mintReceipt`, serialize to JSON, run CLI → stdout contains both principal IDs and `[ VERIFIED ]`
- [ ] Tampered fixture: mutate one field, run CLI → stdout contains `[ INVALID` and exit code is `1`
- [ ] No-key run: receipt file only, no `--jwks` → stdout contains `[ UNVERIFIED` and exit code is `0`
- [ ] Markdown flag: `--markdown` output contains at least one ` ``` ` fence and no box-drawing characters outside fences
- [ ] Stdin pipe: `cat receipt.json | node view-receipt.js` → same output as positional arg

---

## Dependency Order

```
Task 1 (types + extraction)
    └── Task 2 (signing + verification)  ← depends on Task 1 types + validateChain
            └── Task 3 (viewer CLI)      ← depends on Task 2 verifyReceipt + Task 1 types
```

## Definition of Done (all tasks)

- [ ] All subtask checkboxes above are checked
- [ ] `npm test` passes with no skipped tests
- [ ] No `any` types in exported public API surface
- [ ] No external runtime dependencies beyond `node:crypto` and `node:fs` (standard library only for Tasks 1–2; Task 3 may use `node:readline` for stdin)
- [ ] Each module has a barrel export in `src/index.ts`
- [ ] README updated with a usage example for each module

---

*Sprint 01 created 2026-06-18. Next sprint candidate: HTTP issuer service + JWKS endpoint server.*
