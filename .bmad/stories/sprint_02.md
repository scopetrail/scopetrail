# Sprint 02 — HTTP Issuer Service + JWKS Endpoint

**Sprint goal:** Expose the core library over HTTP — an Express service that mints signed receipts, verifies them (with replay protection), and publishes signing keys at a standard JWKS endpoint. Fold in the two schema/architecture decisions from PRD §7 (Q4 embedded summary, Q3 pluggable nonce store).

**Source spec:** [`../docs/PRD_ARCH.md`](../docs/PRD_ARCH.md) §5 (verification), §7 (resolved decisions)
**Depends on:** Sprint 01 (core library)
**Status key:** `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

---

## Task 1 — Schema & architecture follow-ups from PRD §7

#### 1.1 — Embedded summary (Q4)
- [x] Add `summary: string` to `OBOAuditReceipt` (covered by the signature → tamper-proof)
- [x] `buildSummary(context)` generates `<root> authorized <actor> to <verb> <resource>`
- [x] `mintReceipt` populates `summary` before canonicalization

#### 1.2 — Pluggable nonce store (Q3)
- [x] Define `INonceStore { add, has }` interface (allows sync or async impls)
- [x] `NonceStore` (in-process) implements it; `verifyReceipt` accepts `INonceStore` and `await`s calls
- [x] `AsyncNonceStore` (service-side, async-shaped) as the Redis-swap seam

---

## Task 2 — Express issuer service

**Acceptance criteria:** `createApp(deps)` returns a configured Express app (testable without a port). A bootstrapped key store signs receipts; verifiers can fetch keys and validate.

#### 2.1 — Key store
- [x] `KeyStore` with `generateAndActivate(kid)`, `active()`, `get(kid)`, `all()`
- [x] In-memory now; documented HSM/KMS swap point

#### 2.2 — App + routes
- [x] `GET /healthz` → `{ status, issuer }`
- [x] `GET /.well-known/jwks.json` → `buildJwks(...)`, `Cache-Control: max-age=3600`
- [x] `POST /receipts` → `extractContext` → `mintReceipt`; 201 on success, 400 + field errors on `ContextValidationError`
- [x] `POST /verify` → resolve `kid` from `proof.verificationMethod`, `verifyReceipt`; 200 valid / 422 invalid / 422 UNKNOWN_KEY

#### 2.3 — Runnable entry point
- [x] `server.ts` reads `PORT`, `ISSUER_DID`, `ACTIVE_KID` from env; `npm start`

---

## Task 3 — Integration tests

- [x] `GET /healthz` → ok
- [x] `GET /.well-known/jwks.json` → active key present, `crv: Ed25519`
- [x] `POST /receipts` → 201, signed, embedded summary present
- [x] mint → verify → `{ valid: true }`
- [x] tampered receipt → 422, `SIGNATURE_INVALID`
- [x] replay → second `/verify` → 422, `NONCE_REPLAY`
- [x] invalid input → 400, `CONTEXT_VALIDATION_FAILED` with field details

All 7 server tests pass (42 total across the project).

---

## Definition of Done

- [x] `npm test` green (42 tests)
- [x] Live server smoke-tested (health, jwks, mint, verify, replay)
- [x] Core library import graph stays Express-free (server lives under `src/server/`, not in the barrel)
- [x] README documents running the service
- [ ] **Deferred:** Redis-backed `AsyncNonceStore` for true multi-replica (interface seam is in place)
- [ ] **Deferred:** `did:web` issuer document + hosted `@context` (PRD §7 Q1 — defer to publish time)
- [ ] **Deferred:** key rotation/retirement endpoint + persistence (KeyStore is in-memory)

---

*Sprint 02 created 2026-06-18. Next candidate: persistence + key rotation, or a trusted-issuer registry for verifiers.*
