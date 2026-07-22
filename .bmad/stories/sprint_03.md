# Sprint 03 — AT Protocol Publication & Verify-from-`at://`

**Sprint goal:** Publish a minted OBO Audit Receipt as a record in an AT Protocol repo under the
`dev.delegationreceipts.auditReceipt` lexicon, and verify it from its `at://` URI with **no keys and
no auth** — reusing the existing `verifyReceipt()` untouched. Testable path runs against a **mock
PDS**; a single live publish is the stretch task.

**Source spec:** [`../docs/PRD_ARCH_atproto_addendum.md`](../docs/PRD_ARCH_atproto_addendum.md) (§8) — proposed §8 of `PRD_ARCH.md`
**Depends on:** Sprint 01 (core library), Sprint 02 (issuer service). No changes to §3–§5 or the crypto path.
**Status key:** `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

> **Model split (project note):** implement on **Sonnet**, *except* any task that touches the
> signing/canonicalization path (Ed25519/JCS) → **Opus**. Sprint 03 is designed to **not** touch
> that path: the signed payload is stored and retrieved verbatim, so `mintReceipt`/`verifyReceipt`
> are called, never modified. Flagged per task below; if any task drifts into the crypto path, stop
> and escalate to Opus.

---

## Task 1 — Lexicon schema & record builder

> **Scope (addendum §8.3):** Define the `dev.delegationreceipts.auditReceipt` lexicon and the
> wrapper-record builder. Store the signed receipt **verbatim** as a JSON string; duplicate a few
> indexed fields for discovery.

**Acceptance criteria:** Given a signed `OBOAuditReceipt`, `buildRecord(receipt)` returns a wrapper
object with `$type = 'dev.delegationreceipts.auditReceipt'`, `receiptJson` = the exact serialized
receipt, and indexed mirrors (`issuer`, `subject`, `issuanceDate`, `expirationDate`, `summary`,
`schemaVersion`). `parseRecord(record)` returns the exact original receipt object. **Model: Sonnet.**

### Subtasks
- [x] Commit the lexicon JSON to `lexicons/dev.delegationreceipts.auditReceipt.json` (from addendum §8.3.3)
- [x] `src/atproto/record.ts`: `buildRecord(receipt: OBOAuditReceipt): AtpReceiptRecord`
  - [x] `$type` set to the NSID constant `RECEIPT_NSID`
  - [x] `receiptJson = JSON.stringify(receipt)` (verbatim — do not reorder/reshape)
  - [x] Populate indexed mirrors from the receipt; `schemaVersion = 'obo-receipt/v1'`
- [x] `parseRecord(record): OBOAuditReceipt` → `JSON.parse(record.receiptJson)`
- [x] `verifyMirrors(record): boolean` → indexed fields equal the parsed payload's values
- [x] Export `RECEIPT_NSID` and `atUriFor(did, receipt)` → `at://<did>/<nsid>/<receipt.id>`
- [x] Unit tests: round-trip `buildRecord` → `parseRecord` returns a deep-equal receipt; `verifyMirrors` true for honest record, false when a mirror is edited

---

## Task 2 — atproto client seam (auth + putRecord + getRecord)

> **Scope (addendum §8.4, §8.6):** A thin XRPC client with an `AtpAuth` seam, plus an in-memory
> **mock PDS** implementing the exact `putRecord`/`getRecord` shapes and a stub DID resolver.

**Acceptance criteria:** `AtpClient.putRecord(...)` and `getRecord(...)` work identically against the
mock and (by config) a real PDS. Auth is isolated so OAuth can replace app-password later without
touching publish/verify. **Model: Sonnet.**

### Subtasks
- [x] `src/atproto/auth.ts`: `AtpAuth` interface `{ session(): Promise<{ accessJwt, did }> }`
  - [x] `AppPasswordAuth` impl → `com.atproto.server.createSession` (identifier + app password)
  - [x] `FakeAuth` impl for tests (returns a fixed session, no network)
- [x] `src/atproto/client.ts`: `AtpClient`
  - [x] `putRecord({ repo, collection, rkey, record, validate })` → `com.atproto.repo.putRecord`, returns `{ uri, cid }`; default `validate: false` (optimistic — see addendum §8.3.1)
  - [x] `getRecord({ repo, collection, rkey })` → `com.atproto.repo.getRecord` (public GET, no auth)
  - [x] `resolveDidToPds(did): Promise<string>` — PLC resolution → PDS endpoint; stubbable
- [x] `src/atproto/mock-pds.ts`: in-memory PDS implementing put/get with the real request/response shapes; stub resolver maps the test DID → mock endpoint
- [x] Unit tests: put then get returns the same record; getRecord on missing rkey → typed `RecordNotFound`; putRecord without a session → auth error

---

## Task 3 — Publish & verify-from-`at://` pipeline

> **Scope (addendum §8.4–§8.5):** Wire mint → build → publish → resolve → fetch → verify end to end.
> The verify step calls the **existing** `verifyReceipt()` with no modification.

**Acceptance criteria:** `publishReceipt(receipt, client, did)` returns an `at://` URI. Given only
that URI, `verifyFromUri(uri, client)` fetches the record, parses the verbatim receipt, checks the
mirrors, runs `verifyReceipt()`, and returns `{ valid, errors, receipt, render }`. **Model: Sonnet**
(calls the crypto path, does not alter it — if a change to `verifyReceipt` seems needed, stop → Opus).

### Subtasks
- [x] `src/atproto/publish.ts`: `publishReceipt(receipt, client, issuerDid)` → `buildRecord` → `putRecord(rkey = receipt.id)` → return `atUriFor(...)`
- [x] `src/atproto/verify-uri.ts`: `verifyFromUri(uri, client, publicKeyOrJwks)`
  - [x] Parse `at://` URI → `{ did, collection, rkey }`; reject a collection ≠ `RECEIPT_NSID`
  - [x] `resolveDidToPds` → `getRecord` → `parseRecord` → `verifyMirrors`
  - [x] Call `verifyReceipt(receipt, key)` (unchanged) → assemble result; include `renderReceipt`
- [x] Integration test (mock PDS, full loop): mint → publish → `verifyFromUri` → `valid: true`, principals present in render
- [x] Integration test — tamper A: edit `receiptJson` after publish → `verifyFromUri` → `valid: false` (`SIGNATURE_INVALID`)
- [x] Integration test — tamper B: edit an indexed mirror only → `verifyMirrors` false → result flagged invalid before crypto
- [x] Integration test — wrong collection in URI → typed error, not a crash

---

## Task 4 — CLI: verify a receipt from an `at://` URI

> **Scope:** Extend the existing viewer so it can take an `at://` URI, not just a file/stdin.

**Acceptance criteria:** `view-receipt at://did:plc:…/dev.delegationreceipts.auditReceipt/<rkey>`
fetches, verifies, and renders the receipt with the same output as the file path. **Model: Sonnet.**

### Subtasks
- [x] Detect an `at://` positional arg → route through `verifyFromUri` (config: real client vs. mock via env)
- [x] Reuse `renderReceipt` + verification banner; exit `0` valid/unverified, `1` invalid
- [x] Integration test: pipe a mock-published receipt's `at://` URI → stdout shows `[ VERIFIED ]`

---

## Task 5 — Stretch: one real live publish

> **Scope (addendum §8.6):** Prove the XRPC shapes against the real network. Manual, not in CI.

### Subtasks
- [x] Stand up a dev `did:plc` account on a PDS (Bluesky or self-hosted); create an app password — `@reveluxlabs.bsky.social`, credentials in [[../../../ASSETS/Bluesky App Password|Bluesky App Password]]
- [x] Config the real `AppPasswordAuth` + `AtpClient` from env (`ATP_PDS`, `ATP_IDENTIFIER`, `ATP_APP_PASSWORD`)
- [x] Publish one minted receipt; record the resulting `at://` URI in the project note — done 2026-07-20, script `scripts/live-publish-task5.mjs`. Resulting DID: `did:plc:bty3gmskhla7rwblq5zl5jm5`. Published record:
  `at://did:plc:bty3gmskhla7rwblq5zl5jm5/dev.delegationreceipts.auditReceipt/00MRTUTHZID7DDFD1E6E30374BFF25`
- [x] Verify it from a second machine/process using only the `at://` URI — a fresh `AtpClient` (independent PLC resolution + public `getRecord`, no session reuse) called `verifyFromUri` against the URI above: `valid: true`, `errors: []`
- [x] Note any shape mismatches vs. the mock; file follow-ups — no shape mismatches; real PDS matched the mock's `putRecord`/`getRecord` contract exactly. One real gap, not a mock/real mismatch: "no keys shipped" isn't fully true yet — the verify step was handed the issuer's public `CryptoKey` directly in-process, because there's no hosted JWKS endpoint yet for a true third party to fetch it from. **Follow-up:** stand up `.well-known/jwks.json` hosting before claiming true no-keys stateless verification in the launch essay/README.

---

## Dependency order

```
Task 1 (lexicon + record build/parse)
   └── Task 2 (atproto client + mock PDS)
          └── Task 3 (publish + verify-from-uri pipeline)
                 ├── Task 4 (CLI at:// support)
                 └── Task 5 (live publish — stretch, manual)
```

## Definition of Done

- [x] All non-stretch subtasks checked; `npm test` green with the new atproto tests, no skips
- [x] Core library import graph stays clean — atproto code under `src/atproto/`, not in the crypto barrel; **no change to `src/signer` / `verifyReceipt` / canonicalization**
- [x] No new runtime deps in the core path; any atproto HTTP client confined to `src/atproto/` (mock path is dependency-free)
- [x] README gains a "Publish to atproto" section (mint → publish → verify-from-`at://`)
- [x] Verify-from-`at://` demonstrated end to end against the mock PDS
- [ ] **Deferred (addendum Q9/Q10):** own `delegationreceipts.dev` + publish the lexicon schema record + `_lexicon` DNS TXT + strict validation; native field-by-field mapping gated on a CBOR round-trip fixture test
- [ ] **Deferred (Q7):** OAuth replacing app-password auth once headless scopes stabilize

---

*Sprint 03 created 2026-07-16 (Opus planning session). Prereq for merge: fold the addendum into
`PRD_ARCH.md` as §8. Next candidate: KYA labeler / firehose discovery (addendum Q11).*
