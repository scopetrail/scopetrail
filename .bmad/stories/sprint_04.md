# Sprint 04 — ScopeTrail Open-Core Split (re-namespace · carve-out · license · JWKS · live re-publish)

**Sprint goal:** Execute Decision 2 of [[../../../Delegation Receipts - Rollout & Monetization Options|Rollout & Monetization Options]] as a concrete refactor: re-namespace the atproto lexicon to `dev.scopetrail.auditReceipt`, carve the Express issuer service out of the public tree into a **staged** private `ops` package, rename the public package to `@scopetrail/core` with an `/atproto` subpath, add the Apache-2.0 license/NOTICE/trademark apparatus, stand up `.well-known/jwks.json` so verification is **truly** no-keys (closes the Sprint 03 Task 5 follow-up), and re-run one live publish under the real NSID. **No change to the signing/canonicalization path and no change to the signed receipt bytes.**

**Source spec:** [[../../../ScopeTrail - Open-Core Split Design|ScopeTrail — Open-Core Split Design]] (§"Migration steps" 1–6 + file-by-file disposition) · Sprint 03 Task 5 JWKS follow-up (`sprint_03.md` line 113).
**Depends on:** Sprint 03 (atproto publish + verify-from-`at://`, live publish proven). Builds only on `src/atproto/*`, packaging, and hosting — not §3–§5 crypto.
**Status key:** `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

> **Model split (project note):** implement on **Sonnet** throughout. Escalate to **Opus** if any task drifts into the signing/canonicalization path (Ed25519 / JCS / `src/signer` / `verifyReceipt`) **or** would change the signed receipt bytes — i.e. the receipt's internal `@context`, `schemaVersion` (`obo-receipt/v1`), field set, or ordering. This refactor is designed to touch **none** of that: it renames the *atproto collection NSID* and the *npm package*, both of which live outside the canonicalized payload. If any task appears to require editing a signed-payload field or `buildJwks`/key derivation, **stop and escalate**.

> **Regression guardrail (applies to every task):** a receipt minted before this sprint and one minted after must produce the **same signature** for the same input. Add a frozen fixture (a pre-refactor signed receipt) and assert byte-for-byte equality of the canonical form + signature through the whole sprint. If it ever diverges, a task crossed the line above.

---

## Task 1 — Re-namespace the atproto lexicon → `dev.scopetrail.auditReceipt`

> **Scope (design doc step 1 — "do first, blocks nothing"):** Rename the collection NSID only. The
> signed receipt is stored verbatim as before; the NSID is the atproto *collection*, not a
> canonicalized field.

**Acceptance criteria:** `RECEIPT_NSID === 'dev.scopetrail.auditReceipt'`; the lexicon file is renamed accordingly; `atUriFor` emits `at://<did>/dev.scopetrail.auditReceipt/<id>`; every record round-trip / publish / verify-from-`at://` test passes under the new NSID; the frozen signature fixture is unchanged (proves the payload was not touched). **Model: Sonnet.**

### Subtasks
- [x] Rename `lexicons/dev.delegationreceipts.auditReceipt.json` → `lexicons/dev.scopetrail.auditReceipt.json`; update the `id`/`$type` inside it
- [x] Update `RECEIPT_NSID` constant → `'dev.scopetrail.auditReceipt'` (single source of truth; grep for any hard-coded `dev.delegationreceipts` string)
- [x] Verify `buildRecord`/`parseRecord`/`verifyMirrors` need **no** logic change — only the NSID constant flows through
- [x] Update all atproto unit + integration tests to the new NSID; the "wrong collection in URI" test now rejects the *old* NSID
- [x] **Guard:** do **not** touch the receipt's `@context` or `schemaVersion` (`obo-receipt/v1`) — those stay; only the atproto collection name changes
- [x] Add the frozen pre-refactor signature fixture + assertion (regression guardrail)

---

## Task 2 — Stage the ops carve-out (server → private `scopetrail/ops`)

> **Scope (design doc step 2 + file-by-file disposition):** Move everything that exists only to
> *operate a receipt service at scale* out of the public tree. Per Jim's decision, stage it inside the
> vault at `PROJECTS/scopetrail-ops/` as a self-contained package; **Jim** creates the private GitHub
> repo and pushes. Core keeps the in-process `NonceStore` — stateless verification stays fully open.

**Acceptance criteria:** the public tree contains no `src/server/`; the public `package.json` has **zero** runtime dependencies (Express gone) and no `start` script; `npm test` is green in the public tree with the server test relocated; the staged `scopetrail-ops/` folder is self-contained (its own `package.json`, `tsconfig`, README stub, and a `HANDOFF.md` listing exactly what Jim must wire). **Model: Sonnet.**

### Subtasks
- [x] Create `PROJECTS/scopetrail-ops/` staging folder with `src/`, its own `package.json` (declares `express` etc.), `tsconfig.json`, and `README.md` stub
- [x] Move to ops: `src/server/app.ts`, `server.ts`, `src/server/async-nonce-store.ts`, `src/server/keystore.ts`, and `src/tests/server.test.ts`
- [x] Keep in core: in-process `NonceStore` (stateless replay protection stays open)
- [x] Strip `express` from public `package.json` `dependencies`; remove the `start` script; confirm the "zero runtime dependencies" claim now holds without asterisks
- [x] Public `README.md`: replace §5 (HTTP issuer service) with one line — "hosted / self-managed issuer — coming (ScopeTrail ops)"
- [x] Write `scopetrail-ops/HANDOFF.md`: repo name (`scopetrail/ops`, private, all-rights-reserved for now), how it imports `@scopetrail/core`, env vars it expects, and "license TBD at Phase 3 (BSL vs proprietary)"
- [x] `npm test` green in public tree; ops folder builds/typechecks on its own (or HANDOFF documents any pending wire-up)

---

## Task 3 — Rename package → `@scopetrail/core` + `/atproto` subpath export

> **Scope (design doc step 3):** Single package, CLI bin included, atproto as a subpath. Keep today's
> ergonomics; no monorepo machinery.

**Acceptance criteria:** `import { mintReceipt } from '@scopetrail/core'` and `import { verifyFromUri } from '@scopetrail/core/atproto'` both resolve after `npm run build`; the CLI bin still works; README import examples and all internal deep imports (`dist/atproto/index.js`) use the subpath; `npm test` green. A thin `scopetrail` re-export file exists (publish deferred to Task 6). **Model: Sonnet.**

### Subtasks
- [x] `package.json`: `name` → `@scopetrail/core`; add an `exports` map with `"."` and `"./atproto"`; retain `bin`
- [x] Replace today's deep import path (`dist/atproto/index.js`) with the `./atproto` subpath throughout src + tests
- [x] Update README import examples and the "Publish to atproto" section to the new package name + subpath
- [x] Create the thin bare-`scopetrail` package (one file re-exporting `@scopetrail/core`) — file only; **publish deferred to Task 6 (Jim)**
- [x] `npm run build` + `npm test` green; a smoke import of both entry points resolves post-build

---

## Task 4 — License + trademark apparatus (Apache-2.0, DCO, trademark)

> **Scope (design doc step 4 + "License mechanics"):** Apache-2.0 so OEM embedding is copyleft-free;
> DCO not CLA (core stays Apache forever); the real control point is the trademark.

**Acceptance criteria:** `LICENSE` (Apache-2.0) and `NOTICE` ("ScopeTrail, © 2026 [entity TBD]") present at repo root; an SPDX header line in every `src/**/*.ts`; `TRADEMARK.md` (nominative use fine, no confusingly-branded forks) and `CONTRIBUTING.md` (DCO sign-off note, no CLA) present. **Model: Sonnet.**

### Subtasks
- [x] Add `LICENSE` (Apache-2.0 text) and `NOTICE` with the ScopeTrail line (entity left as `[entity TBD]` — parked to Phase 3)
- [x] Add `SPDX-License-Identifier: Apache-2.0` header line to each source file (script the insertion; verify count == file count)
- [x] Add `TRADEMARK.md` — short nominative-use policy, no confusingly-branded forks
- [x] Add `CONTRIBUTING.md` with the DCO sign-off note; **no CLA**
- [x] Confirm the staged ops package is **not** Apache-licensed (all-rights-reserved until Phase 3 — noted in its HANDOFF, per Task 2)

---

## Task 5 — `.well-known/jwks.json` so verification is truly no-keys

> **Scope (Sprint 03 Task 5 follow-up):** Sprint 03's live verify still handed the issuer's public
> `CryptoKey` in-process because there was no hosted JWKS. Close that: publish the issuer key as a
> static JWKS a third party can fetch, and let the verify path resolve the key **by URL**. Because the
> ops server is being carved out, the JWKS must be **static-hostable** with no ops service running.

**Acceptance criteria:** a `jwks.json` artifact is produced from the existing `buildJwks` output **verbatim**; `verifyFromUri` (and/or `verifyReceipt`) can accept a JWKS **URL** and fetch the key rather than receiving a `CryptoKey` in-process; against the mock, a fresh verify that resolves the key by URL returns `valid: true`; README documents the no-keys path. The signature fixture (guardrail) is unchanged. **Model: Sonnet — Opus-gate on `buildJwks`/key derivation: read its output, do not modify it; if a change seems needed, stop → Opus.**

### Subtasks
- [x] Emit a static `jwks.json` from `buildJwks(publicKey)` output verbatim (a small build/CLI step; committed as an example artifact under e.g. `.well-known/`)
- [x] Add a fetch-by-URL key resolver to the verify path (JWKS URL → JWK → `CryptoKey`), leaving the in-process-key signature intact for callers that still pass a key
- [x] Integration test (mock): publish → `verifyFromUri` with **only** the `at://` URI + JWKS URL (no in-process key) → `valid: true`
- [x] README: document true stateless no-keys verification (fetch receipt from `at://`, fetch key from JWKS URL)
- [ ] **Jim handoff (infra, not code):** decide + deploy the static host for `/.well-known/jwks.json` (scopetrail domain or gh-pages) — record the live JWKS URL in the project note. Code lands this sprint; the DNS/host deploy is Jim-gated

---

## Task 6 — npm placeholders + one live re-publish under the new NSID (Jim-gated)

> **Scope (design doc steps 5–6):** Reserve the org npm names and prove the new NSID against the real
> network. External/irreversible actions need Jim's credentials.

**Acceptance criteria:** publish-ready artifacts exist and dry-run green against the mock; Jim's live run records a new `at://` URI under `dev.scopetrail.auditReceipt` and verifies it from the JWKS URL with no in-process key. **Model: Sonnet for prep; Jim executes the external steps.**

### Subtasks
- [x] Prep placeholder packages: bare `scopetrail` (thin re-export, from Task 3), `@scopetrail/server`, `@scopetrail/ops` (minimal placeholder `package.json` under the org scope)
- [x] Update / clone `scripts/live-publish-task5.mjs` → a `task6` publish script targeting `dev.scopetrail.auditReceipt`; dry-run against the mock PDS passes
- [ ] **Jim executes (needs creds):** `npm publish` the three placeholders (org scope); run one live publish of a minted receipt under the new NSID
- [ ] **Jim executes:** verify the new record from a fresh process using only the `at://` URI + the hosted JWKS URL → `valid: true`, `errors: []`; record the new URI in [[../../../ScopeTrail - Open-Core Split Design|the split-design note]] / project note (supersedes the Sprint 03 live URI, which used the old NSID)

---

## Dependency order

```
Task 1 (re-namespace lexicon)  ── do first, blocks nothing
Task 2 (ops carve-out)  ─┐
Task 4 (license apparatus) ─┼─ independent of each other; both before Task 3's final tree
Task 3 (package rename + /atproto)  ── after Task 2 (clean public tree)
Task 5 (JWKS + verify-by-URL)  ── after Task 1; independent of rename
Task 6 (placeholders + live re-publish)  ── LAST; needs 1,3,5; Jim-gated external steps
```

## Definition of Done

- [x] All non–Jim-gated subtasks checked; `npm test` green in the public tree (74 tests, 0 fail, 0 skip)
- [x] **Signature regression fixture unchanged** — a receipt minted post-refactor is byte-identical + signature-identical to the pre-refactor fixture; **no change to `src/signer` / `verifyReceipt` / canonicalization / signed-payload fields**
- [x] Public tree has **zero** runtime dependencies and no `src/server/`; ops staged self-contained in `PROJECTS/scopetrail-ops/` with `HANDOFF.md`
- [x] `@scopetrail/core` resolves with the `./atproto` subpath; CLI bin works; README updated to new name + no-keys verify path
- [x] `LICENSE` / `NOTICE` / `TRADEMARK.md` / `CONTRIBUTING.md` (DCO) present; SPDX header in every source file
- [x] `jwks.json` artifact produced from `buildJwks` verbatim; verify-by-URL demonstrated end to end against the mock
- [ ] **Jim-gated (external / irreversible):** create + push private `scopetrail/ops` repo; `npm publish` the three placeholders; deploy `/.well-known/jwks.json` host; one live re-publish under `dev.scopetrail.auditReceipt` + verify from JWKS URL; record the new URI
- [ ] **Parked (design-doc open questions, non-blocking):** ops license at Phase 3 (BSL 1.1 vs proprietary); legal entity for the NOTICE / trademark owner; whether `atproto` ever becomes its own package

---

*Sprint 04 planned 2026-07-20 (Opus orchestration session). Architect input: [[../../../ScopeTrail - Open-Core Split Design|Open-Core Split Design]]. Implementation is Sonnet per the model-split note above, with the crypto path fenced off by the regression guardrail. Do not free-style the refactor — work the tasks in dependency order.*
