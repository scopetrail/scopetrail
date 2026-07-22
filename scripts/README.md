# scripts/

Manual/operational scripts — none of these run in `npm test` or CI. All import from the built
`dist/`, so `npm run build` first.

## publish-receipt-task6.mjs (Sprint 04 Task 6)

Mints a receipt, publishes it under the current collection NSID (`RECEIPT_NSID`, imported from
`dist/atproto/record.js` — never hardcoded), and verifies it back using the Task 5 JWKS-URL
resolver (no in-process key).

**Dry-run (default — safe, no network, no credentials):**

```bash
npm run build
node scripts/publish-receipt-task6.mjs --mock
```

Runs the full loop against the in-memory mock PDS: mint → build record → publish → `verifyFromUri`
with only the resulting `at://` URI + a JWKS URL (an injected `fetchFn` stands in for the hosted
`.well-known/jwks.json`, so no real network call happens). Prints the mock `at://` URI and asserts
`valid: true`, exiting non-zero if that assertion fails. `--dry-run` and no flags at all behave the
same way — mock is always the default.

**Live publish (Jim only — needs real credentials):**

```bash
export ATP_PDS=https://your-pds.example
export ATP_IDENTIFIER=your-handle
export ATP_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx
# optional — set once the JWKS host from Task 5's Jim handoff is deployed, to verify via the
# true no-keys path instead of the in-process public key fallback:
export ATP_JWKS_URL=https://scopetrail.example/.well-known/jwks.json

node scripts/publish-receipt-task6.mjs --live
```

`--live` without all three required env vars (`ATP_PDS`, `ATP_IDENTIFIER`, `ATP_APP_PASSWORD`)
prints a clear message naming what's missing and exits non-zero — it never attempts a network
call in that case. The resulting `at://` URI is published under the new NSID
(`dev.scopetrail.auditReceipt`) and **supersedes the Sprint 03 live URI**, which was published
under the old NSID. Record the new URI in the project note.

## emit-jwks.mjs (Sprint 04 Task 5)

Writes a static `jwks.json` from `buildJwks()`'s output verbatim — see the README "No-keys
verification" section.

## guardrail-fixture.mjs (Sprint 04 regression guardrail)

`node scripts/guardrail-fixture.mjs --check` — asserts the JCS-canonicalization + Ed25519
signature path is byte-identical to the frozen fixture (`tests/fixtures/guardrail.json`). Run
after any change that touches `src/signer.ts` or its callers.

## live-publish-task5.mjs (Sprint 03 Task 5, superseded)

The original one-off live publish, targeting the pre-Sprint-04 NSID and handing the verify step
an in-process `CryptoKey`. Left as-is for history; `publish-receipt-task6.mjs` is the script to
run going forward.

## add-spdx-headers.mjs (Sprint 04 Task 4)

One-time script that inserted the `SPDX-License-Identifier: Apache-2.0` header into every
`src/**/*.ts` file.
