#!/usr/bin/env node
/**
 * view-receipt — CLI entry point for the OBO Audit Receipt viewer.
 *
 * Usage:
 *   node dist/cli/view-receipt.js <receipt.json>            # from file
 *   cat receipt.json | node dist/cli/view-receipt.js        # from stdin
 *   node dist/cli/view-receipt.js receipt.json --markdown   # Markdown output
 *   node dist/cli/view-receipt.js receipt.json --jwks keys.json  # with verification
 *   node dist/cli/view-receipt.js at://did:plc:.../dev.scopetrail.auditReceipt/<rkey> \
 *     --jwks keys.json                                      # verify-from-at:// (Sprint 03 Task 4)
 *
 * Exit codes:
 *   0 — valid receipt, or unverified (no key supplied) — file/stdin path only
 *   1 — invalid signature / structural error, fatal parse error, or (at:// path) any
 *       atproto-layer error (malformed URI, wrong collection, record not found, mirror mismatch,
 *       key import failure)
 *
 * at:// mode (Sprint 03 Task 4):
 *   `--jwks` is required — `verifyFromUri` always performs verification (it has no "skip
 *   verification" mode the way the file/stdin path does), so there is nothing meaningful to
 *   render without a key to check against.
 *
 *   Client selection is via env var, so this file needn't hardcode a real network client in the
 *   only-ever-exercised-by-tests path:
 *     - `ATP_MOCK=1`            — use an in-memory `MockPds` (src/atproto/mock-pds.ts) instead of
 *                                 a real PDS. No network.
 *     - `ATP_MOCK_STORE=<path>` — (only meaningful with ATP_MOCK=1) a JSON file containing an
 *                                 array of `{ repo, collection, rkey, record }` entries that get
 *                                 `putRecord`-ed into the fresh mock PDS *before* verification
 *                                 runs. This is how a test process (which cannot share in-memory
 *                                 state with this CLI's separate `node` process) seeds the record
 *                                 the CLI is about to fetch — see src/tests/atproto-cli.test.ts.
 *     - unset/anything else     — real client: `FetchTransport` + `createPlcDidResolver()`
 *                                 (live network PLC resolution + PDS HTTP calls).
 *   `FakeAuth` backs both branches: `getRecord` (all this CLI ever calls) is a public,
 *   unauthenticated read, so a real session is never needed for verify-only use.
 *
 * @see sprint_01.md §3.1
 * @see sprint_03.md Task 4
 */
export {};
//# sourceMappingURL=view-receipt.d.ts.map