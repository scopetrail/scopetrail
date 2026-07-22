#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
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
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { loadReceipt, renderReceipt } from '../viewer.js';
import { verifyReceipt, base58btcDecode } from '../signer.js';
import { verifyFromUri } from '../atproto/verify-uri.js';
import { AtpClient, FetchTransport, createPlcDidResolver } from '../atproto/client.js';
import { FakeAuth, FAKE_ACCESS_JWT } from '../atproto/auth.js';
import { MockPds, MOCK_PDS_URL } from '../atproto/mock-pds.js';
const { subtle } = webcrypto;
function parseArgs(argv) {
    const args = argv.slice(2); // strip 'node' and script path
    let source = 'stdin';
    let mode = 'ascii';
    let jwksPath = null;
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (arg === '--markdown') {
            mode = 'markdown';
        }
        else if (arg === '--jwks') {
            jwksPath = args[++i] ?? null;
            if (!jwksPath)
                fatal('--jwks requires a file path argument');
        }
        else if (!arg.startsWith('--')) {
            source = arg;
        }
    }
    return { source, mode, jwksPath };
}
// ── JWKS key importer ─────────────────────────────────────────────────────────
/**
 * Load a JWKS file and import the first Ed25519 signing key found.
 * Matches by `use: 'sig'` and `crv: 'Ed25519'`.
 */
async function importPublicKeyFromJwks(jwksPath, verificationMethod) {
    let jwks;
    try {
        jwks = JSON.parse(readFileSync(jwksPath, 'utf8'));
    }
    catch (e) {
        fatal(`Failed to read JWKS file "${jwksPath}": ${e.message}`);
    }
    if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) {
        fatal(`JWKS file "${jwksPath}" contains no keys`);
    }
    // Try to match by kid extracted from verificationMethod fragment (#key-id)
    const kidFromMethod = verificationMethod.includes('#')
        ? verificationMethod.split('#')[1]
        : null;
    const candidates = jwks.keys.filter(k => k.kty === 'OKP' && k.crv === 'Ed25519' && (kidFromMethod == null || k.kid === kidFromMethod));
    if (candidates.length === 0) {
        process.stderr.write(`Warning: no Ed25519 key matching kid "${kidFromMethod ?? 'any'}" found in JWKS. Trying first OKP key.\n`);
        const fallback = jwks.keys.find(k => k.kty === 'OKP');
        if (!fallback)
            return null;
        candidates.push(fallback);
    }
    try {
        return await subtle.importKey('jwk', candidates[0], { name: 'Ed25519' }, true, ['verify']);
    }
    catch (e) {
        process.stderr.write(`Warning: failed to import public key: ${e.message}\n`);
        return null;
    }
}
// ── Utilities ─────────────────────────────────────────────────────────────────
function fatal(msg) {
    process.stderr.write(`error: ${msg}\n`);
    process.exit(1);
}
// Keep unused import happy — base58btcDecode is used transitively via verifyReceipt
void base58btcDecode;
/**
 * Assemble the `AtpClient` used for `at://` verification. See the file-header doc for the
 * `ATP_MOCK` / `ATP_MOCK_STORE` env var contract this reads.
 */
async function buildAtpClient() {
    if (process.env.ATP_MOCK === '1') {
        const pds = new MockPds([FAKE_ACCESS_JWT]);
        const auth = new FakeAuth();
        // Only one mock PDS exists per CLI invocation, so every DID resolves to it.
        const client = new AtpClient({
            auth,
            transport: pds,
            didResolver: async () => MOCK_PDS_URL,
        });
        const storePath = process.env.ATP_MOCK_STORE;
        if (storePath) {
            let seed;
            try {
                seed = JSON.parse(readFileSync(storePath, 'utf8'));
            }
            catch (e) {
                fatal(`Failed to read ATP_MOCK_STORE file "${storePath}": ${e.message}`);
            }
            for (const entry of seed) {
                await client.putRecord({
                    repo: entry.repo,
                    collection: entry.collection,
                    rkey: entry.rkey,
                    record: entry.record,
                    validate: false,
                });
            }
        }
        return client;
    }
    // Real path: live PLC DID resolution + HTTP PDS calls. FakeAuth is a safe placeholder here —
    // this CLI only ever calls getRecord (a public, unauthenticated read); auth.session() would
    // only be exercised by putRecord, which verify-only use never touches.
    return new AtpClient({
        auth: new FakeAuth(),
        transport: new FetchTransport(),
        didResolver: createPlcDidResolver(),
    });
}
/**
 * Verify-from-`at://` path: fetch, verify, render, exit. Mirrors the file/stdin path's use of
 * `renderReceipt` exactly, but `--jwks` is mandatory since `verifyFromUri` always verifies (it
 * has no "no key supplied" mode).
 */
async function runAtUriVerification(uri, jwksPath, mode) {
    if (!jwksPath) {
        fatal('--jwks is required when verifying an at:// URI (verify-from-at:// always verifies)');
    }
    let jwks;
    try {
        jwks = JSON.parse(readFileSync(jwksPath, 'utf8'));
    }
    catch (e) {
        fatal(`Failed to read JWKS file "${jwksPath}": ${e.message}`);
    }
    const client = await buildAtpClient();
    const result = await verifyFromUri(uri, client, jwks);
    if (result.receipt) {
        // Reuse renderReceipt exactly as the file/stdin path does, building the same
        // VerificationResult shape verifyReceipt() itself returns.
        const output = renderReceipt(result.receipt, { valid: result.valid, errors: result.errors }, mode);
        process.stdout.write(output + '\n');
    }
    else {
        // Early-exit atproto-layer error (MALFORMED_URI / WRONG_COLLECTION / RECORD_NOT_FOUND) —
        // no receipt was recoverable, so there's nothing for renderReceipt to render.
        process.stderr.write(`error: ${result.errors.join(', ')}\n`);
    }
    process.exit(result.valid ? 0 : 1);
}
// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
    const { source, mode, jwksPath } = parseArgs(process.argv);
    if (source.startsWith('at://')) {
        await runAtUriVerification(source, jwksPath, mode);
        return;
    }
    // Load and parse receipt
    let receipt;
    try {
        receipt = await loadReceipt(source);
    }
    catch (e) {
        fatal(e.message);
    }
    // Optionally verify
    let result = null;
    if (jwksPath) {
        const publicKey = await importPublicKeyFromJwks(jwksPath, receipt.proof.verificationMethod);
        if (publicKey) {
            result = await verifyReceipt(receipt, publicKey);
        }
        else {
            process.stderr.write('Warning: could not import a matching public key — skipping verification.\n');
        }
    }
    // Render and print
    const output = renderReceipt(receipt, result, mode);
    process.stdout.write(output + '\n');
    // Exit code: 1 only when we actually verified and it failed
    if (result !== null && !result.valid) {
        process.exit(1);
    }
}
main().catch(e => {
    process.stderr.write(`Unhandled error: ${e.message}\n`);
    process.exit(1);
});
//# sourceMappingURL=view-receipt.js.map