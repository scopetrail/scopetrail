// SPDX-License-Identifier: Apache-2.0
/**
 * atproto-cli.test.ts — Integration tests for Sprint 03 Task 4
 * (CLI: verify a receipt from an `at://` URI).
 *
 * Unlike atproto-pipeline.test.ts (which calls `verifyFromUri` in-process), these tests spawn
 * the *compiled* CLI (`dist/cli/view-receipt.js`) as a real child process — the same way a user
 * would invoke it — and assert on its actual stdout/stderr/exit code.
 *
 * A spawned CLI process can't share the in-memory `MockPds` instance a test builds in this
 * process, so the CLI's mock branch (`ATP_MOCK=1`) is seeded from a file instead:
 * `ATP_MOCK_STORE=<path to JSON file>` holds an array of `{ repo, collection, rkey, record }`
 * entries that the CLI `putRecord`s into its own fresh `MockPds` before verifying — see the
 * `buildAtpClient()` doc comment in src/cli/view-receipt.ts for the full env var contract.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractContext } from '../builder.js';
import { generateKeyPair, mintReceipt, buildJwks } from '../signer.js';
import { buildRecord, rkeyFor, atUriFor, RECEIPT_NSID } from '../atproto/record.js';
// ── Fixtures ─────────────────────────────────────────────────────────────────
const cliPath = fileURLToPath(new URL('../cli/view-receipt.js', import.meta.url));
function makeJwt(claims) {
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
    return `${header}.${payload}.sig`;
}
function makeRawInput() {
    const now = new Date();
    const exp = new Date(now.getTime() + 3_600_000);
    const jwt1 = makeJwt({ iss: 'https://auth.example', exp: Math.floor(exp.getTime() / 1000), jti: 'j1' });
    const jwt2 = makeJwt({ iss: 'https://auth.example', exp: Math.floor(exp.getTime() / 1000), jti: 'j2' });
    return {
        rootPrincipal: { id: 'did:web:org.example/users/jim', type: 'human', displayName: 'Jim' },
        hops: [
            {
                delegator: { id: 'did:web:org.example/users/jim', type: 'human' },
                delegate: { id: 'did:web:org.example/agents/bot', type: 'agent' },
                scopeAtHop: ['read:docs'],
                rawToken: jwt1,
                tokenType: 'jwt',
                authorizedAt: now.toISOString(),
            },
        ],
        actingPrincipal: { id: 'did:web:org.example/agents/bot', type: 'agent', displayName: 'Summarizer Agent v2' },
        rawUpstreamToken: jwt2,
        upstreamTokenType: 'jwt',
        grantedScopes: ['read:docs'],
        audience: ['https://api.example'],
        action: { verb: 'invoke', resourceUri: 'https://api.example/summarize' },
        issuedAt: now.toISOString(),
        expiresAt: exp.toISOString(),
    };
}
/** Mint a fresh keypair + receipt for a given issuer DID (fixed keyId 'key-1'). */
async function mintFixture(issuerDid) {
    const { privateKey, publicKey } = await generateKeyPair();
    const context = extractContext(makeRawInput());
    const receipt = await mintReceipt(context, privateKey, 'key-1', issuerDid);
    return { receipt, publicKey };
}
// ── Tests ──────────────────────────────────────────────────────────────────────
describe('view-receipt CLI: verify from at:// URI (Sprint 03 Task 4)', () => {
    it('mock-published receipt: at:// URI -> stdout shows [ VERIFIED ], exit 0', async () => {
        const issuerDid = 'did:plc:cliTestIssuerValid00000';
        const { receipt, publicKey } = await mintFixture(issuerDid);
        const record = buildRecord(receipt);
        const rkey = rkeyFor(receipt);
        const uri = atUriFor(issuerDid, receipt);
        const jwks = await buildJwks([{ kid: 'key-1', publicKey }]);
        const dir = mkdtempSync(join(tmpdir(), 'view-receipt-cli-'));
        try {
            const storePath = join(dir, 'mock-store.json');
            const jwksPath = join(dir, 'jwks.json');
            writeFileSync(storePath, JSON.stringify([{ repo: issuerDid, collection: RECEIPT_NSID, rkey, record }]));
            writeFileSync(jwksPath, JSON.stringify(jwks));
            const res = spawnSync(process.execPath, [cliPath, uri, '--jwks', jwksPath], {
                encoding: 'utf8',
                env: { ...process.env, ATP_MOCK: '1', ATP_MOCK_STORE: storePath },
            });
            assert.equal(res.status, 0, `expected exit 0, got ${res.status}. stderr: ${res.stderr}`);
            assert.ok(res.stdout.includes('[ VERIFIED ]'), `expected [ VERIFIED ] banner, got:\n${res.stdout}`);
            assert.ok(res.stdout.includes(receipt.credentialSubject.id), 'expected acting principal in output');
            assert.ok(res.stdout.includes(receipt.delegationContext.rootPrincipal.id), 'expected root principal in output');
        }
        finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
    it('wrong collection in the URI -> exit 1, error printed, no crash', async () => {
        const issuerDid = 'did:plc:cliTestIssuerWrongColl0';
        const { receipt, publicKey } = await mintFixture(issuerDid);
        const rkey = rkeyFor(receipt);
        const wrongCollectionUri = `at://${issuerDid}/app.bsky.feed.post/${rkey}`;
        const jwks = await buildJwks([{ kid: 'key-1', publicKey }]);
        const dir = mkdtempSync(join(tmpdir(), 'view-receipt-cli-'));
        try {
            const jwksPath = join(dir, 'jwks.json');
            writeFileSync(jwksPath, JSON.stringify(jwks));
            // No ATP_MOCK_STORE needed: WRONG_COLLECTION is detected before any getRecord call.
            const res = spawnSync(process.execPath, [cliPath, wrongCollectionUri, '--jwks', jwksPath], {
                encoding: 'utf8',
                env: { ...process.env, ATP_MOCK: '1' },
            });
            assert.equal(res.status, 1, `expected exit 1, got ${res.status}. stdout: ${res.stdout}`);
            assert.ok(res.stderr.includes('WRONG_COLLECTION'), `expected WRONG_COLLECTION in stderr, got:\n${res.stderr}`);
            assert.equal(res.stdout, '', 'no receipt should have been rendered');
        }
        finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
    it('missing --jwks for an at:// URI -> fatal error, exit 1, no crash', () => {
        const res = spawnSync(process.execPath, [cliPath, 'at://did:plc:whatever/dev.scopetrail.auditReceipt/abc123'], { encoding: 'utf8', env: { ...process.env, ATP_MOCK: '1' } });
        assert.equal(res.status, 1);
        assert.ok(res.stderr.toLowerCase().includes('--jwks'), `expected a --jwks error, got:\n${res.stderr}`);
    });
});
//# sourceMappingURL=atproto-cli.test.js.map