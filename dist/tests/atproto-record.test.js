// SPDX-License-Identifier: Apache-2.0
/**
 * atproto-record.test.ts — Unit tests for Sprint 03 Task 1 (lexicon record builder).
 * Uses Node.js built-in test runner (node:test) — no external test dep required.
 */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { RECEIPT_NSID, SCHEMA_VERSION, buildRecord, parseRecord, verifyMirrors, atUriFor, rkeyFor, } from '../atproto/record.js';
import { extractContext } from '../builder.js';
import { generateKeyPair, mintReceipt } from '../signer.js';
// ── Fixtures ─────────────────────────────────────────────────────────────────
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
// ── Test state (initialized in before()) ──────────────────────────────────────
let receipt;
const issuerDid = 'did:web:receipts.example';
before(async () => {
    const { privateKey } = await generateKeyPair();
    const context = extractContext(makeRawInput());
    receipt = await mintReceipt(context, privateKey, 'key-1', issuerDid);
});
// ── Tests ──────────────────────────────────────────────────────────────────────
describe('buildRecord / parseRecord round-trip', () => {
    it('parseRecord(buildRecord(receipt)) deep-equals the original signed receipt', () => {
        const record = buildRecord(receipt);
        const parsed = parseRecord(record);
        assert.deepEqual(parsed, receipt);
    });
    it('sets $type to RECEIPT_NSID', () => {
        const record = buildRecord(receipt);
        assert.equal(record.$type, RECEIPT_NSID);
        assert.equal(RECEIPT_NSID, 'dev.scopetrail.auditReceipt');
    });
    it('receiptJson is an exact JSON.stringify of the receipt (verbatim, not reshaped)', () => {
        const record = buildRecord(receipt);
        assert.equal(record.receiptJson, JSON.stringify(receipt));
    });
    it('populates indexed mirrors from the receipt', () => {
        const record = buildRecord(receipt);
        assert.equal(record.issuer, receipt.issuer);
        assert.equal(record.subject, receipt.credentialSubject.id);
        assert.equal(record.issuanceDate, receipt.issuanceDate);
        assert.equal(record.expirationDate, receipt.expirationDate);
        assert.equal(record.summary, receipt.summary);
        assert.equal(record.schemaVersion, SCHEMA_VERSION);
        assert.equal(record.schemaVersion, 'obo-receipt/v1');
    });
});
describe('verifyMirrors', () => {
    it('returns true for an honest, untampered record', () => {
        const record = buildRecord(receipt);
        assert.equal(verifyMirrors(record), true);
    });
    it('returns false when the issuer mirror is edited', () => {
        const record = buildRecord(receipt);
        const tampered = { ...record, issuer: 'did:web:attacker.example' };
        assert.equal(verifyMirrors(tampered), false);
    });
    it('returns false when the summary mirror is edited', () => {
        const record = buildRecord(receipt);
        const tampered = { ...record, summary: 'Not the real summary' };
        assert.equal(verifyMirrors(tampered), false);
    });
    it('returns false when the schemaVersion mirror is edited', () => {
        const record = buildRecord(receipt);
        const tampered = { ...record, schemaVersion: 'obo-receipt/v2' };
        assert.equal(verifyMirrors(tampered), false);
    });
    it('returns false (not throw) when receiptJson is unparsable', () => {
        const record = buildRecord(receipt);
        const tampered = { ...record, receiptJson: 'not json at all' };
        assert.equal(verifyMirrors(tampered), false);
    });
});
describe('rkeyFor / atUriFor', () => {
    it('rkeyFor strips the urn:obo-receipt: prefix from receipt.id', () => {
        assert.ok(receipt.id.startsWith('urn:obo-receipt:'));
        const rkey = rkeyFor(receipt);
        assert.equal(rkey, receipt.id.slice('urn:obo-receipt:'.length));
        assert.ok(rkey.length > 0);
        // rkey must not contain characters illegal in atproto record keys
        assert.doesNotMatch(rkey, /[:/]/);
    });
    it('atUriFor produces at://<did>/<RECEIPT_NSID>/<rkey>', () => {
        const uri = atUriFor(issuerDid, receipt);
        assert.equal(uri, `at://${issuerDid}/${RECEIPT_NSID}/${rkeyFor(receipt)}`);
        assert.equal(uri, `at://did:web:receipts.example/dev.scopetrail.auditReceipt/${rkeyFor(receipt)}`);
    });
    it('rkey used in atUriFor is consistent with rkeyFor (publish/addressing agreement)', () => {
        const uri = atUriFor(issuerDid, receipt);
        const rkey = rkeyFor(receipt);
        assert.ok(uri.endsWith(`/${rkey}`));
    });
});
//# sourceMappingURL=atproto-record.test.js.map