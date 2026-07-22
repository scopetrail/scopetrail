// SPDX-License-Identifier: Apache-2.0
/**
 * atproto-pipeline.test.ts — Integration tests for Sprint 03 Task 3
 * (publish + verify-from-`at://` pipeline), run entirely against the in-memory mock PDS.
 *
 * Full loop: mint → publishReceipt → verifyFromUri, plus the tamper/error paths the sprint
 * story calls out explicitly (tampered receiptJson, tampered mirror-only, wrong collection).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractContext } from '../builder.js';
import { generateKeyPair, mintReceipt, NonceStore } from '../signer.js';
import type { RawContextInput } from '../types.js';
import { AtpClient } from '../atproto/client.js';
import { FakeAuth, FAKE_ACCESS_JWT } from '../atproto/auth.js';
import { MockPds, createMockDidResolver, MOCK_TEST_DID, MOCK_PDS_URL } from '../atproto/mock-pds.js';
import { RECEIPT_NSID, rkeyFor, type AtpReceiptRecord } from '../atproto/record.js';
import { publishReceipt } from '../atproto/publish.js';
import { verifyFromUri } from '../atproto/verify-uri.js';

// ── Fixtures ─────────────────────────────────────────────────────────────────

function makeJwt(claims: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `${header}.${payload}.sig`;
}

function makeRawInput(): RawContextInput {
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

/** Fresh client + mock PDS wired to MOCK_TEST_DID, plus the keypair used to mint/verify. */
async function setup() {
  const { privateKey, publicKey } = await generateKeyPair();
  const context = extractContext(makeRawInput());
  const receipt = await mintReceipt(context, privateKey, 'key-1', MOCK_TEST_DID);

  const pds = new MockPds([FAKE_ACCESS_JWT]);
  const auth = new FakeAuth();
  const didResolver = createMockDidResolver({ [MOCK_TEST_DID]: MOCK_PDS_URL });
  const client = new AtpClient({ auth, transport: pds, didResolver });

  // Fresh NonceStore per test — never share the module singleton across independent tests.
  const nonceStore = new NonceStore();

  return { receipt, publicKey, pds, client, nonceStore };
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describe('atproto publish + verify-from-at:// pipeline', () => {
  it('full loop: mint -> publishReceipt -> verifyFromUri -> valid: true, render has principals', async () => {
    const { receipt, publicKey, client, nonceStore } = await setup();

    const uri = await publishReceipt(receipt, client, MOCK_TEST_DID);
    assert.equal(uri, `at://${MOCK_TEST_DID}/${RECEIPT_NSID}/${rkeyFor(receipt)}`);

    const result = await verifyFromUri(uri, client, publicKey, nonceStore);

    assert.equal(result.valid, true);
    assert.deepEqual(result.errors, []);
    assert.deepEqual(result.receipt, receipt);
    assert.ok(result.render, 'expected a rendered receipt');
    assert.ok(result.render!.includes(receipt.delegationContext.rootPrincipal.id), 'render should include root principal');
    assert.ok(result.render!.includes(receipt.credentialSubject.id), 'render should include acting principal (subject)');
    assert.ok(result.render!.includes('VERIFIED'));
  });

  it('tamper A: mutated receiptJson -> valid: false with SIGNATURE_INVALID from the crypto layer', async () => {
    const { receipt, publicKey, pds, client, nonceStore } = await setup();
    const uri = await publishReceipt(receipt, client, MOCK_TEST_DID);
    const rkey = rkeyFor(receipt);

    // Tamper with the signed payload itself, keeping the mirrors consistent with the new
    // (tampered) payload so the mismatch is caught by the crypto layer, not the mirror check.
    const tamperedReceipt = {
      ...receipt,
      delegationContext: {
        ...receipt.delegationContext,
        grantedScopes: [...receipt.delegationContext.grantedScopes, 'write:docs'],
      },
    };
    const tamperedRecord: AtpReceiptRecord = {
      $type: RECEIPT_NSID,
      receiptJson: JSON.stringify(tamperedReceipt),
      issuer: tamperedReceipt.issuer,
      subject: tamperedReceipt.credentialSubject.id,
      issuanceDate: tamperedReceipt.issuanceDate,
      expirationDate: tamperedReceipt.expirationDate,
      summary: tamperedReceipt.summary,
      schemaVersion: 'obo-receipt/v1',
    };
    pds._setRecordValueForTest(MOCK_TEST_DID, RECEIPT_NSID, rkey, tamperedRecord);

    const result = await verifyFromUri(uri, client, publicKey, nonceStore);

    assert.equal(result.valid, false);
    assert.ok(result.errors.includes('SIGNATURE_INVALID'), `expected SIGNATURE_INVALID, got ${result.errors}`);
    assert.ok(result.receipt, 'receipt should still be returned for display');
  });

  it('tamper B: mutated mirror only -> invalid via mirror check, crypto layer never reached', async () => {
    const { receipt, publicKey, pds, client, nonceStore } = await setup();
    const uri = await publishReceipt(receipt, client, MOCK_TEST_DID);
    const rkey = rkeyFor(receipt);

    // receiptJson (the trusted payload) is untouched; only the untrusted indexed mirror is edited.
    const tamperedRecord: AtpReceiptRecord = {
      $type: RECEIPT_NSID,
      receiptJson: JSON.stringify(receipt),
      issuer: 'did:web:attacker.example',
      subject: receipt.credentialSubject.id,
      issuanceDate: receipt.issuanceDate,
      expirationDate: receipt.expirationDate,
      summary: receipt.summary,
      schemaVersion: 'obo-receipt/v1',
    };
    pds._setRecordValueForTest(MOCK_TEST_DID, RECEIPT_NSID, rkey, tamperedRecord);

    const result = await verifyFromUri(uri, client, publicKey, nonceStore);

    assert.equal(result.valid, false);
    assert.deepEqual(result.errors, ['MIRROR_MISMATCH']);
    // Distinct from any verifyReceipt code — proves the crypto layer was never reached.
    assert.ok(!result.errors.includes('SIGNATURE_INVALID'));
    assert.ok(!result.errors.includes('NONCE_REPLAY'));
  });

  it('wrong collection in the URI -> typed error result, not a crash', async () => {
    const { receipt, publicKey, client, nonceStore } = await setup();
    await publishReceipt(receipt, client, MOCK_TEST_DID);
    const rkey = rkeyFor(receipt);

    const wrongCollectionUri = `at://${MOCK_TEST_DID}/app.bsky.feed.post/${rkey}`;

    const result = await verifyFromUri(wrongCollectionUri, client, publicKey, nonceStore);

    assert.equal(result.valid, false);
    assert.deepEqual(result.errors, ['WRONG_COLLECTION']);
    assert.equal(result.receipt, null);
    assert.equal(result.render, null);
  });

  it('malformed at:// URI -> typed error result, not a crash', async () => {
    const { publicKey, client, nonceStore } = await setup();

    const result = await verifyFromUri('not-an-at-uri', client, publicKey, nonceStore);

    assert.equal(result.valid, false);
    assert.deepEqual(result.errors, ['MALFORMED_URI']);
    assert.equal(result.receipt, null);
    assert.equal(result.render, null);
  });

  it('missing record (never published) -> typed RECORD_NOT_FOUND result, not a throw', async () => {
    const { receipt, publicKey, client, nonceStore } = await setup();
    // Never published — but a well-formed URI at the right collection.
    const uri = `at://${MOCK_TEST_DID}/${RECEIPT_NSID}/${rkeyFor(receipt)}`;

    const result = await verifyFromUri(uri, client, publicKey, nonceStore);

    assert.equal(result.valid, false);
    assert.deepEqual(result.errors, ['RECORD_NOT_FOUND']);
    assert.equal(result.receipt, null);
  });
});
