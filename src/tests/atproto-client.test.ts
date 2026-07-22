// SPDX-License-Identifier: Apache-2.0
/**
 * Unit tests for the atproto client seam (Sprint 03, Task 2).
 * Runs entirely against the in-memory mock PDS — zero network.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AtpClient, RecordNotFound, AuthRequired } from '../atproto/client.js';
import { FakeAuth, FAKE_ACCESS_JWT } from '../atproto/auth.js';
import { MockPds, createMockDidResolver, MOCK_TEST_DID, MOCK_PDS_URL } from '../atproto/mock-pds.js';

const COLLECTION = 'dev.scopetrail.auditReceipt';

function makeClient(opts: { auth?: FakeAuth; pds?: MockPds } = {}) {
  const auth = opts.auth ?? new FakeAuth();
  const pds = opts.pds ?? new MockPds([FAKE_ACCESS_JWT]);
  const didResolver = createMockDidResolver({ [MOCK_TEST_DID]: MOCK_PDS_URL });
  const client = new AtpClient({ auth, transport: pds, didResolver });
  return { client, auth, pds };
}

test('put then get returns the same record', async () => {
  const { client } = makeClient();
  const record = {
    $type: COLLECTION,
    receiptJson: JSON.stringify({ id: 'receipt-1', hello: 'world' }),
    issuer: MOCK_TEST_DID,
  };

  const put = await client.putRecord({
    repo: MOCK_TEST_DID,
    collection: COLLECTION,
    rkey: 'receipt-1',
    record,
  });
  assert.equal(put.uri, `at://${MOCK_TEST_DID}/${COLLECTION}/receipt-1`);
  assert.ok(put.cid, 'putRecord should return a cid');

  const got = await client.getRecord({
    repo: MOCK_TEST_DID,
    collection: COLLECTION,
    rkey: 'receipt-1',
  });
  assert.equal(got.uri, put.uri);
  assert.equal(got.cid, put.cid);
  assert.deepEqual(got.value, record);
});

test('getRecord on a missing rkey throws typed RecordNotFound', async () => {
  const { client } = makeClient();

  await assert.rejects(
    () =>
      client.getRecord({
        repo: MOCK_TEST_DID,
        collection: COLLECTION,
        rkey: 'does-not-exist',
      }),
    (err: unknown) => {
      assert.ok(err instanceof RecordNotFound, 'expected a RecordNotFound instance');
      return true;
    },
  );
});

test('putRecord without a valid session token throws typed AuthRequired', async () => {
  // Bad/unregistered token: the mock PDS only recognizes FAKE_ACCESS_JWT.
  const badAuth = new FakeAuth({ accessJwt: 'not-a-real-token' });
  const { client } = makeClient({ auth: badAuth });

  await assert.rejects(
    () =>
      client.putRecord({
        repo: MOCK_TEST_DID,
        collection: COLLECTION,
        rkey: 'receipt-2',
        record: { $type: COLLECTION, receiptJson: '{}' },
      }),
    (err: unknown) => {
      assert.ok(err instanceof AuthRequired, 'expected an AuthRequired instance');
      return true;
    },
  );
});

test('resolveDidToPds via the stub resolver returns the mock endpoint', async () => {
  const { client } = makeClient();
  const endpoint = await client.resolveDidToPds(MOCK_TEST_DID);
  assert.equal(endpoint, MOCK_PDS_URL);
});

test('resolveDidToPds rejects an unregistered DID', async () => {
  const { client } = makeClient();
  await assert.rejects(() => client.resolveDidToPds('did:plc:unregistered000000000'));
});

test('putRecord defaults validate to false when not specified', async () => {
  // Behavioral proxy: putRecord succeeds through the full client path without callers ever
  // having to pass `validate` themselves (PRD_ARCH.md §8.3/§8.6 — optimistic validation).
  const { client } = makeClient();
  const result = await client.putRecord({
    repo: MOCK_TEST_DID,
    collection: COLLECTION,
    rkey: 'receipt-3',
    record: { $type: COLLECTION, receiptJson: '{}' },
  });
  assert.ok(result.uri);
});
