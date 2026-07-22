// SPDX-License-Identifier: Apache-2.0
/**
 * atproto-jwks.test.ts — Sprint 04 Task 5: fetch-by-URL JWKS resolution.
 *
 * Two layers, entirely against injected fetch stubs — no real network:
 *   1. Unit tests directly against src/atproto/jwks.ts (`fetchJwks`, `selectAndImportKey`,
 *      `resolveKeyFromJwksUrl`).
 *   2. The integration case the sprint story calls out explicitly: mint -> publish (mock PDS)
 *      -> `verifyFromUri` using ONLY the `at://` URI + a JWKS URL (a `JwksUrlRef` with an
 *      injected `fetchFn`) -> `valid: true`, with no in-process `CryptoKey`/`JsonWebKeySet`
 *      passed anywhere in the call. A negative test covers a wrong/missing kid in the served
 *      JWKS -> typed `KEY_IMPORT_FAILED`, not a crash.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractContext } from '../builder.js';
import { generateKeyPair, mintReceipt, buildJwks, NonceStore } from '../signer.js';
import type { RawContextInput } from '../types.js';
import { AtpClient } from '../atproto/client.js';
import { FakeAuth, FAKE_ACCESS_JWT } from '../atproto/auth.js';
import { MockPds, createMockDidResolver, MOCK_TEST_DID, MOCK_PDS_URL } from '../atproto/mock-pds.js';
import { publishReceipt } from '../atproto/publish.js';
import { verifyFromUri, type JsonWebKeySet } from '../atproto/verify-uri.js';
import { fetchJwks, selectAndImportKey, resolveKeyFromJwksUrl, JwksFetchError } from '../atproto/jwks.js';

const DEMO_JWKS_URL = 'https://scopetrail.example/.well-known/jwks.json';

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

/** A no-network stub `fetch` that serves a fixed JWKS document only for a fixed URL. */
function stubFetchServing(
  url: string,
  jwks: JsonWebKeySet,
  calls: { count: number }
): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    calls.count++;
    const requested = typeof input === 'string' ? input : input.toString();
    if (requested !== url) {
      return { ok: false, status: 404, json: async () => ({}) } as unknown as Response;
    }
    return { ok: true, status: 200, json: async () => jwks } as unknown as Response;
  }) as typeof fetch;
}

/** Fresh mock-PDS client + a minted, mock-published receipt, plus its JWKS (kid: 'key-1'). */
async function setup() {
  const { privateKey, publicKey } = await generateKeyPair();
  const context = extractContext(makeRawInput());
  const receipt = await mintReceipt(context, privateKey, 'key-1', MOCK_TEST_DID);

  const pds = new MockPds([FAKE_ACCESS_JWT]);
  const auth = new FakeAuth();
  const didResolver = createMockDidResolver({ [MOCK_TEST_DID]: MOCK_PDS_URL });
  const client = new AtpClient({ auth, transport: pds, didResolver });

  const jwks = await buildJwks([{ kid: 'key-1', publicKey }]);
  const nonceStore = new NonceStore();

  return { receipt, publicKey, jwks, client, nonceStore };
}

// ── Unit tests: src/atproto/jwks.ts ────────────────────────────────────────────

describe('jwks.ts — fetch-by-URL JWKS resolution (unit)', () => {
  it('fetchJwks: parses a well-formed JWKS response via the injected fetchFn', async () => {
    const { publicKey } = await generateKeyPair();
    const jwks = await buildJwks([{ kid: 'key-1', publicKey }]);
    const calls = { count: 0 };
    const fetchFn = stubFetchServing(DEMO_JWKS_URL, jwks, calls);

    const fetched = await fetchJwks(DEMO_JWKS_URL, fetchFn);

    assert.deepEqual(fetched, jwks);
    assert.equal(calls.count, 1);
  });

  it('fetchJwks: non-OK HTTP status -> typed JwksFetchError, not a crash', async () => {
    const fetchFn = (async () =>
      ({ ok: false, status: 500, json: async () => ({}) }) as unknown as Response) as typeof fetch;

    await assert.rejects(
      () => fetchJwks(DEMO_JWKS_URL, fetchFn),
      (err: unknown) => {
        assert.ok(err instanceof JwksFetchError, 'expected a JwksFetchError instance');
        return true;
      }
    );
  });

  it('fetchJwks: response missing a "keys" array -> typed JwksFetchError', async () => {
    const fetchFn = (async () =>
      ({ ok: true, status: 200, json: async () => ({ notKeys: [] }) }) as unknown as Response) as typeof fetch;

    await assert.rejects(
      () => fetchJwks(DEMO_JWKS_URL, fetchFn),
      (err: unknown) => {
        assert.ok(err instanceof JwksFetchError, 'expected a JwksFetchError instance');
        return true;
      }
    );
  });

  it('fetchJwks: fetch itself throws (network error) -> typed JwksFetchError, not a crash', async () => {
    const fetchFn = (async () => {
      throw new Error('simulated DNS/connect failure');
    }) as unknown as typeof fetch;

    await assert.rejects(
      () => fetchJwks(DEMO_JWKS_URL, fetchFn),
      (err: unknown) => {
        assert.ok(err instanceof JwksFetchError, 'expected a JwksFetchError instance');
        return true;
      }
    );
  });

  it('selectAndImportKey: matches by kid and imports a usable verification CryptoKey', async () => {
    const { publicKey } = await generateKeyPair();
    const jwks = await buildJwks([{ kid: 'key-1', publicKey }]);

    const imported = await selectAndImportKey(jwks, 'key-1');
    assert.ok(imported, 'expected a CryptoKey');
    assert.equal(imported!.type, 'public');
  });

  it('selectAndImportKey: wrong kid -> null (typed "not found"), not a throw', async () => {
    const { publicKey } = await generateKeyPair();
    const jwks = await buildJwks([{ kid: 'key-1', publicKey }]);

    const imported = await selectAndImportKey(jwks, 'no-such-kid');
    assert.equal(imported, null);
  });

  it('selectAndImportKey: empty keys array -> null, not a throw', async () => {
    const imported = await selectAndImportKey({ keys: [] }, 'key-1');
    assert.equal(imported, null);
  });

  it('resolveKeyFromJwksUrl: end-to-end fetch + select + import, via injected fetchFn', async () => {
    const { publicKey } = await generateKeyPair();
    const jwks = await buildJwks([{ kid: 'key-1', publicKey }]);
    const calls = { count: 0 };
    const fetchFn = stubFetchServing(DEMO_JWKS_URL, jwks, calls);

    const imported = await resolveKeyFromJwksUrl(DEMO_JWKS_URL, 'did:plc:issuer#key-1', fetchFn);

    assert.ok(imported, 'expected a CryptoKey');
    assert.equal(calls.count, 1);
  });
});

// ── Integration: verifyFromUri with a JWKS URL (Sprint 04 Task 5) ────────────

describe('verifyFromUri with a JWKS URL — true no-keys verification (Sprint 04 Task 5)', () => {
  it('mint -> publish (mock PDS) -> verifyFromUri with ONLY the at:// URI + a JWKS URL -> valid:true', async () => {
    const { receipt, jwks, client, nonceStore } = await setup();
    const uri = await publishReceipt(receipt, client, MOCK_TEST_DID);

    const calls = { count: 0 };
    const fetchFn = stubFetchServing(DEMO_JWKS_URL, jwks, calls);

    // The critical call: no in-process CryptoKey or JsonWebKeySet is passed here at all — only
    // { jwksUrl, fetchFn }. The verification key is entirely resolved by fetching the URL.
    const result = await verifyFromUri(uri, client, { jwksUrl: DEMO_JWKS_URL, fetchFn }, nonceStore);

    assert.equal(result.valid, true);
    assert.deepEqual(result.errors, []);
    assert.deepEqual(result.receipt, receipt);
    assert.ok(result.render && result.render.includes('VERIFIED'));
    assert.equal(
      calls.count,
      1,
      'expected the injected fetchFn to have been called exactly once to resolve the JWKS'
    );
  });

  it('wrong kid in the served JWKS -> typed KEY_IMPORT_FAILED, not a crash', async () => {
    const { receipt, client, nonceStore } = await setup2WithSigningKid('key-1');
    const uri = await publishReceipt(receipt, client, MOCK_TEST_DID);

    // A JWKS that HAS keys, but none under the kid the receipt's proof.verificationMethod
    // expects ('key-1') — simulates a hosted JWKS that has rotated the key away.
    const { publicKey: unrelatedPublicKey } = await generateKeyPair();
    const wrongJwks = await buildJwks([{ kid: 'key-9-not-the-signer', publicKey: unrelatedPublicKey }]);
    const fetchFn = stubFetchServing(DEMO_JWKS_URL, wrongJwks, { count: 0 });

    const result = await verifyFromUri(uri, client, { jwksUrl: DEMO_JWKS_URL, fetchFn }, nonceStore);

    assert.equal(result.valid, false);
    assert.deepEqual(result.errors, ['KEY_IMPORT_FAILED']);
    assert.ok(result.receipt, 'receipt should still be returned for display');
  });

  it('missing/empty keys array in the served JWKS -> typed KEY_IMPORT_FAILED, not a crash', async () => {
    const { receipt, client, nonceStore } = await setup();
    const uri = await publishReceipt(receipt, client, MOCK_TEST_DID);

    const emptyJwks: JsonWebKeySet = { keys: [] };
    const fetchFn = stubFetchServing(DEMO_JWKS_URL, emptyJwks, { count: 0 });

    const result = await verifyFromUri(uri, client, { jwksUrl: DEMO_JWKS_URL, fetchFn }, nonceStore);

    assert.equal(result.valid, false);
    assert.deepEqual(result.errors, ['KEY_IMPORT_FAILED']);
  });

  it('JWKS URL fetch fails (network error) -> typed KEY_IMPORT_FAILED, not a crash', async () => {
    const { receipt, client, nonceStore } = await setup();
    const uri = await publishReceipt(receipt, client, MOCK_TEST_DID);

    const failingFetchFn = (async () => {
      throw new Error('simulated network failure');
    }) as unknown as typeof fetch;

    const result = await verifyFromUri(
      uri,
      client,
      { jwksUrl: 'https://unreachable.example/.well-known/jwks.json', fetchFn: failingFetchFn },
      nonceStore
    );

    assert.equal(result.valid, false);
    assert.deepEqual(result.errors, ['KEY_IMPORT_FAILED']);
  });
});

/** Same as `setup()`, but with an explicit signing kid, so the wrong-kid test's intent reads clearly. */
async function setup2WithSigningKid(signingKid: string) {
  const { privateKey } = await generateKeyPair();
  const context = extractContext(makeRawInput());
  const receipt = await mintReceipt(context, privateKey, signingKid, MOCK_TEST_DID);

  const pds = new MockPds([FAKE_ACCESS_JWT]);
  const auth = new FakeAuth();
  const didResolver = createMockDidResolver({ [MOCK_TEST_DID]: MOCK_PDS_URL });
  const client = new AtpClient({ auth, transport: pds, didResolver });

  const nonceStore = new NonceStore();
  return { receipt, client, nonceStore };
}
