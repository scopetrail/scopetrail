#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * publish-receipt-task6.mjs — Sprint 04 Task 6.
 *
 * Adapted from scripts/live-publish-task5.mjs (Sprint 03 Task 5). Two differences that matter:
 *
 *   1. Targets the NEW collection NSID `dev.scopetrail.auditReceipt` — imported from the built
 *      `dist` (never hardcoded here), so this script always agrees with whatever Task 1's
 *      re-namespace actually shipped.
 *   2. The verify step proves the true "no keys" path added in Task 5: the verification key is
 *      resolved by fetching a JWKS **URL** (`resolveKeyFromJwksUrl` via `verifyFromUri`'s
 *      `JwksUrlRef` argument), never handed an in-process `CryptoKey`.
 *
 * Two modes:
 *
 *   --mock (default, or bare `--dry-run`): runs the FULL loop — mint -> build record -> publish
 *     -> verifyFromUri — entirely against the in-memory mock PDS (src/atproto/mock-pds.ts). No
 *     network of any kind. The JWKS "host" is simulated with an injected `fetchFn` serving a
 *     demo JWKS document in the same shape as the committed `.well-known/jwks.json` example.
 *     Asserts `valid: true` and exits non-zero if that assertion fails.
 *
 *   --live: the real thing (Jim only — needs credentials). Requires ATP_PDS, ATP_IDENTIFIER,
 *     ATP_APP_PASSWORD in the environment; missing any of them prints a clear message and exits
 *     non-zero WITHOUT attempting any network call. Optionally reads ATP_JWKS_URL to verify the
 *     freshly published record via the hosted JWKS URL (the true no-keys path); if ATP_JWKS_URL
 *     is not set, the live verify step falls back to the in-process public key (same gap Task 5
 *     closed for the mock path — the live JWKS host is a separate Jim-gated deploy step) and
 *     says so explicitly.
 *
 * Run from the package root (after `npm run build`):
 *   node scripts/publish-receipt-task6.mjs --mock
 *   node scripts/publish-receipt-task6.mjs --live        # Jim only, needs env vars
 */

import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { extractContext } from '../dist/builder.js';
import { generateKeyPair, mintReceipt, buildJwks, exportPublicKeyAsJwk } from '../dist/signer.js';
import { AppPasswordAuth, FakeAuth, FAKE_ACCESS_JWT } from '../dist/atproto/auth.js';
import {
  AtpClient,
  FetchTransport,
  createPlcDidResolver,
} from '../dist/atproto/client.js';
import { MockPds, createMockDidResolver, MOCK_TEST_DID, MOCK_PDS_URL } from '../dist/atproto/mock-pds.js';
import { RECEIPT_NSID } from '../dist/atproto/record.js';
import { publishReceipt } from '../dist/atproto/publish.js';
import { verifyFromUri } from '../dist/atproto/verify-uri.js';

// A demo JWKS URL, styled after the real `.well-known/jwks.json` this repo commits as an
// EXAMPLE (see scripts/emit-jwks.mjs / README "No-keys verification"). Never dialed for real in
// --mock mode — it exists only as the key the injected fetchFn matches against.
const DEMO_JWKS_URL = 'https://scopetrail.dev/.well-known/jwks.json';

function parseArgs(argv) {
  const args = argv.slice(2);
  const live = args.includes('--live');
  // Default is dry-run/mock in every case except an explicit --live (--mock / --dry-run / no
  // flags at all are all equivalent — "safe by default").
  return { live };
}

function must(name) {
  const v = process.env[name];
  if (!v) return null;
  return v;
}

/** Load the persistent issuer keypair written by scripts/generate-issuer-key.mjs.
 * Imports both halves via WebCrypto so the live publish SIGNS with the same key whose public
 * half is hosted at .well-known/jwks.json — the whole point of the keyless verify path. */
async function loadIssuerKey(path) {
  const parsed = JSON.parse(readFileSync(path, 'utf8'));
  if (!parsed.privateJwk || !parsed.publicJwk) {
    throw new Error(`${path} must contain privateJwk and publicJwk (see generate-issuer-key.mjs).`);
  }
  const { subtle } = webcrypto;
  const privateKey = await subtle.importKey('jwk', parsed.privateJwk, { name: 'Ed25519' }, true, ['sign']);
  const publicKey = await subtle.importKey('jwk', parsed.publicJwk, { name: 'Ed25519' }, true, ['verify']);
  return { privateKey, publicKey, kid: parsed.kid ?? 'key-1' };
}

function makeJwt(claims) {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `${header}.${payload}.sig`;
}

function makeRawInput() {
  const now = new Date();
  const exp = new Date(now.getTime() + 3_600_000);
  const jwt1 = makeJwt({ iss: 'https://auth.scopetrail.dev', exp: Math.floor(exp.getTime() / 1000), jti: 'j1' });
  const jwt2 = makeJwt({ iss: 'https://auth.scopetrail.dev', exp: Math.floor(exp.getTime() / 1000), jti: 'j2' });

  return {
    rootPrincipal: { id: 'did:web:scopetrail.dev/users/jim', type: 'human', displayName: 'Jim' },
    hops: [
      {
        delegator: { id: 'did:web:scopetrail.dev/users/jim', type: 'human' },
        delegate: { id: 'did:web:scopetrail.dev/agents/expense-bot', type: 'agent' },
        scopeAtHop: ['read:receipts'],
        rawToken: jwt1,
        tokenType: 'jwt',
        authorizedAt: now.toISOString(),
      },
    ],
    actingPrincipal: { id: 'did:web:scopetrail.dev/agents/expense-bot', type: 'agent', displayName: 'Expense Agent' },
    rawUpstreamToken: jwt2,
    upstreamTokenType: 'jwt',
    grantedScopes: ['read:receipts'],
    audience: ['https://api.scopetrail.dev'],
    action: { verb: 'invoke', resourceUri: 'https://api.scopetrail.dev/expense/process' },
    issuedAt: now.toISOString(),
    expiresAt: exp.toISOString(),
  };
}

/** A no-network stub `fetch` that serves a fixed JWKS document only for a fixed URL — same
 * pattern as src/tests/atproto-jwks.test.ts. Simulates the hosted `.well-known/jwks.json` a real
 * verifier would fetch, with no server actually running. */
function stubFetchServing(url, jwks) {
  return async (input) => {
    const requested = typeof input === 'string' ? input : input.toString();
    if (requested !== url) {
      return { ok: false, status: 404, json: async () => ({}) };
    }
    return { ok: true, status: 200, json: async () => jwks };
  };
}

// ── --mock / --dry-run: full loop against the in-memory mock PDS, no network ──────────────────

async function runMock() {
  console.log('=== Sprint 04 Task 6 — DRY-RUN (--mock) against the in-memory mock PDS ===');
  console.log(`Collection NSID (from dist): ${RECEIPT_NSID}\n`);

  console.log('--- Step 1: mint a receipt ---');
  const { privateKey, publicKey } = await generateKeyPair();
  const context = extractContext(makeRawInput());
  const receipt = await mintReceipt(context, privateKey, 'key-1', MOCK_TEST_DID);
  console.log(`Minted receipt ${receipt.id}`);
  console.log(receipt.summary);

  console.log('\n--- Step 2: build record + publish to the mock PDS ---');
  const pds = new MockPds([FAKE_ACCESS_JWT]);
  const auth = new FakeAuth();
  const didResolver = createMockDidResolver({ [MOCK_TEST_DID]: MOCK_PDS_URL });
  const client = new AtpClient({ auth, transport: pds, didResolver });

  const uri = await publishReceipt(receipt, client, MOCK_TEST_DID);
  console.log(`Published (mock): ${uri}`);
  if (!uri.includes(`/${RECEIPT_NSID}/`)) {
    throw new Error(`Published URI does not carry the expected NSID "${RECEIPT_NSID}": ${uri}`);
  }

  console.log('\n--- Step 3: verify from a fresh call using ONLY the at:// URI + a JWKS URL ---');
  console.log('(no in-process CryptoKey/JsonWebKeySet passed — the Task 5 JWKS-URL resolver');
  console.log(' fetches a demo JWKS document, styled after the committed .well-known/jwks.json,');
  console.log(' via an injected fetchFn; no real network call is made)');

  const jwks = await buildJwks([{ kid: 'key-1', publicKey }]);
  const fetchFn = stubFetchServing(DEMO_JWKS_URL, jwks);

  const result = await verifyFromUri(uri, client, { jwksUrl: DEMO_JWKS_URL, fetchFn });

  console.log(`\nvalid: ${result.valid}`);
  console.log(`errors: ${JSON.stringify(result.errors)}`);
  console.log('\n--- render ---');
  console.log(result.render);

  if (result.valid !== true) {
    console.error('\nFAILED: expected valid: true from the no-keys JWKS-URL verify path.');
    process.exit(1);
  }

  console.log('\n=== SUMMARY ===');
  console.log(`Collection NSID: ${RECEIPT_NSID}`);
  console.log(`at:// URI (mock): ${uri}`);
  console.log(`valid: ${result.valid}`);
  console.log('\nDRY-RUN OK — the real publish (npm publish + a live PDS account) is Jim-gated;');
  console.log('run with --live (+ ATP_PDS/ATP_IDENTIFIER/ATP_APP_PASSWORD) when ready.');
}

// ── --live: the real thing (Jim only) ──────────────────────────────────────────────────────────

async function runLive() {
  const service = must('ATP_PDS');
  const rawIdentifier = must('ATP_IDENTIFIER');
  const appPassword = must('ATP_APP_PASSWORD');

  if (!service || !rawIdentifier || !appPassword) {
    console.error('--live requires ATP_PDS, ATP_IDENTIFIER, and ATP_APP_PASSWORD in the environment.');
    console.error('None of these were used and no network call was attempted.');
    console.error('Missing: ' + [
      !service && 'ATP_PDS',
      !rawIdentifier && 'ATP_IDENTIFIER',
      !appPassword && 'ATP_APP_PASSWORD',
    ].filter(Boolean).join(', '));
    console.error('\nRun the dry-run instead: node scripts/publish-receipt-task6.mjs --mock');
    process.exit(1);
  }

  const identifier = rawIdentifier.replace(/^@/, ''); // atproto identifiers don't take a leading '@'
  const jwksUrl = must('ATP_JWKS_URL'); // optional — the hosted JWKS host is a separate Jim-gated deploy step
  const issuerKeyPath = must('ATP_ISSUER_KEY'); // persistent issuer key (scripts/generate-issuer-key.mjs)

  // Fail fast (before any network auth) on the one combo that can never verify: a hosted JWKS
  // URL to check against, but no persistent key to sign with — a throwaway key would never match.
  if (jwksUrl && !issuerKeyPath) {
    console.error('ATP_JWKS_URL is set but ATP_ISSUER_KEY is not — a hosted JWKS can never match a');
    console.error('throwaway key. Set ATP_ISSUER_KEY to the persistent issuer key');
    console.error('(scripts/generate-issuer-key.mjs) and re-run. No network call was attempted.');
    process.exit(1);
  }

  console.log('=== Sprint 04 Task 6 — LIVE publish under the new NSID ===');
  console.log(`Collection NSID (from dist): ${RECEIPT_NSID}\n`);

  console.log('--- Step 1: authenticate + resolve issuer DID ---');
  const auth = new AppPasswordAuth({ service, identifier, appPassword });
  const session = await auth.session();
  const issuerDid = session.did;
  console.log(`Authenticated as ${identifier} -> ${issuerDid}`);

  console.log('\n--- Step 2: mint a receipt ---');
  let privateKey, publicKey, mintKid;
  if (issuerKeyPath) {
    ({ privateKey, publicKey, kid: mintKid } = await loadIssuerKey(issuerKeyPath));
    console.log(`Signing with the persistent issuer key from ${issuerKeyPath} (kid: ${mintKid})`);
  } else {
    // No persistent key: legacy throwaway behavior. (The jwksUrl-without-key combo was already
    // rejected up front, so reaching here means no hosted JWKS to match against.)
    ({ privateKey, publicKey } = await generateKeyPair());
    mintKid = 'key-1';
    console.log('ATP_ISSUER_KEY not set — signing with a THROWAWAY key (legacy behavior);');
    console.log('keyless verify against a hosted JWKS will NOT match.');
  }
  const context = extractContext(makeRawInput());
  const receipt = await mintReceipt(context, privateKey, mintKid, issuerDid);
  console.log(`Minted receipt ${receipt.id}`);
  console.log(receipt.summary);

  console.log('\n--- Step 3: publish to the real PDS ---');
  const publishClient = new AtpClient({
    auth,
    transport: new FetchTransport(),
    didResolver: createPlcDidResolver(),
  });
  const uri = await publishReceipt(receipt, publishClient, issuerDid);
  console.log(`Published: ${uri}`);
  if (!uri.includes(`/${RECEIPT_NSID}/`)) {
    throw new Error(`Published URI does not carry the expected NSID "${RECEIPT_NSID}": ${uri}`);
  }

  console.log('\n--- Step 4: verify from a fresh client using only the at:// URI ---');
  const verifyAuth = new AppPasswordAuth({ service, identifier, appPassword });
  const verifyClient = new AtpClient({
    auth: verifyAuth,
    transport: new FetchTransport(),
    didResolver: createPlcDidResolver(),
  });

  let result;
  if (jwksUrl) {
    console.log(`Resolving the verification key from the hosted JWKS URL (true no-keys path): ${jwksUrl}`);
    result = await verifyFromUri(uri, verifyClient, { jwksUrl });
  } else {
    console.log('ATP_JWKS_URL not set — falling back to the in-process public key.');
    console.log('(hosting /.well-known/jwks.json is a separate Jim-gated deploy step — see README');
    console.log(' "No-keys verification"; set ATP_JWKS_URL and re-run to prove the URL-only path.)');
    result = await verifyFromUri(uri, verifyClient, publicKey);
  }

  console.log(`\nvalid: ${result.valid}`);
  console.log(`errors: ${JSON.stringify(result.errors)}`);
  console.log('\n--- render ---');
  console.log(result.render);

  console.log('\n--- Public key (JWK, for reference) ---');
  console.log(JSON.stringify(await exportPublicKeyAsJwk(publicKey)));

  console.log('\n=== SUMMARY ===');
  console.log(`Collection NSID: ${RECEIPT_NSID}`);
  console.log(`at:// URI: ${uri}`);
  console.log(`valid: ${result.valid}`);
  console.log('\nThis URI supersedes the Sprint 03 live URI (old NSID). Record it in the project note.');
}

async function main() {
  const { live } = parseArgs(process.argv);

  if (live) {
    await runLive();
    return;
  }

  await runMock();
}

main().catch((err) => {
  console.error('FAILED:', err);
  process.exit(1);
});
