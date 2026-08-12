#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * mint-demo-receipt.mjs — Sprint 06: re-mint the public launch-demo receipt.
 *
 * The currently-published live demo receipt
 * (at://did:plc:bty3gmskhla7rwblq5zl5jm5/dev.scopetrail.auditReceipt/00MRWDSX7S17169627C414A4FB6605)
 * has three defects found in review:
 *
 *   (a) it expired 2026-07-22 (minted with a 1-hour TTL) — verification now returns
 *       `valid: false`, `RECEIPT_EXPIRED`.
 *   (b) it is single-hop, while the launch narrative is explicitly multi-hop
 *       ("Four agents, three hops, one human authorization at the top").
 *   (c) its `@context` carried the dead pre-rename domain
 *       `https://schemas.delegation-receipts.dev/v1/obo-receipt.jsonld`. That URL is baked into
 *       `OBO_CONTEXTS` in `src/signer.ts` (and thence `dist/signer.js`), so re-minting alone
 *       could not repair it. **Fixed 2026-08-11:** `OBO_CONTEXTS` now points at
 *       `https://scopetrail.github.io/contexts/obo-receipt/v1.jsonld`, served from the Pages
 *       site. Rebuild (`npm run build`) before running --live so dist/ carries the new URL.
 *
 * This script mints a new receipt that:
 *   - is genuinely multi-hop: human (Jim) -> orchestrator (service) -> agent -> tool (service),
 *     matching the launch post's "human -> orchestrator -> agent -> tool" chain description
 *   - shows real scope attenuation at each hop (3 scopes -> 2 -> 1), never widening
 *   - describes an ALLOWED final action (a payment invocation within the final hop's scope cap)
 *   - carries a ~1-year TTL so it won't expire again before the next planned rotation
 *   - signs with the persistent issuer key (`keys/issuer-private.jwk.json`, kid `key-1`) whose
 *     public half is already hosted at https://scopetrail.github.io/.well-known/jwks.json — so
 *     the existing hosted JWKS keeps working with no redeploy needed
 *
 * Two modes, same convention as scripts/publish-receipt-task6.mjs and
 * scripts/publish-lexicon-record.mjs:
 *
 *   --mock (default): full loop — mint -> build record -> publish -> read back (canonicalized
 *     comparison, see `deepEqual` below and the DAG-CBOR key-reordering note in
 *     scripts/publish-lexicon-record.mjs) -> verifyFromUri — entirely against the in-memory mock
 *     PDS (src/atproto/mock-pds.ts). No network of any kind. Also writes the signed receipt to
 *     `scripts/.demo-receipt.mock.json` (gitignore-worthy scratch output, not a repo source file)
 *     so `dist/cli/view-receipt.js` can be run against it directly as a second, independent
 *     rendering check. Asserts `valid: true` and exits non-zero if that assertion fails.
 *
 *   --live: the real thing (Jim only — needs credentials). Requires ATP_PDS, ATP_IDENTIFIER,
 *     ATP_APP_PASSWORD in the environment; missing any of them prints a clear message and exits
 *     non-zero WITHOUT attempting any network call. Signs with ATP_ISSUER_KEY if set, else falls
 *     back to `keys/issuer-private.jwk.json` in the repo root (the persistent key already backing
 *     the hosted JWKS) if present, else a throwaway key (with a loud warning — a throwaway key
 *     will NOT verify against the hosted JWKS).
 *
 * Run from the package root (after `npm run build`, if dist/ is stale):
 *   node scripts/mint-demo-receipt.mjs --mock
 *   node scripts/mint-demo-receipt.mjs --live        # Jim only, needs env vars
 *
 * Prints the resulting at:// URI and rkey on success in both modes.
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { extractContext } from '../dist/builder.js';
import { generateKeyPair, mintReceipt, buildJwks, exportPublicKeyAsJwk } from '../dist/signer.js';
import { AppPasswordAuth, FakeAuth, FAKE_ACCESS_JWT } from '../dist/atproto/auth.js';
import { AtpClient, FetchTransport, createPlcDidResolver } from '../dist/atproto/client.js';
import { MockPds, createMockDidResolver, MOCK_TEST_DID, MOCK_PDS_URL } from '../dist/atproto/mock-pds.js';
import { RECEIPT_NSID } from '../dist/atproto/record.js';
import { publishReceipt } from '../dist/atproto/publish.js';
import { verifyFromUri } from '../dist/atproto/verify-uri.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..');
const DEFAULT_ISSUER_KEY_PATH = join(REPO_ROOT, 'keys', 'issuer-private.jwk.json');
const MOCK_RECEIPT_OUT = join(__dirname, '.demo-receipt.mock.json');

// The real hosted JWKS location, per the launch post ("the issuer's public key is hosted at
// https://scopetrail.github.io/.well-known/jwks.json"). Only ever fetched via an injected stub
// in --mock mode; --live mode only touches it if ATP_JWKS_URL is explicitly set.
const HOSTED_JWKS_URL = 'https://scopetrail.github.io/.well-known/jwks.json';

function parseArgs(argv) {
  const args = argv.slice(2);
  const live = args.includes('--live');
  return { live };
}

function must(name) {
  const v = process.env[name];
  return v || null;
}

/** Same loader as publish-receipt-task6.mjs — imports both halves of a persisted issuer keypair. */
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

/**
 * The demo chain: human (Jim) -> orchestrator -> agent -> tool, 3 hops / 4 principals, matching
 * the launch post's "every hop (human -> orchestrator -> agent -> tool)" line. Scope attenuates
 * at every hop (never widens): 3 scopes at hop 1, 2 at hop 2, 1 at hop 3. The final action (a
 * $412.50 reimbursement payment) is within the final hop's `approve:payment:upto:500` cap, i.e.
 * an ALLOWED action — verifyReceipt has no separate allow/deny field (see report), so "allowed"
 * here means: an ordinary, in-scope action, so the receipt verifies clean (`valid: true`) rather
 * than exercising the chain/scope-violation error paths.
 */
function makeRawInput() {
  const now = new Date();
  const oneYearMs = 365 * 24 * 60 * 60 * 1000;
  const exp = new Date(now.getTime() + oneYearMs);

  const t = (offsetMs) => new Date(now.getTime() + offsetMs).toISOString();
  const tokenExp = new Date(now.getTime() + 3_600_000); // per-hop JWTs carry a short session expiry; the receipt's own TTL is independent

  const jwtHop1 = makeJwt({ iss: 'https://auth.scopetrail.dev', exp: Math.floor(tokenExp.getTime() / 1000), jti: 'demo-hop-1' });
  const jwtHop2 = makeJwt({ iss: 'https://auth.scopetrail.dev', exp: Math.floor(tokenExp.getTime() / 1000), jti: 'demo-hop-2' });
  const jwtHop3 = makeJwt({ iss: 'https://auth.scopetrail.dev', exp: Math.floor(tokenExp.getTime() / 1000), jti: 'demo-hop-3' });
  const jwtUpstream = makeJwt({ iss: 'https://auth.scopetrail.dev', exp: Math.floor(tokenExp.getTime() / 1000), jti: 'demo-upstream' });

  const jim = { id: 'did:web:scopetrail.dev:users:jim', type: 'human', displayName: 'Jim' };
  const orchestrator = {
    id: 'did:web:scopetrail.dev:services:expense-orchestrator',
    type: 'service',
    displayName: 'Expense Orchestrator',
  };
  const agent = {
    id: 'did:web:scopetrail.dev:agents:expense-agent',
    type: 'agent',
    displayName: 'Expense Agent',
  };
  const tool = {
    id: 'did:web:scopetrail.dev:tools:payment-api',
    type: 'service',
    displayName: 'Payment Tool',
  };

  const fullScopes = ['read:expense-reports', 'invoke:reimbursement', 'approve:payment:upto:500'];

  return {
    rootPrincipal: jim,
    hops: [
      {
        delegator: jim,
        delegate: orchestrator,
        scopeAtHop: fullScopes, // hop 1: full grant passed straight through to the orchestrator
        rawToken: jwtHop1,
        tokenType: 'jwt',
        authorizedAt: t(0),
      },
      {
        delegator: orchestrator,
        delegate: agent,
        scopeAtHop: ['invoke:reimbursement', 'approve:payment:upto:500'], // hop 2: drop read — the agent doesn't need to read the report, only process it
        rawToken: jwtHop2,
        tokenType: 'jwt',
        authorizedAt: t(60_000), // +1 min
      },
      {
        delegator: agent,
        delegate: tool,
        scopeAtHop: ['approve:payment:upto:500'], // hop 3: drop invoke:reimbursement — the tool only ever executes the payment step
        rawToken: jwtHop3,
        tokenType: 'jwt',
        authorizedAt: t(120_000), // +2 min
      },
    ],
    actingPrincipal: tool,
    rawUpstreamToken: jwtUpstream,
    upstreamTokenType: 'jwt',
    grantedScopes: fullScopes,
    audience: ['https://api.scopetrail.dev/expense'],
    action: {
      verb: 'invoke',
      resourceUri: 'https://api.scopetrail.dev/expense/reimbursements/RPT-48213/pay',
      parameters: { amount: 412.5, currency: 'USD' },
      metadata: { correlationId: 'demo-launch-2026-07-25', environment: 'demo' },
    },
    issuedAt: now.toISOString(),
    expiresAt: exp.toISOString(),
  };
}

/** Same canonicalized structural-equality helper as publish-lexicon-record.mjs — a live PDS
 * round-trips records through DAG-CBOR, which reorders object keys (sorted by length then
 * bytewise) even though the bytes are unchanged. A naive JSON.stringify(a) === JSON.stringify(b)
 * false-fails on a correct live publish; this compares canonicalized (key-sorted) forms instead.
 * Arrays are left in insertion order — order is significant there (e.g. delegationChain, scopes). */
function canonicalizeForCompare(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalizeForCompare);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((k) => [k, canonicalizeForCompare(value[k])])
    );
  }
  return value;
}

function deepEqual(a, b) {
  return JSON.stringify(canonicalizeForCompare(a)) === JSON.stringify(canonicalizeForCompare(b));
}

/** No-network stub `fetch` serving a fixed JWKS document only for a fixed URL (same pattern as
 * scripts/publish-receipt-task6.mjs / src/tests/atproto-jwks.test.ts). */
function stubFetchServing(url, jwks) {
  return async (input) => {
    const requested = typeof input === 'string' ? input : input.toString();
    if (requested !== url) {
      return { ok: false, status: 404, json: async () => ({}) };
    }
    return { ok: true, status: 200, json: async () => jwks };
  };
}

async function resolveSigningKey({ requireHosted }) {
  if (existsSync(DEFAULT_ISSUER_KEY_PATH)) {
    const { privateKey, publicKey, kid } = await loadIssuerKey(DEFAULT_ISSUER_KEY_PATH);
    console.log(`Signing with the persistent issuer key: ${DEFAULT_ISSUER_KEY_PATH} (kid: ${kid})`);
    console.log('(this is the same key already hosted at ' + HOSTED_JWKS_URL + ' — no JWKS redeploy needed)');
    return { privateKey, publicKey, kid, source: 'persistent' };
  }
  if (requireHosted) {
    throw new Error(
      `Persistent issuer key not found at ${DEFAULT_ISSUER_KEY_PATH} — cannot sign a receipt that ` +
        `will verify against the hosted JWKS. Set ATP_ISSUER_KEY or restore the key file.`
    );
  }
  console.log('WARNING: persistent issuer key not found — signing with a THROWAWAY key.');
  console.log('A throwaway key will NOT verify against the real hosted JWKS.');
  const { privateKey, publicKey } = await generateKeyPair();
  return { privateKey, publicKey, kid: 'key-1', source: 'throwaway' };
}

// ── --mock (default): full loop against the in-memory mock PDS, no network ────────────────────

async function runMock() {
  console.log('=== mint-demo-receipt — DRY-RUN (--mock) against the in-memory mock PDS ===');
  console.log(`Collection NSID (from dist): ${RECEIPT_NSID}\n`);

  console.log('--- Step 1: mint the multi-hop demo receipt ---');
  const { privateKey, publicKey, kid, source } = await resolveSigningKey({ requireHosted: false });
  const context = extractContext(makeRawInput());
  const receipt = await mintReceipt(context, privateKey, kid, MOCK_TEST_DID);
  console.log(`Minted receipt ${receipt.id}`);
  console.log(receipt.summary);
  console.log(`Chain depth: ${receipt.delegationContext.delegationChain.length} hops`);
  console.log(`expirationDate: ${receipt.expirationDate}  (TTL ~1 year from issuance)`);

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

  console.log('\n--- Step 3: read the record back and verify it round-trips unchanged ---');
  console.log('(canonicalized/key-order-insensitive comparison — see file header re: DAG-CBOR reordering');
  console.log(' on a live PDS; the mock PDS happens to preserve insertion order, but this checks the same');
  console.log(' way --live does, so a real structural mismatch would still be caught here.)');
  const rkey = uri.split('/').pop();
  const got = await client.getRecord({ repo: MOCK_TEST_DID, collection: RECEIPT_NSID, rkey });
  const sentRecord = { ...got.value }; // the record as stored is what we compare against itself here;
  // the meaningful round-trip check is receiptJson parsing back to an identical receipt object:
  const roundTripOk =
    deepEqual(JSON.parse(got.value.receiptJson), receipt) && typeof got.value.receiptJson === 'string';
  console.log(`Round-trip match (parsed receiptJson === minted receipt): ${roundTripOk}`);
  if (!roundTripOk) {
    console.error('FAILED: round-tripped receiptJson does not match the minted receipt.');
    process.exit(1);
  }
  void sentRecord;

  console.log('\n--- Step 4: verify from a fresh call using ONLY the at:// URI + a JWKS URL ---');
  console.log(`(styled after the real hosted JWKS at ${HOSTED_JWKS_URL}; served here via an`);
  console.log(' injected fetchFn — no real network call is made)');

  const jwks = await buildJwks([{ kid, publicKey }]);
  const fetchFn = stubFetchServing(HOSTED_JWKS_URL, jwks);

  const result = await verifyFromUri(uri, client, { jwksUrl: HOSTED_JWKS_URL, fetchFn });

  console.log(`\nvalid: ${result.valid}`);
  console.log(`errors: ${JSON.stringify(result.errors)}`);
  console.log('\n--- render (from verifyFromUri) ---');
  console.log(result.render);

  if (result.valid !== true) {
    console.error('\nFAILED: expected valid: true from the no-keys JWKS-URL verify path.');
    process.exit(1);
  }

  console.log('\n--- Step 5: independent render via the actual view-receipt CLI ---');
  writeFileSync(MOCK_RECEIPT_OUT, JSON.stringify(receipt, null, 2) + '\n');
  // The CLI's --jwks expects a JWKS document ({ keys: [...] }), not the {kid, publicJwk} shape
  // keys/issuer-public.jwk.json uses. The committed .well-known/jwks.json is already in JWKS
  // shape and (when signing with the persistent key) matches the key that signed this receipt;
  // fall back to a freshly-built JWKS file next to the receipt otherwise (e.g. throwaway-key path).
  const hostedJwksFile = join(REPO_ROOT, '.well-known', 'jwks.json');
  let cliJwksArgFile = join(__dirname, '.demo-receipt.mock.jwks.json');
  if (source === 'persistent' && existsSync(hostedJwksFile)) {
    cliJwksArgFile = hostedJwksFile;
  } else {
    writeFileSync(cliJwksArgFile, JSON.stringify(jwks, null, 2) + '\n');
  }
  try {
    const cliOut = execFileSync(
      process.execPath,
      [join(REPO_ROOT, 'dist', 'cli', 'view-receipt.js'), MOCK_RECEIPT_OUT, '--jwks', cliJwksArgFile],
      { encoding: 'utf8' }
    );
    console.log(cliOut);
  } catch (e) {
    // execFileSync throws on non-zero exit; the CLI exits 1 on invalid/verification-failed, but
    // we already asserted valid:true above, so surface stdout/stderr either way for the report.
    if (e.stdout) console.log(e.stdout);
    if (e.stderr) console.error(e.stderr);
    throw e;
  }

  console.log('=== SUMMARY ===');
  console.log(`Collection NSID: ${RECEIPT_NSID}`);
  console.log(`at:// URI (mock): ${uri}`);
  console.log(`rkey: ${rkey}`);
  console.log(`valid: ${result.valid}`);
  console.log(`Receipt JSON written to: ${MOCK_RECEIPT_OUT}`);
  console.log('\nDRY-RUN OK — the real publish (a live PDS account) is Jim-gated; run with --live');
  console.log('(+ ATP_PDS/ATP_IDENTIFIER/ATP_APP_PASSWORD) when ready.');
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
    console.error('\nRun the dry-run instead: node scripts/mint-demo-receipt.mjs --mock');
    process.exit(1);
  }

  const identifier = rawIdentifier.replace(/^@/, '');
  const jwksUrl = must('ATP_JWKS_URL'); // optional — set to HOSTED_JWKS_URL to prove the true no-keys path
  const issuerKeyOverride = must('ATP_ISSUER_KEY'); // optional override of the default persistent key path

  console.log('=== mint-demo-receipt — LIVE re-mint of the public launch-demo receipt ===');
  console.log(`Collection NSID (from dist): ${RECEIPT_NSID}\n`);

  console.log('--- Step 1: authenticate + resolve issuer DID ---');
  const auth = new AppPasswordAuth({ service, identifier, appPassword });
  const session = await auth.session();
  const issuerDid = session.did;
  console.log(`Authenticated as ${identifier} -> ${issuerDid}`);

  console.log('\n--- Step 2: mint the multi-hop demo receipt ---');
  let privateKey, publicKey, kid;
  if (issuerKeyOverride) {
    ({ privateKey, publicKey, kid } = await loadIssuerKey(issuerKeyOverride));
    console.log(`Signing with ATP_ISSUER_KEY: ${issuerKeyOverride} (kid: ${kid})`);
  } else {
    ({ privateKey, publicKey, kid } = await resolveSigningKey({ requireHosted: false }));
  }
  const context = extractContext(makeRawInput());
  const receipt = await mintReceipt(context, privateKey, kid, issuerDid);
  console.log(`Minted receipt ${receipt.id}`);
  console.log(receipt.summary);
  console.log(`Chain depth: ${receipt.delegationContext.delegationChain.length} hops`);
  console.log(`expirationDate: ${receipt.expirationDate}  (TTL ~1 year from issuance)`);

  console.log('\n--- Step 3: publish to the real PDS ---');
  const publishClient = new AtpClient({
    auth,
    transport: new FetchTransport(),
    didResolver: createPlcDidResolver(),
  });
  const uri = await publishReceipt(receipt, publishClient, issuerDid);
  const rkey = uri.split('/').pop();
  console.log(`Published: ${uri}`);
  if (!uri.includes(`/${RECEIPT_NSID}/`)) {
    throw new Error(`Published URI does not carry the expected NSID "${RECEIPT_NSID}": ${uri}`);
  }

  console.log('\n--- Step 4: read the record back and verify it round-trips unchanged ---');
  console.log('(canonicalized/key-order-insensitive comparison — a live PDS reorders object keys via');
  console.log(' DAG-CBOR on round-trip even though the bytes are unchanged; see script header.)');
  const verifyReadClient = new AtpClient({
    auth: new AppPasswordAuth({ service, identifier, appPassword }),
    transport: new FetchTransport(),
    didResolver: createPlcDidResolver(),
  });
  const got = await verifyReadClient.getRecord({ repo: issuerDid, collection: RECEIPT_NSID, rkey });
  const roundTripOk = deepEqual(JSON.parse(got.value.receiptJson), receipt);
  console.log(`Round-trip match (parsed receiptJson === minted receipt): ${roundTripOk}`);
  if (!roundTripOk) {
    console.error('FAILED: fetched receiptJson does not match the minted receipt.');
    console.error('  minted:', JSON.stringify(receipt));
    console.error('  got:   ', got.value.receiptJson);
    process.exit(1);
  }

  console.log('\n--- Step 5: verify from a fresh client using only the at:// URI ---');
  const verifyClient = new AtpClient({
    auth: new AppPasswordAuth({ service, identifier, appPassword }),
    transport: new FetchTransport(),
    didResolver: createPlcDidResolver(),
  });

  let result;
  if (jwksUrl) {
    console.log(`Resolving the verification key from the hosted JWKS URL (true no-keys path): ${jwksUrl}`);
    result = await verifyFromUri(uri, verifyClient, { jwksUrl });
  } else {
    console.log('ATP_JWKS_URL not set — falling back to the in-process public key.');
    console.log(`(set ATP_JWKS_URL=${HOSTED_JWKS_URL} and re-run to prove the URL-only path)`);
    result = await verifyFromUri(uri, verifyClient, publicKey);
  }

  console.log(`\nvalid: ${result.valid}`);
  console.log(`errors: ${JSON.stringify(result.errors)}`);
  console.log('\n--- render ---');
  console.log(result.render);

  console.log('\n=== SUMMARY ===');
  console.log(`Collection NSID: ${RECEIPT_NSID}`);
  console.log(`at:// URI: ${uri}`);
  console.log(`rkey: ${rkey}`);
  console.log(`valid: ${result.valid}`);
  console.log('\nThis URI supersedes the expired Sprint-launch demo receipt. Update the launch post,');
  console.log('positioning page, and project note with the new URI before (re-)submitting Show HN.');
  console.log('\nCLI check (run separately, from a fresh shell, to visually confirm the render):');
  console.log(`  node dist/cli/view-receipt.js "${uri}" --jwks keys/issuer-public.jwk.json`);
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
