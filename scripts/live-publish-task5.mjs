/**
 * Sprint 03 Task 5 (stretch) — one real live publish + verify-from-`at://`.
 *
 * Manual, not in CI. Mints one receipt, publishes it to a real Bluesky PDS account, then
 * verifies it back using nothing but the resulting `at://` URI + the issuer's public key
 * (simulating a second-machine verifier — no auth, no session, just a public GET).
 *
 * Env vars required: ATP_PDS, ATP_IDENTIFIER, ATP_APP_PASSWORD.
 * Run from the package root: node --env-file=... scripts/live-publish-task5.mjs
 * (or export the three env vars in the shell before running).
 */

import { extractContext } from '../dist/builder.js';
import { generateKeyPair, mintReceipt, exportPublicKeyAsJwk } from '../dist/signer.js';
import { AppPasswordAuth } from '../dist/atproto/auth.js';
import { AtpClient, FetchTransport, createPlcDidResolver } from '../dist/atproto/client.js';
import { publishReceipt } from '../dist/atproto/publish.js';
import { verifyFromUri } from '../dist/atproto/verify-uri.js';

function must(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`Missing required env var: ${name}`);
    process.exit(1);
  }
  return v;
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

async function main() {
  const service = must('ATP_PDS');
  const rawIdentifier = must('ATP_IDENTIFIER');
  const identifier = rawIdentifier.replace(/^@/, ''); // atproto identifiers don't take a leading '@'
  const appPassword = must('ATP_APP_PASSWORD');

  console.log('--- Step 1: authenticate + resolve issuer DID ---');
  const auth = new AppPasswordAuth({ service, identifier, appPassword });
  const session = await auth.session();
  const issuerDid = session.did;
  console.log(`Authenticated as ${identifier} -> ${issuerDid}`);

  console.log('\n--- Step 2: mint a receipt ---');
  const { privateKey, publicKey } = await generateKeyPair();
  const context = extractContext(makeRawInput());
  const receipt = await mintReceipt(context, privateKey, 'key-1', issuerDid);
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

  console.log('\n--- Step 4: verify from a fresh client using only the at:// URI ---');
  // Fresh client + fresh PLC resolution, simulating a second machine that has no session and
  // no keys of its own -- only the URI and the issuer's public key (as it would fetch from a
  // hosted JWKS in the real flow; JWKS hosting isn't stood up yet, so the key is passed directly
  // here and that gap is flagged in the sprint note as a Phase 0 follow-up).
  const verifyAuth = new AppPasswordAuth({ service, identifier, appPassword });
  const verifyClient = new AtpClient({
    auth: verifyAuth,
    transport: new FetchTransport(),
    didResolver: createPlcDidResolver(),
  });
  const result = await verifyFromUri(uri, verifyClient, publicKey);

  console.log(`valid: ${result.valid}`);
  console.log(`errors: ${JSON.stringify(result.errors)}`);
  console.log('\n--- render ---');
  console.log(result.render);

  console.log('\n--- Public key (JWK, for reference) ---');
  console.log(JSON.stringify(await exportPublicKeyAsJwk(publicKey)));

  console.log('\n=== SUMMARY ===');
  console.log(`at:// URI: ${uri}`);
  console.log(`valid: ${result.valid}`);
}

main().catch((err) => {
  console.error('FAILED:', err);
  process.exit(1);
});
