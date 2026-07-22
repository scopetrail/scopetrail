/**
 * guardrail-fixture.mjs — Sprint 04 regression guardrail.
 *
 * Proves the refactor did not alter the signing/canonicalization path.
 * Uses a FIXED Ed25519 key and a FROZEN unsigned receipt document, so the
 * JCS-canonical bytes and the Ed25519 signature are fully deterministic.
 *
 * Run before the sprint to record the golden values, and again after each task:
 *   node scripts/guardrail-fixture.mjs            # prints current values
 *   node scripts/guardrail-fixture.mjs --check    # asserts against tests/fixtures/guardrail.json
 *
 * Imports canonicalize/base58 from the BUILT dist so it exercises the real code.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { canonicalize, base58btcEncode } from '../dist/signer.js';

const { subtle } = globalThis.crypto;
const here = dirname(fileURLToPath(import.meta.url));

// Fixed private key (test-only; never used for real receipts).
const PRIV_JWK = {
  key_ops: ['sign'], ext: true, alg: 'Ed25519', crv: 'Ed25519',
  d: 'qdoHM1Biwnrq0FTrD8Q6jWZDiqdEpPAnfFVxXzTCXAc',
  x: 'Y_GwovU2WywLeh9Im3hFrqwejycQx424SxS4P57Vc8M',
  kty: 'OKP',
};

// Frozen unsigned receipt — every field fixed (no Date.now(), no generated id).
// Shape mirrors mintReceipt()'s `unsigned` object exactly.
const UNSIGNED = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://delegationreceipts.dev/contexts/obo-receipt/v1',
  ],
  '@type': ['VerifiableCredential', 'OBOAuditReceipt'],
  id: 'urn:uuid:00000000-0000-4000-8000-000000000000',
  issuer: 'did:web:issuer.example',
  issuanceDate: '2026-01-01T00:00:00.000Z',
  expirationDate: '2026-01-01T01:00:00.000Z',
  credentialSubject: { id: 'did:web:org.example/agents/bot', type: 'agent' },
  delegationContext: {
    rootPrincipal: { id: 'did:web:org.example/users/jim', type: 'human' },
    delegationChain: [
      {
        delegator: { id: 'did:web:org.example/users/jim', type: 'human' },
        delegate: { id: 'did:web:org.example/agents/bot', type: 'agent' },
        scopeAtHop: ['read:docs'],
        tokenRef: 'sha256:aaaa',
        tokenType: 'jwt',
        authorizedAt: '2026-01-01T00:00:00.000Z',
      },
    ],
    grantedScopes: ['read:docs'],
    audience: ['https://api.example'],
    upstreamTokenRef: 'sha256:bbbb',
  },
  action: { verb: 'read', resourceUri: 'https://api.example/docs/1' },
  summary: 'agent read on behalf of jim',
  nonce: 'fixed-nonce-0001',
};

async function compute() {
  const key = await subtle.importKey('jwk', PRIV_JWK, 'Ed25519', false, ['sign']);
  const canonical = canonicalize(UNSIGNED);
  const digest = new Uint8Array(await subtle.digest('SHA-256', canonical));
  const sig = new Uint8Array(await subtle.sign('Ed25519', key, canonical));
  const hex = (b) => Buffer.from(b).toString('hex');
  return {
    canonicalSha256: hex(digest),
    proofValue: base58btcEncode(sig),
    canonicalLength: canonical.length,
  };
}

const cur = await compute();

if (process.argv.includes('--check')) {
  const golden = JSON.parse(readFileSync(join(here, '..', 'tests', 'fixtures', 'guardrail.json'), 'utf8'));
  const ok =
    golden.canonicalSha256 === cur.canonicalSha256 &&
    golden.proofValue === cur.proofValue &&
    golden.canonicalLength === cur.canonicalLength;
  if (!ok) {
    console.error('GUARDRAIL FAILED — signing/canonicalization path changed!');
    console.error('golden :', JSON.stringify(golden));
    console.error('current:', JSON.stringify(cur));
    process.exit(1);
  }
  console.log('GUARDRAIL OK — canonical bytes + signature unchanged.');
} else {
  console.log(JSON.stringify(cur, null, 2));
}
