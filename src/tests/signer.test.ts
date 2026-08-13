// SPDX-License-Identifier: Apache-2.0
/**
 * signer.test.ts — Unit tests for Task 2 (asymmetric signing utility).
 * Uses Node.js built-in test runner (node:test) — no external test dep required.
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeyPair,
  mintReceipt,
  verifyReceipt,
  NonceStore,
  canonicalize,
  base58btcEncode,
  base58btcDecode,
} from '../signer.js';
import { extractContext } from '../builder.js';
import type { OBOAuditReceipt } from '../types.js';
import type { RawContextInput } from '../types.js';

// ── Fixtures ──────────────────────────────────────────────────────────────────

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
    rootPrincipal: { id: 'did:web:org.example:users:jim', type: 'human' },
    hops: [
      {
        delegator: { id: 'did:web:org.example:users:jim', type: 'human' },
        delegate: { id: 'did:web:org.example:agents:bot', type: 'agent' },
        scopeAtHop: ['read:docs'],
        rawToken: jwt1,
        tokenType: 'jwt',
        authorizedAt: now.toISOString(),
      },
    ],
    actingPrincipal: { id: 'did:web:org.example:agents:bot', type: 'agent' },
    rawUpstreamToken: jwt2,
    upstreamTokenType: 'jwt',
    grantedScopes: ['read:docs'],
    audience: ['https://api.example'],
    action: { verb: 'read', resourceUri: 'https://api.example/docs/1' },
    issuedAt: now.toISOString(),
    expiresAt: exp.toISOString(),
  };
}

// ── Test state (initialized in before()) ────────────────────────────────────

let privateKey: CryptoKey;
let publicKey: CryptoKey;
let signedReceipt: OBOAuditReceipt;

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('base58btc encode / decode', () => {
  it('round-trips a known byte vector', () => {
    const original = new Uint8Array([0, 1, 2, 3, 255, 254, 253]);
    const encoded = base58btcEncode(original);
    const decoded = base58btcDecode(encoded);
    assert.deepEqual(decoded, original);
  });

  it('handles leading zero bytes (leading "1" chars)', () => {
    const bytes = new Uint8Array([0, 0, 5]);
    const encoded = base58btcEncode(bytes);
    assert.ok(encoded.startsWith('11'), `Expected leading 1s, got: ${encoded}`);
    const decoded = base58btcDecode(encoded);
    assert.deepEqual(decoded, bytes);
  });

  it('throws on invalid Base58 character', () => {
    assert.throws(() => base58btcDecode('0Invalid'), /Invalid Base58btc character/);
  });
});

describe('JCS canonicalization', () => {
  it('produces identical bytes regardless of key insertion order', () => {
    const a = canonicalize({ b: 2, a: 1, c: 3 } as Record<string, unknown>);
    const b = canonicalize({ c: 3, a: 1, b: 2 } as Record<string, unknown>);
    assert.deepEqual(a, b);
  });

  it('sorts nested object keys', () => {
    const result = new TextDecoder().decode(
      canonicalize({ z: { y: 1, x: 2 } } as Record<string, unknown>)
    );
    assert.equal(result, '{"z":{"x":2,"y":1}}');
  });

  it('preserves array order', () => {
    const result = new TextDecoder().decode(
      canonicalize({ arr: [3, 1, 2] } as Record<string, unknown>)
    );
    assert.equal(result, '{"arr":[3,1,2]}');
  });

  it('serializes -0 as "0"', () => {
    const result = new TextDecoder().decode(canonicalize({ v: -0 } as Record<string, unknown>));
    assert.equal(result, '{"v":0}');
  });
});

describe('mintReceipt + verifyReceipt (round-trip)', () => {
  // Generate keys and sign once; reuse across tests in this suite
  before(async () => {
    const kp = await generateKeyPair();
    privateKey = kp.privateKey;
    publicKey = kp.publicKey;

    const ctx = extractContext(makeRawInput());
    signedReceipt = await mintReceipt(ctx, privateKey, 'key-1', 'did:web:receipts.example');
  });

  it('receipt has correct @type', () => {
    assert.ok(signedReceipt['@type'].includes('OBOAuditReceipt'));
  });

  it('receipt has a proof with eddsa-jcs-2022 cryptosuite', () => {
    assert.equal(signedReceipt.proof.cryptosuite, 'eddsa-jcs-2022');
    assert.ok(signedReceipt.proof.proofValue.length > 0);
  });

  it('verifyReceipt returns valid:true on a fresh receipt', async () => {
    const store = new NonceStore();
    const result = await verifyReceipt(signedReceipt, publicKey, store);
    assert.equal(result.valid, true, `Errors: ${result.errors.join(', ')}`);
  });

  it('tamper detection: mutating action.verb → valid:false', async () => {
    const tampered: OBOAuditReceipt = {
      ...signedReceipt,
      action: { ...signedReceipt.action, verb: 'delete' },
    };
    const store = new NonceStore();
    const result = await verifyReceipt(tampered, publicKey, store);
    assert.equal(result.valid, false);
    assert.ok(result.errors.includes('SIGNATURE_INVALID'));
  });

  it('tamper detection: corrupting proofValue → valid:false', async () => {
    const tampered: OBOAuditReceipt = {
      ...signedReceipt,
      proof: { ...signedReceipt.proof, proofValue: signedReceipt.proof.proofValue.slice(0, -4) + 'XXXX' },
    };
    const store = new NonceStore();
    const result = await verifyReceipt(tampered, publicKey, store);
    assert.equal(result.valid, false);
    assert.ok(result.errors.includes('SIGNATURE_INVALID'));
  });

  it('expired receipt → valid:false with RECEIPT_EXPIRED', async () => {
    const expired: OBOAuditReceipt = {
      ...signedReceipt,
      expirationDate: new Date(Date.now() - 1000).toISOString(),
    };
    const store = new NonceStore();
    const result = await verifyReceipt(expired, publicKey, store);
    assert.equal(result.valid, false);
    assert.ok(result.errors.includes('RECEIPT_EXPIRED'));
  });

  it('nonce replay: second verify returns NONCE_REPLAY', async () => {
    const store = new NonceStore();
    const first = await verifyReceipt(signedReceipt, publicKey, store);
    assert.equal(first.valid, true);
    const second = await verifyReceipt(signedReceipt, publicKey, store);
    assert.equal(second.valid, false);
    assert.ok(second.errors.includes('NONCE_REPLAY'));
  });
});
