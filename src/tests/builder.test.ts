// SPDX-License-Identifier: Apache-2.0
/**
 * builder.test.ts — Unit tests for Task 1 (token extraction & chain sorting).
 * Uses Node.js built-in test runner (node:test) — no external test dep required.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  digestToken,
  extractJwtClaims,
  sortChain,
  validateChain,
  generateNonce,
  extractContext,
} from '../builder.js';
import { ContextValidationError } from '../types.js';
import type { Principal, DelegationHop, RawContextInput } from '../types.js';

// ── Fixtures ─────────────────────────────────────────────────────────────────

const human: Principal = { id: 'did:web:org.example:users:jim', type: 'human' };
const svc: Principal = { id: 'did:web:org.example:services:orch', type: 'service' };
const agent: Principal = { id: 'did:web:org.example:agents:bot', type: 'agent' };

/** Minimal valid JWT with iss, exp, jti claims */
function makeJwt(claims: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `${header}.${payload}.fakesig`;
}

const jwt1 = makeJwt({ iss: 'https://auth.example', exp: Math.floor(Date.now() / 1000) + 3600, jti: 'tok-1' });
const jwt2 = makeJwt({ iss: 'https://auth.example', exp: Math.floor(Date.now() / 1000) + 3600, jti: 'tok-2' });

function makeRawInput(overrides: Partial<RawContextInput> = {}): RawContextInput {
  const now = new Date();
  const exp = new Date(now.getTime() + 3_600_000);
  return {
    rootPrincipal: human,
    hops: [
      {
        delegator: human,
        delegate: svc,
        scopeAtHop: ['read:docs'],
        rawToken: jwt1,
        tokenType: 'jwt',
        authorizedAt: now.toISOString(),
      },
      {
        delegator: svc,
        delegate: agent,
        scopeAtHop: ['read:docs'],
        rawToken: jwt2,
        tokenType: 'jwt',
        authorizedAt: new Date(now.getTime() + 60_000).toISOString(),
      },
    ],
    actingPrincipal: agent,
    rawUpstreamToken: jwt2,
    upstreamTokenType: 'jwt',
    grantedScopes: ['read:docs'],
    audience: ['https://api.example'],
    action: { verb: 'read', resourceUri: 'https://api.example/docs/1' },
    issuedAt: now.toISOString(),
    expiresAt: exp.toISOString(),
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('digestToken', () => {
  it('returns sha256:<64 hex chars>', () => {
    const d = digestToken('hello');
    assert.match(d, /^sha256:[0-9a-f]{64}$/);
  });

  it('is deterministic', () => {
    assert.equal(digestToken('abc'), digestToken('abc'));
  });

  it('produces different digests for different inputs', () => {
    assert.notEqual(digestToken('a'), digestToken('b'));
  });
});

describe('extractJwtClaims', () => {
  it('extracts iss, exp, jti from a valid JWT', () => {
    const claims = extractJwtClaims(jwt1);
    assert.equal(claims.iss, 'https://auth.example');
    assert.equal(typeof claims.exp, 'number');
    assert.equal(claims.jti, 'tok-1');
  });

  it('throws ContextValidationError for wrong segment count', () => {
    assert.throws(
      () => extractJwtClaims('a.b'),
      (e: unknown) => e instanceof ContextValidationError && e.errors[0].field === 'jwt'
    );
  });

  it('throws ContextValidationError for non-JSON payload', () => {
    const bad = 'aaa.' + Buffer.from('not json').toString('base64url') + '.sig';
    assert.throws(
      () => extractJwtClaims(bad),
      (e: unknown) => e instanceof ContextValidationError && e.errors[0].field === 'jwt.payload'
    );
  });
});

describe('sortChain', () => {
  it('sorts hops ascending by authorizedAt', () => {
    const hop1: DelegationHop = {
      delegator: human, delegate: svc, scopeAtHop: ['r'],
      tokenRef: { tokenDigest: 'sha256:' + 'a'.repeat(64), tokenType: 'opaque', issuer: '', tokenExpiresAt: '' },
      authorizedAt: '2026-06-18T14:22:00Z',
    };
    const hop2: DelegationHop = {
      delegator: svc, delegate: agent, scopeAtHop: ['r'],
      tokenRef: { tokenDigest: 'sha256:' + 'b'.repeat(64), tokenType: 'opaque', issuer: '', tokenExpiresAt: '' },
      authorizedAt: '2026-06-18T14:20:00Z',
    };
    const sorted = sortChain([hop1, hop2]);
    assert.equal(sorted[0].authorizedAt, '2026-06-18T14:20:00Z');
    assert.equal(sorted[1].authorizedAt, '2026-06-18T14:22:00Z');
  });

  it('does not mutate the input array', () => {
    const hops: DelegationHop[] = [];
    const result = sortChain(hops);
    assert.notEqual(result, hops);
  });
});

describe('validateChain', () => {
  const makeHop = (from: Principal, to: Principal, scopes: string[], time: string): DelegationHop => ({
    delegator: from, delegate: to, scopeAtHop: scopes,
    tokenRef: { tokenDigest: 'sha256:' + 'a'.repeat(64), tokenType: 'opaque', issuer: '', tokenExpiresAt: '' },
    authorizedAt: time,
  });

  it('passes a valid 2-hop chain', () => {
    const chain = [
      makeHop(human, svc, ['read:docs'], 'T1'),
      makeHop(svc, agent, ['read:docs'], 'T2'),
    ];
    const r = validateChain(human, chain, agent, ['read:docs']);
    assert.equal(r.valid, true);
    assert.equal(r.errors.length, 0);
  });

  it('passes an empty chain (root acts directly)', () => {
    const r = validateChain(human, [], human, ['read:docs']);
    assert.equal(r.valid, true);
  });

  it('fails when hop[0].delegator !== root', () => {
    const chain = [makeHop(svc, agent, ['read:docs'], 'T1')];
    const r = validateChain(human, chain, agent, ['read:docs']);
    assert.equal(r.valid, false);
    assert.ok(r.errors.some(e => e.field.includes('delegator')));
  });

  it('fails on a broken link between consecutive hops', () => {
    const wrong: Principal = { id: 'did:web:other', type: 'service' };
    const chain = [
      makeHop(human, svc, ['read:docs'], 'T1'),
      makeHop(wrong, agent, ['read:docs'], 'T2'), // delegator should be svc
    ];
    const r = validateChain(human, chain, agent, ['read:docs']);
    assert.equal(r.valid, false);
  });

  it('fails on scope inflation', () => {
    const chain = [
      makeHop(human, svc, ['read:docs', 'write:docs'], 'T1'), // write:docs not in grantedScopes
    ];
    const r = validateChain(human, chain, svc, ['read:docs']);
    assert.equal(r.valid, false);
    assert.ok(r.errors.some(e => e.rule.includes('write:docs')));
  });

  it('fails when chain depth exceeds 5', () => {
    const principals = Array.from({ length: 7 }, (_, i) => ({
      id: `did:web:p${i}`, type: 'service' as const,
    }));
    const chain: DelegationHop[] = Array.from({ length: 6 }, (_, i) =>
      makeHop(principals[i], principals[i + 1], ['r'], `T${i}`)
    );
    const r = validateChain(principals[0], chain, principals[6], ['r']);
    assert.equal(r.valid, false);
    assert.ok(r.errors.some(e => e.field === 'delegationChain'));
  });
});

describe('generateNonce', () => {
  it('returns a UUID v4 string', () => {
    const n = generateNonce();
    assert.match(n, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it('generates unique values', () => {
    assert.notEqual(generateNonce(), generateNonce());
  });
});

describe('extractContext', () => {
  it('happy path: returns valid OBOTokenContext with sorted chain', () => {
    const ctx = extractContext(makeRawInput());
    assert.equal(ctx.rootPrincipal.id, human.id);
    assert.equal(ctx.actingPrincipal.id, agent.id);
    assert.equal(ctx.delegationChain.length, 2);
    // Chain is sorted
    assert.ok(ctx.delegationChain[0].authorizedAt <= ctx.delegationChain[1].authorizedAt);
    // Nonce is present
    assert.match(ctx.nonce, /^[0-9a-f-]{36}$/);
    // Token digests are present
    assert.match(ctx.upstreamTokenRef.tokenDigest, /^sha256:[0-9a-f]{64}$/);
  });

  it('throws ContextValidationError for invalid rootPrincipal.id', () => {
    assert.throws(
      () => extractContext(makeRawInput({ rootPrincipal: { id: 'not-a-did-or-uri', type: 'human' } })),
      (e: unknown) => e instanceof ContextValidationError
    );
  });

  it('throws ContextValidationError when issuedAt is 10s in the future', () => {
    const future = new Date(Date.now() + 10_000).toISOString();
    const exp = new Date(Date.now() + 3_600_000).toISOString();
    assert.throws(
      () => extractContext(makeRawInput({ issuedAt: future, expiresAt: exp })),
      (e: unknown) => e instanceof ContextValidationError &&
        e.errors.some(err => err.field === 'issuedAt')
    );
  });

  it('throws ContextValidationError for invalid action.resourceUri', () => {
    assert.throws(
      () => extractContext(makeRawInput({ action: { verb: 'read', resourceUri: 'not-a-url' } })),
      (e: unknown) => e instanceof ContextValidationError &&
        e.errors.some(err => err.field === 'action.resourceUri')
    );
  });

  it('throws ContextValidationError for malformed JWT in hops', () => {
    const badInput = makeRawInput();
    badInput.hops[0].rawToken = 'not.a.jwt.at.all';
    assert.throws(
      () => extractContext(badInput),
      (e: unknown) => e instanceof ContextValidationError
    );
  });
});

describe('principal identifier conformance (did-core §3.1)', () => {
  /** Extract the field names from a thrown ContextValidationError, whatever its shape. */
  function fieldsOf(fn: () => unknown): string {
    try {
      fn();
    } catch (e) {
      return JSON.stringify(e instanceof ContextValidationError ? (e as unknown as { errors?: unknown }).errors ?? String(e) : String(e));
    }
    return '';
  }

  const slash = { id: 'did:web:org.example/users/jim', type: 'human' as const };

  it('rejects a slash-form did:web in rootPrincipal.id', () => {
    assert.throws(
      () => extractContext(makeRawInput({ rootPrincipal: slash })),
      (e: unknown) => e instanceof ContextValidationError
    );
  });

  it('rejects a slash-form did:web in actingPrincipal.id — previously unvalidated', () => {
    assert.throws(
      () => extractContext(makeRawInput({ actingPrincipal: { id: 'did:web:org.example/agents/bot', type: 'agent' } })),
      (e: unknown) => e instanceof ContextValidationError
    );
    assert.match(fieldsOf(() => extractContext(makeRawInput({
      actingPrincipal: { id: 'did:web:org.example/agents/bot', type: 'agent' },
    }))), /actingPrincipal\.id/);
  });

  it('rejects a slash-form did:web inside a hop — previously unvalidated', () => {
    const bad = { id: 'did:web:org.example/services/orch', type: 'service' as const };
    const input = makeRawInput();
    input.hops[0].delegate = bad;
    input.hops[1].delegator = bad;
    assert.match(fieldsOf(() => extractContext(input)), /hops\[0\]\.delegate\.id/);
  });

  it('accepts a conformant multi-segment did:web', () => {
    const ok = { id: 'did:web:example.com:users:jim', type: 'human' as const };
    const input = makeRawInput({ rootPrincipal: ok });
    input.hops[0].delegator = ok;
    assert.doesNotThrow(() => extractContext(input));
  });

  it('accepts did:plc and a bare-domain did:web', () => {
    for (const id of ['did:plc:bty3gmskhla7rwblq5zl5jm5', 'did:web:example.com']) {
      const p = { id, type: 'human' as const };
      const input = makeRawInput({ rootPrincipal: p });
      input.hops[0].delegator = p;
      assert.doesNotThrow(() => extractContext(input), `should accept ${id}`);
    }
  });

  it('accepts an absolute https URI as a principal id', () => {
    const p = { id: 'https://example.com/users/jim', type: 'human' as const };
    const input = makeRawInput({ rootPrincipal: p });
    input.hops[0].delegator = p;
    assert.doesNotThrow(() => extractContext(input));
  });

  it('rejects malformed DIDs that the old shape-check let through', () => {
    for (const id of ['did:', 'did:web', 'did:web:', 'did:WEB:example.com:jim', 'not-a-did-or-uri']) {
      assert.throws(
        () => extractContext(makeRawInput({ rootPrincipal: { id, type: 'human' } })),
        (e: unknown) => e instanceof ContextValidationError,
        `should reject ${JSON.stringify(id)}`
      );
    }
  });
});
