// SPDX-License-Identifier: Apache-2.0
/**
 * builder.test.ts — Unit tests for Task 1 (token extraction & chain sorting).
 * Uses Node.js built-in test runner (node:test) — no external test dep required.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { digestToken, extractJwtClaims, sortChain, validateChain, generateNonce, extractContext, } from '../builder.js';
import { ContextValidationError } from '../types.js';
// ── Fixtures ─────────────────────────────────────────────────────────────────
const human = { id: 'did:web:org.example/users/jim', type: 'human' };
const svc = { id: 'did:web:org.example/services/orch', type: 'service' };
const agent = { id: 'did:web:org.example/agents/bot', type: 'agent' };
/** Minimal valid JWT with iss, exp, jti claims */
function makeJwt(claims) {
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
    return `${header}.${payload}.fakesig`;
}
const jwt1 = makeJwt({ iss: 'https://auth.example', exp: Math.floor(Date.now() / 1000) + 3600, jti: 'tok-1' });
const jwt2 = makeJwt({ iss: 'https://auth.example', exp: Math.floor(Date.now() / 1000) + 3600, jti: 'tok-2' });
function makeRawInput(overrides = {}) {
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
        assert.throws(() => extractJwtClaims('a.b'), (e) => e instanceof ContextValidationError && e.errors[0].field === 'jwt');
    });
    it('throws ContextValidationError for non-JSON payload', () => {
        const bad = 'aaa.' + Buffer.from('not json').toString('base64url') + '.sig';
        assert.throws(() => extractJwtClaims(bad), (e) => e instanceof ContextValidationError && e.errors[0].field === 'jwt.payload');
    });
});
describe('sortChain', () => {
    it('sorts hops ascending by authorizedAt', () => {
        const hop1 = {
            delegator: human, delegate: svc, scopeAtHop: ['r'],
            tokenRef: { tokenDigest: 'sha256:' + 'a'.repeat(64), tokenType: 'opaque', issuer: '', tokenExpiresAt: '' },
            authorizedAt: '2026-06-18T14:22:00Z',
        };
        const hop2 = {
            delegator: svc, delegate: agent, scopeAtHop: ['r'],
            tokenRef: { tokenDigest: 'sha256:' + 'b'.repeat(64), tokenType: 'opaque', issuer: '', tokenExpiresAt: '' },
            authorizedAt: '2026-06-18T14:20:00Z',
        };
        const sorted = sortChain([hop1, hop2]);
        assert.equal(sorted[0].authorizedAt, '2026-06-18T14:20:00Z');
        assert.equal(sorted[1].authorizedAt, '2026-06-18T14:22:00Z');
    });
    it('does not mutate the input array', () => {
        const hops = [];
        const result = sortChain(hops);
        assert.notEqual(result, hops);
    });
});
describe('validateChain', () => {
    const makeHop = (from, to, scopes, time) => ({
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
        const wrong = { id: 'did:web:other', type: 'service' };
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
            id: `did:web:p${i}`, type: 'service',
        }));
        const chain = Array.from({ length: 6 }, (_, i) => makeHop(principals[i], principals[i + 1], ['r'], `T${i}`));
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
        assert.throws(() => extractContext(makeRawInput({ rootPrincipal: { id: 'not-a-did-or-uri', type: 'human' } })), (e) => e instanceof ContextValidationError);
    });
    it('throws ContextValidationError when issuedAt is 10s in the future', () => {
        const future = new Date(Date.now() + 10_000).toISOString();
        const exp = new Date(Date.now() + 3_600_000).toISOString();
        assert.throws(() => extractContext(makeRawInput({ issuedAt: future, expiresAt: exp })), (e) => e instanceof ContextValidationError &&
            e.errors.some(err => err.field === 'issuedAt'));
    });
    it('throws ContextValidationError for invalid action.resourceUri', () => {
        assert.throws(() => extractContext(makeRawInput({ action: { verb: 'read', resourceUri: 'not-a-url' } })), (e) => e instanceof ContextValidationError &&
            e.errors.some(err => err.field === 'action.resourceUri'));
    });
    it('throws ContextValidationError for malformed JWT in hops', () => {
        const badInput = makeRawInput();
        badInput.hops[0].rawToken = 'not.a.jwt.at.all';
        assert.throws(() => extractContext(badInput), (e) => e instanceof ContextValidationError);
    });
});
//# sourceMappingURL=builder.test.js.map