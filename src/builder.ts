// SPDX-License-Identifier: Apache-2.0
/**
 * builder.ts — Task 1: Token Extraction & Chain Sorting Module
 *
 * Responsibilities:
 *   - Digest raw tokens (SHA-256 via node:crypto, no external deps)
 *   - Extract JWT claims without verifying signatures
 *   - Sort delegation hops chronologically
 *   - Validate chain linkage, scope subsetting, and all input constraints
 *   - Assemble a validated OBOTokenContext ready for mintReceipt()
 *
 * @see PRD_ARCH.md §3
 * @see sprint_01.md Task 1
 */

import { createHash, randomUUID } from 'node:crypto';
import type {
  Principal,
  DelegationHop,
  TokenRef,
  OBOTokenContext,
  JwtClaims,
  RawContextInput,
  RawHopInput,
  ValidationResult,
} from './types.js';
import { ContextValidationError } from './types.js';

// ── Constants ─────────────────────────────────────────────────────────────────

const TOKEN_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
/** Matches `did:…` or any URI containing `://` */
const DID_OR_URI_RE = /^did:|:\/\//;
const MAX_CHAIN_DEPTH = 5;
/** Maximum allowed clock skew for issuedAt (ms) */
const CLOCK_SKEW_MS = 5_000;

// ── §1.2 — Token digest ───────────────────────────────────────────────────────

/**
 * Compute a SHA-256 digest of a raw token string.
 * Returns `sha256:<64 lowercase hex chars>`. Never stores the raw token.
 */
export function digestToken(rawToken: string): string {
  const hex = createHash('sha256').update(rawToken, 'utf8').digest('hex');
  const digest = `sha256:${hex}`;
  // Sanity-check our own output — should never fail in practice
  if (!TOKEN_DIGEST_RE.test(digest)) {
    throw new Error(`digestToken produced a malformed digest: ${digest}`);
  }
  return digest;
}

// ── §1.3 — JWT claim extractor ────────────────────────────────────────────────

/**
 * Base64url-decode the JWT payload and return its claims.
 * Does NOT verify the signature — that is the caller's responsibility.
 * Throws `ContextValidationError` on malformed input.
 */
export function extractJwtClaims(jwt: string): JwtClaims {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new ContextValidationError([
      { field: 'jwt', rule: 'Must have exactly 3 dot-separated segments (header.payload.signature)' },
    ]);
  }
  try {
    const payloadJson = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(payloadJson) as JwtClaims;
  } catch {
    throw new ContextValidationError([
      { field: 'jwt.payload', rule: 'Payload segment is not valid base64url-encoded JSON' },
    ]);
  }
}

// ── §1.4 — Chain chronological sort ──────────────────────────────────────────

/**
 * Return a new array of hops sorted ascending by `authorizedAt`.
 * Lexicographic sort is safe for ISO-8601 UTC timestamps.
 * Does not mutate the input array.
 */
export function sortChain(hops: DelegationHop[]): DelegationHop[] {
  return [...hops].sort((a, b) => a.authorizedAt.localeCompare(b.authorizedAt));
}

// ── §1.5 — Chain linkage validator ───────────────────────────────────────────

/**
 * Validate that the delegation chain is structurally sound:
 *   - chain[0].delegator.id === root.id
 *   - Each hop's delegate.id === the next hop's delegator.id
 *   - chain[last].delegate.id === actor.id
 *   - chain.length <= MAX_CHAIN_DEPTH (5)
 *   - Each hop's scopeAtHop is a non-empty subset of the previous hop's scopes
 *
 * An empty chain is valid — it means the root principal is acting directly.
 */
export function validateChain(
  root: Principal,
  chain: DelegationHop[],
  actor: Principal,
  grantedScopes: string[]
): ValidationResult {
  const errors: Array<{ field: string; rule: string }> = [];

  if (chain.length > MAX_CHAIN_DEPTH) {
    errors.push({
      field: 'delegationChain',
      rule: `Chain depth ${chain.length} exceeds the maximum of ${MAX_CHAIN_DEPTH} hops`,
    });
    // Return early — further checks may panic on out-of-range indices
    return { valid: false, errors };
  }

  if (chain.length === 0) {
    // Direct root action: no hops to validate
    return { valid: true, errors: [] };
  }

  // Root linkage
  if (chain[0].delegator.id !== root.id) {
    errors.push({
      field: 'delegationChain[0].delegator.id',
      rule: `First hop delegator "${chain[0].delegator.id}" must equal rootPrincipal.id "${root.id}"`,
    });
  }

  // Consecutive linkage
  for (let i = 0; i < chain.length - 1; i++) {
    if (chain[i].delegate.id !== chain[i + 1].delegator.id) {
      errors.push({
        field: `delegationChain[${i}].delegate.id`,
        rule: `hop[${i}].delegate "${chain[i].delegate.id}" must equal hop[${i + 1}].delegator "${chain[i + 1].delegator.id}"`,
      });
    }
  }

  // Terminal linkage
  if (chain[chain.length - 1].delegate.id !== actor.id) {
    errors.push({
      field: `delegationChain[${chain.length - 1}].delegate.id`,
      rule: `Last hop delegate "${chain[chain.length - 1].delegate.id}" must equal actingPrincipal.id "${actor.id}"`,
    });
  }

  // Scope subset validation: each hop's scopes must be a subset of the previous scopes
  let prevScopes = new Set(grantedScopes);
  for (let i = 0; i < chain.length; i++) {
    const hopScopes = chain[i].scopeAtHop;
    if (hopScopes.length === 0) {
      errors.push({
        field: `delegationChain[${i}].scopeAtHop`,
        rule: 'scopeAtHop must not be empty',
      });
    } else {
      for (const scope of hopScopes) {
        if (!prevScopes.has(scope)) {
          errors.push({
            field: `delegationChain[${i}].scopeAtHop`,
            rule: `Scope "${scope}" was not granted in the previous hop (scope inflation)`,
          });
        }
      }
    }
    prevScopes = new Set(hopScopes);
  }

  return { valid: errors.length === 0, errors };
}

// ── §1.6 — Nonce generator ────────────────────────────────────────────────────

/**
 * Generate a UUID v4 nonce using `node:crypto` — no external dependency.
 */
export function generateNonce(): string {
  return randomUUID();
}

// ── §1.2 helper — Build TokenRef from a raw hop input ────────────────────────

function buildTokenRef(
  rawToken: string,
  tokenType: TokenRef['tokenType'],
  fieldPrefix: string,
  errors: Array<{ field: string; rule: string }>
): TokenRef {
  if (tokenType === 'jwt') {
    try {
      const claims = extractJwtClaims(rawToken);
      return {
        tokenDigest: digestToken(rawToken),
        tokenType: 'jwt',
        issuer: typeof claims.iss === 'string' ? claims.iss : '',
        tokenExpiresAt:
          typeof claims.exp === 'number'
            ? new Date(claims.exp * 1_000).toISOString()
            : '',
        tokenId: typeof claims.jti === 'string' ? claims.jti : undefined,
      };
    } catch (e) {
      if (e instanceof ContextValidationError) {
        for (const err of e.errors) {
          errors.push({ field: `${fieldPrefix}.${err.field}`, rule: err.rule });
        }
      } else {
        errors.push({ field: fieldPrefix, rule: String(e) });
      }
      // Return a placeholder so we continue collecting other errors
      return { tokenDigest: '', tokenType: 'jwt', issuer: '', tokenExpiresAt: '' };
    }
  }

  // Non-JWT token — we can only store the digest
  return {
    tokenDigest: digestToken(rawToken),
    tokenType,
    issuer: '',
    tokenExpiresAt: '',
  };
}

// ── §1.7 — Full extractContext() assembler ────────────────────────────────────

/**
 * Assemble, sort, and validate a complete `OBOTokenContext` from raw input.
 *
 * - Digests all raw tokens (SHA-256) and extracts JWT claims where applicable
 * - Sorts the delegation chain by `authorizedAt` (ascending)
 * - Runs all structural validation rules
 * - Throws `ContextValidationError` with a full per-field error list on any failure
 * - Generates a fresh nonce (UUID v4)
 */
export function extractContext(input: RawContextInput): OBOTokenContext {
  const errors: Array<{ field: string; rule: string }> = [];

  // Validate rootPrincipal.id
  if (!input.rootPrincipal.id || !DID_OR_URI_RE.test(input.rootPrincipal.id)) {
    errors.push({
      field: 'rootPrincipal.id',
      rule: 'Must be non-empty and start with "did:" or contain "://"',
    });
  }

  // Validate action.resourceUri
  try {
    new URL(input.action.resourceUri);
  } catch {
    errors.push({
      field: 'action.resourceUri',
      rule: `"${input.action.resourceUri}" is not a valid URL`,
    });
  }

  // Validate timing
  const now = Date.now();
  const issuedAtMs = new Date(input.issuedAt).getTime();
  const expiresAtMs = new Date(input.expiresAt).getTime();

  if (isNaN(issuedAtMs)) {
    errors.push({ field: 'issuedAt', rule: 'Must be a valid ISO-8601 date string' });
  } else if (issuedAtMs > now + CLOCK_SKEW_MS) {
    errors.push({
      field: 'issuedAt',
      rule: `issuedAt is ${issuedAtMs - now}ms in the future — exceeds ${CLOCK_SKEW_MS}ms clock skew tolerance`,
    });
  }

  if (isNaN(expiresAtMs)) {
    errors.push({ field: 'expiresAt', rule: 'Must be a valid ISO-8601 date string' });
  } else if (!isNaN(issuedAtMs) && expiresAtMs <= issuedAtMs) {
    errors.push({ field: 'expiresAt', rule: 'Must be strictly after issuedAt' });
  }

  // Build TokenRef for each hop (collect errors without early exit)
  const hopsWithRefs: DelegationHop[] = input.hops.map((hop: RawHopInput, i: number) => {
    const tokenRef = buildTokenRef(hop.rawToken, hop.tokenType, `hops[${i}].rawToken`, errors);
    return {
      delegator: hop.delegator,
      delegate: hop.delegate,
      scopeAtHop: hop.scopeAtHop,
      tokenRef,
      authorizedAt: hop.authorizedAt,
    };
  });

  // Sort chain chronologically (before validation so linkage checks use correct order)
  const sortedChain = sortChain(hopsWithRefs);

  // Validate chain structure
  const chainResult = validateChain(
    input.rootPrincipal,
    sortedChain,
    input.actingPrincipal,
    input.grantedScopes
  );
  errors.push(...chainResult.errors);

  // Build upstream TokenRef
  const upstreamTokenRef = buildTokenRef(
    input.rawUpstreamToken,
    input.upstreamTokenType,
    'rawUpstreamToken',
    errors
  );

  if (errors.length > 0) {
    throw new ContextValidationError(errors);
  }

  return {
    rootPrincipal: input.rootPrincipal,
    delegationChain: sortedChain,
    actingPrincipal: input.actingPrincipal,
    upstreamTokenRef,
    grantedScopes: input.grantedScopes,
    audience: input.audience,
    action: input.action,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    nonce: generateNonce(),
  };
}
