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
import type { Principal, DelegationHop, OBOTokenContext, JwtClaims, RawContextInput, ValidationResult } from './types.js';
/**
 * Compute a SHA-256 digest of a raw token string.
 * Returns `sha256:<64 lowercase hex chars>`. Never stores the raw token.
 */
export declare function digestToken(rawToken: string): string;
/**
 * Base64url-decode the JWT payload and return its claims.
 * Does NOT verify the signature — that is the caller's responsibility.
 * Throws `ContextValidationError` on malformed input.
 */
export declare function extractJwtClaims(jwt: string): JwtClaims;
/**
 * Return a new array of hops sorted ascending by `authorizedAt`.
 * Lexicographic sort is safe for ISO-8601 UTC timestamps.
 * Does not mutate the input array.
 */
export declare function sortChain(hops: DelegationHop[]): DelegationHop[];
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
export declare function validateChain(root: Principal, chain: DelegationHop[], actor: Principal, grantedScopes: string[]): ValidationResult;
/**
 * Generate a UUID v4 nonce using `node:crypto` — no external dependency.
 */
export declare function generateNonce(): string;
/**
 * Assemble, sort, and validate a complete `OBOTokenContext` from raw input.
 *
 * - Digests all raw tokens (SHA-256) and extracts JWT claims where applicable
 * - Sorts the delegation chain by `authorizedAt` (ascending)
 * - Runs all structural validation rules
 * - Throws `ContextValidationError` with a full per-field error list on any failure
 * - Generates a fresh nonce (UUID v4)
 */
export declare function extractContext(input: RawContextInput): OBOTokenContext;
//# sourceMappingURL=builder.d.ts.map