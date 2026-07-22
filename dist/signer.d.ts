/**
 * signer.ts — Task 2: Asymmetric Signing Utility
 *
 * Responsibilities:
 *   - JCS canonicalization (RFC 8785) — zero external deps
 *   - Base58btc encode/decode — zero external deps
 *   - Ed25519 key generation and export via node:crypto webcrypto
 *   - mintReceipt(): sign an OBOTokenContext into a tamper-proof OBOAuditReceipt
 *   - NonceStore: in-process replay prevention with lazy TTL eviction
 *   - verifyReceipt(): stateless signature + structural + replay verification
 *   - buildJwks(): export public keys as JWKS-format JSON
 *
 * @see PRD_ARCH.md §5
 * @see sprint_01.md Task 2
 */
import type { OBOTokenContext, OBOAuditReceipt, VerificationResult } from './types.js';
/**
 * Encode a byte array as Base58btc (Bitcoin alphabet, no checksum).
 * Used to encode Ed25519 signatures as the `proofValue` field.
 */
export declare function base58btcEncode(bytes: Uint8Array): string;
/**
 * Decode a Base58btc string back to a byte array.
 * Throws if any character is outside the Base58 alphabet.
 */
export declare function base58btcDecode(str: string): Uint8Array;
/**
 * JCS-canonicalize an object to UTF-8 bytes per RFC 8785.
 * This is the byte sequence that gets signed and verified.
 */
export declare function canonicalize(obj: Record<string, unknown>): Uint8Array;
/**
 * SHA-256 hash utility using `webcrypto.subtle`.
 * Note: `mintReceipt` signs the JCS canonical bytes *directly* per the
 * `eddsa-jcs-2022` spec (Ed25519 applies SHA-512 internally).
 * This function is exposed for callers who need a standalone hash.
 */
export declare function hashDocument(canonical: Uint8Array): Promise<Uint8Array>;
/**
 * Generate an Ed25519 key pair via `node:crypto` WebCrypto.
 * Requires Node.js ≥ 18.
 */
export declare function generateKeyPair(): Promise<{
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}>;
/**
 * Export an Ed25519 public key as a JWK (`kty: "OKP"`, `crv: "Ed25519"`).
 */
export declare function exportPublicKeyAsJwk(publicKey: CryptoKey): Promise<JsonWebKey>;
/**
 * In-process nonce store for replay prevention.
 *
 * Backed by a `Map<nonce, expiryMs>`. Expired entries are evicted lazily
 * on each `add()` call — no background timer required.
 *
 * For multi-replica deployments, replace with a shared store (Redis, etc.)
 * by implementing the same `has()` / `add()` interface.
 */
/**
 * Replay-protection store contract (PRD §7 Q3). The default in-process
 * implementation below suits single-replica deployments; multi-replica services
 * (e.g. the HTTP issuer) can supply a Redis/DB-backed implementation of this
 * same interface to `verifyReceipt()`.
 */
export interface INonceStore {
    add(nonce: string, expiresAt: Date): void | Promise<void>;
    has(nonce: string): boolean | Promise<boolean>;
}
export declare class NonceStore implements INonceStore {
    private readonly store;
    /** Register a nonce with its expiry. Evicts stale entries first. */
    add(nonce: string, expiresAt: Date): void;
    /**
     * Return `true` if this nonce is known and still within its validity window.
     * Treats expired entries as absent (deletes them on read).
     */
    has(nonce: string): boolean;
}
/** Default singleton nonce store for single-process deployments. */
export declare const defaultNonceStore: NonceStore;
/**
 * Build the one-line human-readable summary embedded in every receipt (PRD §7 Q4).
 * Format: `<root> authorized <actor> to <verb> <resource>`.
 */
export declare function buildSummary(context: OBOTokenContext): string;
/**
 * Sign a validated `OBOTokenContext` into a tamper-proof `OBOAuditReceipt`.
 *
 * Signing protocol (`eddsa-jcs-2022`):
 *   1. Build unsigned receipt (no `proof` field)
 *   2. JCS-canonicalize → UTF-8 bytes
 *   3. Sign bytes directly with Ed25519 (Ed25519 applies SHA-512 internally)
 *   4. Base58btc-encode the 64-byte signature → `proofValue`
 *   5. Attach `proof` block and return the complete receipt
 */
export declare function mintReceipt(context: OBOTokenContext, privateKey: CryptoKey, keyId: string, issuerDid: string): Promise<OBOAuditReceipt>;
/**
 * Verify a signed `OBOAuditReceipt`.
 *
 * Verification steps (in order):
 *   1. Nonce replay check — early exit if nonce is already known
 *   2. Structural checks: expiry, issuance clock skew
 *   3. Delegation chain integrity (via builder.validateChain)
 *   4. Cryptographic signature verification
 *   5. If all pass: register nonce in store to prevent replay
 *
 * Returns `VerificationResult { valid, errors }`. All errors are collected
 * before returning (no early exit after step 1) so callers see the full picture.
 */
export declare function verifyReceipt(receipt: OBOAuditReceipt, publicKey: CryptoKey, nonceStore?: INonceStore): Promise<VerificationResult>;
/**
 * Build a JWKS document from an array of Ed25519 public keys.
 * Output is ready to serve as `GET /.well-known/jwks.json`.
 */
export declare function buildJwks(keys: Array<{
    kid: string;
    publicKey: CryptoKey;
}>): Promise<{
    keys: JsonWebKey[];
}>;
//# sourceMappingURL=signer.d.ts.map