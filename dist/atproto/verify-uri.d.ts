/**
 * verify-uri.ts — Sprint 03 Task 3: verify a receipt from nothing but its `at://` URI.
 *
 * This is the headline flow of PRD_ARCH.md §8.5: a verifier holds no keys and no auth, only a
 * URI. It resolves the DID, fetches the record (a public, unauthenticated GET), re-parses the
 * verbatim signed payload, checks the untrusted indexed mirrors, and — only once all of that is
 * clean — calls the **existing** `verifyReceipt()` unchanged. Nothing here touches the crypto
 * path; this module composes Task 1 (record.ts) and Task 2 (client.ts) and calls out to
 * `../signer.js` and `../viewer.js` without modifying either.
 *
 * Failure modes that are NOT the verifier's fault for holding a bad URI (malformed URI, wrong
 * collection, missing record, tampered mirror) are returned as a typed, non-throwing result —
 * never a thrown error and never a crash. Errors from `verifyReceipt` itself (SIGNATURE_INVALID,
 * RECEIPT_EXPIRED, NONCE_REPLAY, CHAIN_INVALID:*, …) are passed through verbatim in the same
 * `errors` array so callers (e.g. Task 4's CLI) don't need two different error vocabularies.
 *
 * @see PRD_ARCH.md §8.5 (Verify-from-`at://` flow)
 * @see sprint_03.md Task 3
 */
import type { OBOAuditReceipt } from '../types.js';
import { type INonceStore } from '../signer.js';
import { type AtpClient } from './client.js';
/**
 * Error codes contributed by the atproto layer itself, checked *before* any crypto runs. These
 * sit in the same `errors` string array as `verifyReceipt`'s own codes (`SIGNATURE_INVALID`,
 * `RECEIPT_EXPIRED`, `ISSUANCE_DATE_IN_FUTURE`, `NONCE_REPLAY`, `CHAIN_INVALID:<field>`) — one
 * flat vocabulary, so a consumer (e.g. the Task 4 CLI) doesn't need to special-case atproto vs.
 * core errors. Distinguishable by string value/prefix if a caller needs to branch:
 *   - `MALFORMED_URI`    — not a well-formed `at://<did>/<collection>/<rkey>` URI
 *   - `WRONG_COLLECTION` — parsed collection != RECEIPT_NSID
 *   - `RECORD_NOT_FOUND` — resolveDidToPds/getRecord found nothing at that address
 *   - `MIRROR_MISMATCH`  — indexed mirrors disagree with the verbatim receiptJson payload
 *   - `KEY_IMPORT_FAILED` — publicKeyOrJwks could not be resolved to a usable Ed25519 key
 */
export type AtprotoVerifyErrorCode = 'MALFORMED_URI' | 'WRONG_COLLECTION' | 'RECORD_NOT_FOUND' | 'MIRROR_MISMATCH' | 'KEY_IMPORT_FAILED';
export interface ParsedAtUri {
    did: string;
    collection: string;
    rkey: string;
}
/** A JWKS document, e.g. loaded from a `.well-known/jwks.json` file. */
export interface JsonWebKeySet {
    keys: JsonWebKey[];
}
/**
 * A hosted JWKS to fetch by URL rather than an in-process document (Sprint 04 Task 5 — closes
 * the Sprint 03 Task 5 follow-up: verification with no in-process key at all, only an `at://`
 * URI and this URL). `fetchFn` is injectable so callers (and tests) never depend on the real
 * `globalThis.fetch`.
 */
export interface JwksUrlRef {
    /** URL to fetch a JWKS document from, e.g. `https://scopetrail.example/.well-known/jwks.json`. */
    jwksUrl: string;
    /** Injectable fetch for testability; defaults to `globalThis.fetch`. */
    fetchFn?: typeof fetch;
}
/** Either an already-imported verification key, an in-process JWKS, or a JWKS URL to fetch. */
export type PublicKeyOrJwks = CryptoKey | JsonWebKeySet | JwksUrlRef;
export interface VerifyFromUriResult {
    valid: boolean;
    /** Flat list of error codes — atproto-layer codes and/or verifyReceipt's own codes. */
    errors: string[];
    /** The parsed receipt, when it could be recovered (null only for MALFORMED_URI/WRONG_COLLECTION/RECORD_NOT_FOUND). */
    receipt: OBOAuditReceipt | null;
    /** `renderReceipt` output, when a receipt + verification outcome exist to render. */
    render: string | null;
}
/**
 * Parse an `at://<did>/<collection>/<rkey>` URI. Returns `null` (never throws) on anything
 * malformed, so callers can turn that into a typed error result.
 */
export declare function parseAtUri(uri: string): ParsedAtUri | null;
/**
 * Verify a receipt given only its `at://` URI: resolve → fetch → parse → check mirrors →
 * `verifyReceipt()` (unchanged) → render.
 *
 * Mirror mismatches are reported and returned *before* any cryptographic verification runs
 * (PRD_ARCH.md §8.5 step 4 precedes step 5) — a tampered mirror never reaches `verifyReceipt`.
 *
 * @param publicKeyOrJwks how to get the verification key — three shapes accepted (Sprint 04
 *   Task 5 added the third): an in-process `CryptoKey`; an in-process `JsonWebKeySet`; or a
 *   `JwksUrlRef` (`{ jwksUrl, fetchFn? }`) to fetch a hosted JWKS document by URL, with no
 *   in-process key material at all — the true "no keys" verification path (closes the Sprint 03
 *   Task 5 follow-up).
 * @param nonceStore optional override for `verifyReceipt`'s replay store; defaults to
 *   `verifyReceipt`'s own module-level `defaultNonceStore` when omitted.
 */
export declare function verifyFromUri(uri: string, client: AtpClient, publicKeyOrJwks: PublicKeyOrJwks, nonceStore?: INonceStore): Promise<VerifyFromUriResult>;
//# sourceMappingURL=verify-uri.d.ts.map