// SPDX-License-Identifier: Apache-2.0
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

import { webcrypto } from 'node:crypto';
import type { OBOAuditReceipt } from '../types.js';
import { verifyReceipt, type INonceStore } from '../signer.js';
import { renderReceipt } from '../viewer.js';
import { RECEIPT_NSID, parseRecord, verifyMirrors, type AtpReceiptRecord } from './record.js';
import { RecordNotFound, type AtpClient } from './client.js';
import { resolveKeyFromJwksUrl } from './jwks.js';

const { subtle } = webcrypto;

// ── Result shape ──────────────────────────────────────────────────────────────

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
export type AtprotoVerifyErrorCode =
  | 'MALFORMED_URI'
  | 'WRONG_COLLECTION'
  | 'RECORD_NOT_FOUND'
  | 'MIRROR_MISMATCH'
  | 'KEY_IMPORT_FAILED';

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

// ── at:// URI parsing ─────────────────────────────────────────────────────────

/**
 * Parse an `at://<did>/<collection>/<rkey>` URI. Returns `null` (never throws) on anything
 * malformed, so callers can turn that into a typed error result.
 */
export function parseAtUri(uri: string): ParsedAtUri | null {
  const PREFIX = 'at://';
  if (typeof uri !== 'string' || !uri.startsWith(PREFIX)) {
    return null;
  }

  const rest = uri.slice(PREFIX.length);
  const parts = rest.split('/');
  if (parts.length !== 3) {
    return null;
  }

  const [did, collection, rkey] = parts;
  if (!did || !collection || !rkey) {
    return null;
  }

  return { did, collection, rkey };
}

// ── Key resolution ────────────────────────────────────────────────────────────

function isJwks(input: PublicKeyOrJwks): input is JsonWebKeySet {
  return typeof input === 'object' && input !== null && 'keys' in input;
}

function isJwksUrlRef(input: PublicKeyOrJwks): input is JwksUrlRef {
  return typeof input === 'object' && input !== null && 'jwksUrl' in input;
}

/**
 * Resolve a `PublicKeyOrJwks` to an imported `CryptoKey`, matching a JWKS entry by the `kid`
 * fragment of `verificationMethod` (`did:...#key-1` → `key-1`) when possible, falling back to
 * the first Ed25519/OKP key. Mirrors the matching logic in `src/cli/view-receipt.ts`.
 *
 * When `input` is a `JwksUrlRef` (Sprint 04 Task 5), the JWKS document itself is fetched first
 * — via `resolveKeyFromJwksUrl` (src/atproto/jwks.ts) — over the caller's injectable `fetchFn`.
 * Any fetch/HTTP/parse failure is caught here and folded into the same `null` →
 * `KEY_IMPORT_FAILED` typed-error path as every other key-resolution failure, so a bad/missing
 * JWKS URL never throws out of `verifyFromUri`.
 */
async function resolvePublicKey(
  input: PublicKeyOrJwks,
  verificationMethod: string
): Promise<CryptoKey | null> {
  if (isJwksUrlRef(input)) {
    try {
      return await resolveKeyFromJwksUrl(input.jwksUrl, verificationMethod, input.fetchFn);
    } catch {
      return null;
    }
  }

  if (!isJwks(input)) {
    return input;
  }

  if (!Array.isArray(input.keys) || input.keys.length === 0) {
    return null;
  }

  const kidFromMethod = verificationMethod.includes('#') ? verificationMethod.split('#')[1] : null;

  type JwkWithKid = JsonWebKey & { kid?: string };
  const keys = input.keys as JwkWithKid[];
  const matched = keys.filter(
    (k) => k.kty === 'OKP' && k.crv === 'Ed25519' && (kidFromMethod == null || k.kid === kidFromMethod)
  );
  const chosen = matched[0] ?? keys.find((k) => k.kty === 'OKP');
  if (!chosen) {
    return null;
  }

  try {
    return await subtle.importKey('jwk', chosen, { name: 'Ed25519' } as Algorithm, true, ['verify']);
  } catch {
    return null;
  }
}

// ── The verify-from-`at://` pipeline ──────────────────────────────────────────

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
export async function verifyFromUri(
  uri: string,
  client: AtpClient,
  publicKeyOrJwks: PublicKeyOrJwks,
  nonceStore?: INonceStore
): Promise<VerifyFromUriResult> {
  const parsed = parseAtUri(uri);
  if (!parsed) {
    return { valid: false, errors: ['MALFORMED_URI'], receipt: null, render: null };
  }

  if (parsed.collection !== RECEIPT_NSID) {
    return { valid: false, errors: ['WRONG_COLLECTION'], receipt: null, render: null };
  }

  const { did, collection, rkey } = parsed;

  let record: AtpReceiptRecord;
  try {
    const got = await client.getRecord({ repo: did, collection, rkey });
    record = got.value as AtpReceiptRecord;
  } catch (e) {
    if (e instanceof RecordNotFound) {
      return { valid: false, errors: ['RECORD_NOT_FOUND'], receipt: null, render: null };
    }
    throw e;
  }

  const receipt = parseRecord(record);

  // Mirror integrity check runs BEFORE any crypto — a tampered mirror never reaches verifyReceipt.
  if (!verifyMirrors(record)) {
    return { valid: false, errors: ['MIRROR_MISMATCH'], receipt, render: null };
  }

  const publicKey = await resolvePublicKey(publicKeyOrJwks, receipt.proof.verificationMethod);
  if (!publicKey) {
    return { valid: false, errors: ['KEY_IMPORT_FAILED'], receipt, render: null };
  }

  const result =
    nonceStore !== undefined
      ? await verifyReceipt(receipt, publicKey, nonceStore)
      : await verifyReceipt(receipt, publicKey);

  const render = renderReceipt(receipt, result, 'ascii');

  return { valid: result.valid, errors: result.errors, receipt, render };
}
