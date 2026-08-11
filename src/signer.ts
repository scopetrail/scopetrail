// SPDX-License-Identifier: Apache-2.0
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

import { webcrypto, randomBytes } from 'node:crypto';
import { validateChain } from './builder.js';
import type {
  OBOTokenContext,
  OBOAuditReceipt,
  DataIntegrityProof,
  VerificationResult,
} from './types.js';

const { subtle } = webcrypto;

// ── JSON-LD receipt context URLs ──────────────────────────────────────────────

const OBO_CONTEXTS: string[] = [
  'https://www.w3.org/ns/credentials/v2',
  'https://scopetrail.github.io/contexts/obo-receipt/v1.jsonld',
];

// ── §2.4 — Base58btc encode / decode ─────────────────────────────────────────
// Bitcoin Base58 alphabet — no 0, O, I, l to avoid visual ambiguity

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Encode a byte array as Base58btc (Bitcoin alphabet, no checksum).
 * Used to encode Ed25519 signatures as the `proofValue` field.
 */
export function base58btcEncode(bytes: Uint8Array): string {
  // Count leading zero bytes — each maps to a leading '1' in Base58
  let leadingZeros = 0;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0) break;
    leadingZeros++;
  }

  // Convert byte array to BigInt for base conversion
  let num = 0n;
  for (const byte of bytes) {
    num = num * 256n + BigInt(byte);
  }

  // Convert BigInt to Base58 digits
  let result = '';
  while (num > 0n) {
    const rem = Number(num % 58n);
    num /= 58n;
    result = B58_ALPHABET[rem] + result;
  }

  return '1'.repeat(leadingZeros) + result;
}

/**
 * Decode a Base58btc string back to a byte array.
 * Throws if any character is outside the Base58 alphabet.
 */
export function base58btcDecode(str: string): Uint8Array {
  let num = 0n;
  for (const char of str) {
    const idx = B58_ALPHABET.indexOf(char);
    if (idx === -1) {
      throw new Error(`Invalid Base58btc character: "${char}"`);
    }
    num = num * 58n + BigInt(idx);
  }

  // Convert BigInt to bytes
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num & 0xffn));
    num >>= 8n;
  }

  // Restore leading zeros (each leading '1' → 0x00)
  let leadingOnes = 0;
  for (const ch of str) {
    if (ch !== '1') break;
    leadingOnes++;
  }

  return new Uint8Array([...new Array<number>(leadingOnes).fill(0), ...bytes]);
}

// ── §2.2 — JCS canonicalization (RFC 8785) ───────────────────────────────────
//
// Rules:
//   - Object keys are sorted by Unicode code point (= JS default string sort)
//   - Arrays preserve insertion order
//   - Numbers: standard JSON serialization; -0 → "0"; non-finite → error
//   - No whitespace outside string values
//   - Applies recursively to all nested objects and arrays

function jcsStringify(value: unknown): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return String(value);

    case 'number':
      if (!isFinite(value)) {
        throw new TypeError(`JCS: non-finite number (${value}) is not representable in JSON`);
      }
      // -0 must serialize as "0" per RFC 8785 §3.2.2.3
      if (Object.is(value, -0)) return '0';
      return JSON.stringify(value);

    case 'string':
      return JSON.stringify(value);

    case 'object':
      if (Array.isArray(value)) {
        return '[' + value.map(jcsStringify).join(',') + ']';
      }
      // Plain object: sort keys by Unicode code point, recurse
      {
        const obj = value as Record<string, unknown>;
        const sorted = Object.keys(obj).sort(); // lexicographic = Unicode code point order for BMP
        const pairs = sorted.map(k => `${JSON.stringify(k)}:${jcsStringify(obj[k])}`);
        return '{' + pairs.join(',') + '}';
      }

    default:
      throw new TypeError(`JCS: unsupported value type "${typeof value}"`);
  }
}

/**
 * JCS-canonicalize an object to UTF-8 bytes per RFC 8785.
 * This is the byte sequence that gets signed and verified.
 */
export function canonicalize(obj: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(jcsStringify(obj));
}

// ── §2.3 — SHA-256 document hash (utility) ───────────────────────────────────

/**
 * SHA-256 hash utility using `webcrypto.subtle`.
 * Note: `mintReceipt` signs the JCS canonical bytes *directly* per the
 * `eddsa-jcs-2022` spec (Ed25519 applies SHA-512 internally).
 * This function is exposed for callers who need a standalone hash.
 */
export async function hashDocument(canonical: Uint8Array): Promise<Uint8Array> {
  const buf = await subtle.digest('SHA-256', canonical);
  return new Uint8Array(buf);
}

// ── §2.1 — Key generation ─────────────────────────────────────────────────────

/**
 * Generate an Ed25519 key pair via `node:crypto` WebCrypto.
 * Requires Node.js ≥ 18.
 */
export async function generateKeyPair(): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
  // The `as Algorithm` cast is required because TypeScript's DOM typings predate
  // Ed25519 being standardized in the WebCrypto spec. Runtime behaviour is correct.
  const kp = (await subtle.generateKey(
    { name: 'Ed25519' } as Algorithm,
    true,
    ['sign', 'verify']
  )) as CryptoKeyPair;

  return { privateKey: kp.privateKey, publicKey: kp.publicKey };
}

/**
 * Export an Ed25519 public key as a JWK (`kty: "OKP"`, `crv: "Ed25519"`).
 */
export async function exportPublicKeyAsJwk(publicKey: CryptoKey): Promise<JsonWebKey> {
  return subtle.exportKey('jwk', publicKey);
}

// ── Receipt ID generator ──────────────────────────────────────────────────────

/**
 * Generate a time-sortable receipt ID.
 * Format: `urn:obo-receipt:<base36-timestamp><20-hex-random>`
 */
function generateReceiptId(): string {
  const ts = Date.now().toString(36).toUpperCase().padStart(10, '0');
  const rand = randomBytes(10).toString('hex').toUpperCase();
  return `urn:obo-receipt:${ts}${rand}`;
}

// ── §2.6 — In-process nonce store ─────────────────────────────────────────────

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

export class NonceStore implements INonceStore {
  private readonly store = new Map<string, number>();

  /** Register a nonce with its expiry. Evicts stale entries first. */
  add(nonce: string, expiresAt: Date): void {
    const now = Date.now();
    // Lazy eviction: purge all expired entries on each write
    for (const [n, exp] of this.store) {
      if (exp <= now) this.store.delete(n);
    }
    this.store.set(nonce, expiresAt.getTime());
  }

  /**
   * Return `true` if this nonce is known and still within its validity window.
   * Treats expired entries as absent (deletes them on read).
   */
  has(nonce: string): boolean {
    const exp = this.store.get(nonce);
    if (exp === undefined) return false;
    if (exp <= Date.now()) {
      this.store.delete(nonce);
      return false;
    }
    return true;
  }
}

/** Default singleton nonce store for single-process deployments. */
export const defaultNonceStore = new NonceStore();

// ── §2.5 — mintReceipt ────────────────────────────────────────────────────────

/**
 * Build the one-line human-readable summary embedded in every receipt (PRD §7 Q4).
 * Format: `<root> authorized <actor> to <verb> <resource>`.
 */
export function buildSummary(context: OBOTokenContext): string {
  const name = (p: { displayName?: string; id: string }) => p.displayName ?? p.id;
  return (
    `${name(context.rootPrincipal)} authorized ${name(context.actingPrincipal)} ` +
    `to ${context.action.verb} ${context.action.resourceUri}`
  );
}

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
export async function mintReceipt(
  context: OBOTokenContext,
  privateKey: CryptoKey,
  keyId: string,
  issuerDid: string
): Promise<OBOAuditReceipt> {
  // Step 1: build unsigned receipt
  const unsigned: Omit<OBOAuditReceipt, 'proof'> = {
    '@context': OBO_CONTEXTS,
    '@type': ['VerifiableCredential', 'OBOAuditReceipt'],
    id: generateReceiptId(),
    issuer: issuerDid,
    issuanceDate: context.issuedAt,
    expirationDate: context.expiresAt,
    credentialSubject: context.actingPrincipal,
    delegationContext: {
      rootPrincipal: context.rootPrincipal,
      delegationChain: context.delegationChain,
      grantedScopes: context.grantedScopes,
      audience: context.audience,
      upstreamTokenRef: context.upstreamTokenRef,
    },
    action: context.action,
    summary: buildSummary(context),
    nonce: context.nonce,
  };

  // Step 2: JCS-canonicalize
  const canonical = canonicalize(unsigned as unknown as Record<string, unknown>);

  // Step 3: Sign canonical bytes with Ed25519
  // Per eddsa-jcs-2022: sign the raw canonical bytes; Ed25519 handles hashing internally.
  const sigBuffer = await subtle.sign(
    'Ed25519',
    privateKey,
    canonical
  );

  // Step 4: Encode signature as Base58btc
  const proofValue = base58btcEncode(new Uint8Array(sigBuffer));

  // Step 5: Attach proof
  const proof: DataIntegrityProof = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: context.issuedAt,
    verificationMethod: `${issuerDid}#${keyId}`,
    proofPurpose: 'assertionMethod',
    proofValue,
  };

  return { ...unsigned, proof };
}

// ── §2.7 — verifyReceipt ──────────────────────────────────────────────────────

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
export async function verifyReceipt(
  receipt: OBOAuditReceipt,
  publicKey: CryptoKey,
  nonceStore: INonceStore = defaultNonceStore
): Promise<VerificationResult> {
  // Step 1: Nonce replay — exit immediately; no need to check signature for replays
  if (await nonceStore.has(receipt.nonce)) {
    return { valid: false, errors: ['NONCE_REPLAY'] };
  }

  const errors: string[] = [];
  const now = Date.now();

  // Step 2: Structural checks
  const expiryMs = new Date(receipt.expirationDate).getTime();
  const issuanceMs = new Date(receipt.issuanceDate).getTime();

  if (expiryMs <= now) {
    errors.push('RECEIPT_EXPIRED');
  }
  if (issuanceMs > now + 5_000) {
    errors.push('ISSUANCE_DATE_IN_FUTURE');
  }

  // Step 3: Chain integrity
  const chainResult = validateChain(
    receipt.delegationContext.rootPrincipal,
    receipt.delegationContext.delegationChain,
    receipt.credentialSubject,
    receipt.delegationContext.grantedScopes
  );
  if (!chainResult.valid) {
    for (const e of chainResult.errors) {
      errors.push(`CHAIN_INVALID:${e.field}`);
    }
  }

  // Step 4: Signature verification
  // Strip proof, re-canonicalize the unsigned body, verify against stored signature.
  let sigValid = false;
  try {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { proof, ...unsignedReceipt } = receipt;
    const canonical = canonicalize(unsignedReceipt as unknown as Record<string, unknown>);
    const sigBytes = base58btcDecode(proof.proofValue);
    sigValid = await subtle.verify('Ed25519', publicKey, sigBytes, canonical);
  } catch {
    sigValid = false;
  }

  if (!sigValid) {
    errors.push('SIGNATURE_INVALID');
  }

  const valid = errors.length === 0;

  // Step 5: Register nonce only after all checks pass
  if (valid) {
    await nonceStore.add(receipt.nonce, new Date(receipt.expirationDate));
  }

  return { valid, errors };
}

// ── §2.8 — JWKS builder ───────────────────────────────────────────────────────

/**
 * Build a JWKS document from an array of Ed25519 public keys.
 * Output is ready to serve as `GET /.well-known/jwks.json`.
 */
export async function buildJwks(
  keys: Array<{ kid: string; publicKey: CryptoKey }>
): Promise<{ keys: JsonWebKey[] }> {
  const jwkKeys = await Promise.all(
    keys.map(async ({ kid, publicKey }) => {
      const jwk = await exportPublicKeyAsJwk(publicKey);
      return { ...jwk, kid, use: 'sig' };
    })
  );
  return { keys: jwkKeys };
}
