// SPDX-License-Identifier: Apache-2.0
/**
 * Core type definitions for the OBO Audit Receipt library.
 * Interfaces correspond directly to PRD_ARCH.md §3 (Input Schema) and §4 (JSON-LD Artifact).
 */

/** A human, service, or AI agent in the delegation chain. @see PRD_ARCH §3.1 */
export interface Principal {
  /** Globally unique stable identifier — a DID (`did:web:…`) or URI. */
  id: string;
  /** Optional human-readable label for audit/display. */
  displayName?: string;
  /** Principal classification. */
  type: 'human' | 'service' | 'agent';
}

/**
 * Opaque reference to an upstream token.
 * Stores only a SHA-256 digest — never the raw token value.
 * @see PRD_ARCH §3.1 TokenRef
 */
export interface TokenRef {
  /** SHA-256 hex digest. Format: `sha256:<64 lowercase hex chars>` */
  tokenDigest: string;
  /** Token protocol. */
  tokenType: 'jwt' | 'opaque' | 'saml' | 'api_key';
  /** Issuer claim (`iss`) extracted from the token. */
  issuer: string;
  /** Token expiry as ISO-8601 UTC. */
  tokenExpiresAt: string;
  /** Unique token ID (`jti`) if present. */
  tokenId?: string;
}

/**
 * A single link in the delegation chain.
 * @see PRD_ARCH §3.1 DelegationHop
 */
export interface DelegationHop {
  /** Principal granting the delegation. */
  delegator: Principal;
  /** Principal receiving the delegation. */
  delegate: Principal;
  /**
   * Scopes passed through at this hop.
   * Must be a non-empty subset of the previous hop's scopes (or `grantedScopes` at root).
   */
  scopeAtHop: string[];
  /** Opaque reference to the token authorizing this hop. */
  tokenRef: TokenRef;
  /** ISO-8601 UTC when this hop was authorized. */
  authorizedAt: string;
}

/**
 * The action taken under delegation.
 * All parameters must be sanitized — no secrets, bearer tokens, or PII.
 */
export interface ActionDescriptor {
  /** Operation verb: `"read"`, `"write"`, `"invoke"`, `"query"`, etc. */
  verb: string;
  /** Target resource — must be a valid URL. */
  resourceUri: string;
  /** Sanitized operation parameters. */
  parameters?: Record<string, unknown>;
  /** Metadata: service name, environment, correlationId, etc. */
  metadata?: Record<string, string>;
}

/**
 * Complete upstream token context assembled at receipt-mint time.
 * This is the input to `mintReceipt()`. @see PRD_ARCH §3
 */
export interface OBOTokenContext {
  /** Original granting principal (human or root service). */
  rootPrincipal: Principal;
  /**
   * Ordered hop chain, root → acting principal.
   * `rootPrincipal` is NOT repeated here; array holds intermediate + leaf hops.
   */
  delegationChain: DelegationHop[];
  /** Leaf agent or service performing the action right now. */
  actingPrincipal: Principal;
  /** Token reference for the immediate upstream token authorizing the acting principal. */
  upstreamTokenRef: TokenRef;
  /** Final effective scopes granted to the acting principal. */
  grantedScopes: string[];
  /** Audience restrictions from the upstream token. */
  audience: string[];
  /** The action being performed under delegation. */
  action: ActionDescriptor;
  /** ISO-8601 UTC receipt mint time. */
  issuedAt: string;
  /** ISO-8601 UTC receipt expiry. */
  expiresAt: string;
  /** UUID v4 nonce for replay prevention. */
  nonce: string;
}

/** W3C Data Integrity proof block (`eddsa-jcs-2022` cryptosuite). @see PRD_ARCH §4.2 */
export interface DataIntegrityProof {
  type: 'DataIntegrityProof';
  cryptosuite: 'eddsa-jcs-2022';
  /** ISO-8601 UTC when the receipt was signed. */
  created: string;
  /** DID URL of the signing key, e.g. `did:web:receipts.org#key-1`. */
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  /** Base58btc-encoded 64-byte Ed25519 signature over the JCS-canonicalized receipt body. */
  proofValue: string;
}

/**
 * Signed, portable OBO Audit Receipt.
 * A W3C Verifiable Credential of type `OBOAuditReceipt`. @see PRD_ARCH §4.2
 */
export interface OBOAuditReceipt {
  '@context': string[];
  '@type': string[];
  /** Time-sortable receipt identifier. Format: `urn:obo-receipt:<ts><rand>`. */
  id: string;
  /** DID or URI of the receipt-issuing service. */
  issuer: string;
  /** ISO-8601 UTC mint time. */
  issuanceDate: string;
  /** ISO-8601 UTC expiry. */
  expirationDate: string;
  /** The leaf acting agent (receipt subject). */
  credentialSubject: Principal;
  /** Full delegation context embedded in the receipt. */
  delegationContext: {
    rootPrincipal: Principal;
    delegationChain: DelegationHop[];
    grantedScopes: string[];
    audience: string[];
    upstreamTokenRef: TokenRef;
  };
  /** The action taken under delegation. */
  action: ActionDescriptor;
  /**
   * One-line, plain-English summary of the delegation, for audit-log UIs that
   * render receipts without running the viewer. Generated at mint time and
   * covered by the signature (tamper-proof). Resolves PRD_ARCH §7 Q4.
   * Example: `Jim authorized Summarizer Agent v2 to invoke .../summarize`.
   */
  summary: string;
  /** UUID v4 nonce. Verifiers must store this to detect replays. */
  nonce: string;
  /** Cryptographic proof sealing the receipt against tampering. */
  proof: DataIntegrityProof;
}

/** Result of `validateChain()`. */
export interface ValidationResult {
  valid: boolean;
  errors: Array<{ field: string; rule: string }>;
}

/** Result of `verifyReceipt()`. */
export interface VerificationResult {
  valid: boolean;
  errors: string[];
}

/** JWT standard claims extracted by `extractJwtClaims()`. */
export interface JwtClaims {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: unknown;
}

/** Per-hop raw input provided to `extractContext()`. */
export interface RawHopInput {
  delegator: Principal;
  delegate: Principal;
  scopeAtHop: string[];
  /** Raw token string — will be digested; never stored in the receipt. */
  rawToken: string;
  tokenType: TokenRef['tokenType'];
  /** ISO-8601 UTC when this hop was authorized. */
  authorizedAt: string;
}

/** Raw input to `extractContext()` before digestion, sorting, and validation. */
export interface RawContextInput {
  rootPrincipal: Principal;
  hops: RawHopInput[];
  actingPrincipal: Principal;
  /** Leaf-hop raw token — the one directly authorizing the acting principal. */
  rawUpstreamToken: string;
  upstreamTokenType: TokenRef['tokenType'];
  grantedScopes: string[];
  audience: string[];
  action: ActionDescriptor;
  /** ISO-8601 UTC receipt mint time. */
  issuedAt: string;
  /** ISO-8601 UTC receipt expiry. */
  expiresAt: string;
}

/**
 * Typed validation error thrown by `extractContext()` when input fails validation.
 * Collects all field errors in a single throw rather than failing on the first.
 */
export class ContextValidationError extends Error {
  readonly errors: Array<{ field: string; rule: string }>;

  constructor(errors: Array<{ field: string; rule: string }>) {
    const detail = errors.map(e => `  [${e.field}] ${e.rule}`).join('\n');
    super(
      `OBO context validation failed (${errors.length} error${errors.length === 1 ? '' : 's'}):\n${detail}`
    );
    this.name = 'ContextValidationError';
    this.errors = errors;
  }
}
