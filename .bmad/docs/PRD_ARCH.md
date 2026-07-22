# OBO Audit Receipt — Product Requirements & Architecture

**Status:** Draft
**Date:** 2026-06-18
**Authors:** PM + Architect (BMad session)

---

## 1. Problem Statement

When an AI agent or service acts **on behalf of (OBO)** a human principal, there is currently no portable, tamper-proof artifact that proves:

- *Who* authorized the action
- *What* scopes/permissions were delegated
- *When* the delegation occurred and expired
- *What* action was taken under that delegation

This gap creates an audit blind spot. The OBO Audit Receipt tool fills it by capturing the full delegation context at action time and sealing it into a cryptographically signed, portable JSON-LD receipt.

---

## 2. Goals

| # | Goal |
|---|---|
| G1 | Capture the complete upstream token context at delegation time |
| G2 | Produce a self-describing, portable JSON-LD artifact |
| G3 | Seal the artifact with an asymmetric signature so any verifier can detect tampering |
| G4 | Make receipt verification stateless — no callback to the issuer required |
| G5 | Support a chain of delegation (human → service → agent → sub-agent) |

---

## 3. Input Schema — Upstream Token Context

The **input** is everything the system knows at the moment an OBO action is executed. This is assembled from the inbound authorization token plus runtime context before the receipt is minted.

### 3.1 TypeScript Interface (canonical definition)

```typescript
/** Full context assembled at receipt-mint time */
interface OBOTokenContext {
  // ── Principal chain ─────────────────────────────────────────
  /** The human or root service that originally granted authority */
  rootPrincipal: Principal;

  /** Ordered chain from root down to the acting agent.
   *  rootPrincipal is NOT repeated here; this is intermediate + leaf. */
  delegationChain: DelegationHop[];

  /** The leaf agent/service performing the action right now */
  actingPrincipal: Principal;

  // ── Token provenance ────────────────────────────────────────
  /** The upstream token that authorized this action (opaque handle — NOT the raw token) */
  upstreamTokenRef: TokenRef;

  /** Scopes/permissions granted to the acting principal */
  grantedScopes: string[];

  /** Any audience restrictions from the upstream token */
  audience: string[];

  // ── Action being taken ──────────────────────────────────────
  action: ActionDescriptor;

  // ── Timing ──────────────────────────────────────────────────
  /** ISO-8601 UTC timestamp when the receipt is minted */
  issuedAt: string;

  /** ISO-8601 UTC — when this receipt (and its authority) expires */
  expiresAt: string;

  /** Monotonic nonce for replay prevention */
  nonce: string;
}

interface Principal {
  /** Globally unique, stable identifier (DID, email, service account) */
  id: string;

  /** Human-readable display name */
  displayName?: string;

  /** "human" | "service" | "agent" */
  type: "human" | "service" | "agent";
}

interface DelegationHop {
  /** Principal doing the delegating */
  delegator: Principal;

  /** Principal receiving the delegation */
  delegate: Principal;

  /** Scopes passed through at this hop (may be subset of delegator's) */
  scopeAtHop: string[];

  /** Token reference at this hop */
  tokenRef: TokenRef;

  /** ISO-8601 UTC when this hop was authorized */
  authorizedAt: string;
}

interface TokenRef {
  /** SHA-256 hex digest of the raw token — links receipt to token without embedding it */
  tokenDigest: string;

  /** "jwt" | "opaque" | "saml" | "api_key" */
  tokenType: string;

  /** Issuer claim from the token (iss) */
  issuer: string;

  /** Token's own expiry (ISO-8601 UTC) */
  tokenExpiresAt: string;

  /** JWT `jti` or equivalent unique token ID, if present */
  tokenId?: string;
}

interface ActionDescriptor {
  /** Verb: "read" | "write" | "delete" | "invoke" | "query" | … */
  verb: string;

  /** Resource URI or stable identifier */
  resourceUri: string;

  /** Optional structured parameters (sanitized — no secrets) */
  parameters?: Record<string, unknown>;

  /** Arbitrary key/value metadata (service name, environment, etc.) */
  metadata?: Record<string, string>;
}
```

### 3.2 Validation Rules

| Field | Rule |
|---|---|
| `rootPrincipal.id` | Must be a non-empty URI or DID |
| `delegationChain` | Each hop's `delegate` must equal the next hop's `delegator`; leaf delegate = `actingPrincipal` |
| `grantedScopes` | Must be a non-empty subset of scopes on the upstream token |
| `upstreamTokenRef.tokenDigest` | Must be `sha256:<hex>` format |
| `issuedAt` / `expiresAt` | `expiresAt` must be strictly after `issuedAt`; `issuedAt` must be ≤ now + 5 s clock skew |
| `nonce` | Must be a UUID v4 or CSPRNG hex ≥ 16 bytes |
| `action.resourceUri` | Must be a valid URI |

---

## 4. JSON-LD Audit Artifact

The **receipt** is the signed, portable output. It is a JSON-LD document so it is self-describing and compatible with Verifiable Credential tooling.

### 4.1 Context and Type

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://schemas.delegation-receipts.dev/v1/obo-receipt.jsonld"
  ],
  "@type": ["VerifiableCredential", "OBOAuditReceipt"]
}
```

> **Note:** The `delegation-receipts.dev` context URL is a placeholder. Replace with your hosted schema once published.

### 4.2 Full Artifact Schema

```jsonc
{
  // ── JSON-LD envelope ────────────────────────────────────────
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://schemas.delegation-receipts.dev/v1/obo-receipt.jsonld"
  ],
  "@type": ["VerifiableCredential", "OBOAuditReceipt"],

  // ── Receipt identity ────────────────────────────────────────
  "id": "urn:obo-receipt:01J4KZQXYZ...",   // ULID — lexicographically sortable
  "issuer": "did:web:receipts.your-org.example",

  // ── Timing ──────────────────────────────────────────────────
  "issuanceDate": "2026-06-18T14:22:31Z",
  "expirationDate": "2026-06-18T15:22:31Z",

  // ── Subject — the acting agent ──────────────────────────────
  "credentialSubject": {
    "id": "did:web:agent.your-org.example/agents/summarizer-v2",
    "type": "agent",
    "displayName": "Summarizer Agent v2"
  },

  // ── Delegation context ──────────────────────────────────────
  "delegationContext": {

    "rootPrincipal": {
      "id": "did:web:your-org.example/users/jim@example.com",
      "type": "human",
      "displayName": "Jim Holt"
    },

    "delegationChain": [
      {
        "delegator": {
          "id": "did:web:your-org.example/users/jim@example.com",
          "type": "human"
        },
        "delegate": {
          "id": "did:web:your-org.example/services/orchestrator",
          "type": "service"
        },
        "scopeAtHop": ["read:documents", "invoke:summarize"],
        "tokenRef": {
          "tokenDigest": "sha256:a3f1c9...",
          "tokenType": "jwt",
          "issuer": "https://auth.your-org.example",
          "tokenExpiresAt": "2026-06-18T16:00:00Z",
          "tokenId": "jti:abc123"
        },
        "authorizedAt": "2026-06-18T14:20:00Z"
      },
      {
        "delegator": {
          "id": "did:web:your-org.example/services/orchestrator",
          "type": "service"
        },
        "delegate": {
          "id": "did:web:agent.your-org.example/agents/summarizer-v2",
          "type": "agent"
        },
        "scopeAtHop": ["read:documents", "invoke:summarize"],
        "tokenRef": {
          "tokenDigest": "sha256:b9e2d4...",
          "tokenType": "jwt",
          "issuer": "https://auth.your-org.example",
          "tokenExpiresAt": "2026-06-18T15:30:00Z",
          "tokenId": "jti:def456"
        },
        "authorizedAt": "2026-06-18T14:22:00Z"
      }
    ],

    "grantedScopes": ["read:documents", "invoke:summarize"],
    "audience": ["https://api.your-org.example/documents"],

    "upstreamTokenRef": {
      "tokenDigest": "sha256:b9e2d4...",
      "tokenType": "jwt",
      "issuer": "https://auth.your-org.example",
      "tokenExpiresAt": "2026-06-18T15:30:00Z",
      "tokenId": "jti:def456"
    }
  },

  // ── Action ──────────────────────────────────────────────────
  "action": {
    "verb": "invoke",
    "resourceUri": "https://api.your-org.example/documents/doc-789/summarize",
    "parameters": {
      "format": "bullet_points",
      "maxLength": 500
    },
    "metadata": {
      "environment": "production",
      "service": "docs-api",
      "correlationId": "req-zzz999"
    }
  },

  // ── Replay prevention ────────────────────────────────────────
  "nonce": "f47ac10b-58cc-4372-a567-0e02b2c3d479",

  // ── Cryptographic proof ─────────────────────────────────────
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2026-06-18T14:22:31Z",
    "verificationMethod": "did:web:receipts.your-org.example#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3Jq8K..."   // Base58btc-encoded Ed25519 signature
  }
}
```

### 4.3 Field Registry

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | URI | Yes | ULID preferred for sortability |
| `issuer` | DID or URI | Yes | Identifies the signing service |
| `issuanceDate` | ISO-8601 | Yes | Mint time |
| `expirationDate` | ISO-8601 | Yes | Receipt validity window |
| `credentialSubject.id` | URI/DID | Yes | The leaf acting agent |
| `delegationContext.rootPrincipal` | Principal | Yes | Human or root service |
| `delegationContext.delegationChain` | array | Yes | Empty `[]` only when root acts directly |
| `delegationContext.grantedScopes` | string[] | Yes | Final effective scopes |
| `delegationContext.upstreamTokenRef` | TokenRef | Yes | Points to the leaf-hop token |
| `action` | ActionDescriptor | Yes | Sanitized — no credential values in parameters |
| `nonce` | UUID v4 | Yes | Must be stored by verifier to detect replays |
| `proof` | DataIntegrityProof | Yes | See Section 5 |

---

## 5. Verification Architecture

### 5.1 Key Algorithm Selection

| Property | Choice | Rationale |
|---|---|---|
| Algorithm | **Ed25519** | Fast, small signatures (64 bytes), widely supported, no parameter-choice footguns vs. ECDSA |
| Key format | **JWK** (JSON Web Key) | Interoperable; easy to publish in a JWKS endpoint |
| Signature encoding | **Base58btc** | W3C Data Integrity standard encoding |
| Canonicalization | **JCS** (JSON Canonicalization Scheme, RFC 8785) | Deterministic serialization before hashing |

### 5.2 Key Lifecycle

```
┌─────────────────────────────────────────────────────┐
│                  Receipt Issuer Service              │
│                                                     │
│  Key Store (HSM or KMS)                             │
│  ┌─────────────────────────────────────────────┐    │
│  │  key-1 (active)   Ed25519 private key       │    │
│  │  key-0 (retired)  Ed25519 private key       │    │
│  └─────────────────────────────────────────────┘    │
│                                                     │
│  JWKS Endpoint  ──► GET /.well-known/jwks.json      │
│  (public keys only — key-1 + key-0 for verify)      │
└─────────────────────────────────────────────────────┘
```

**Key rotation policy:**
- Rotate signing keys every 90 days (or immediately on suspected compromise)
- Retire keys stay in the JWKS endpoint for `max(receipt TTL, 30 days)` to allow late verification
- Each key has a stable `kid` (key ID) — the receipt's `verificationMethod` DID fragment references this `kid`

### 5.3 Signing Flow

```
Input context (OBOTokenContext)
         │
         ▼
1. Build unsigned receipt JSON-LD (all fields except `proof`)
         │
         ▼
2. Serialize to canonical form using JCS (RFC 8785)
         │
         ▼
3. SHA-256 hash the canonical bytes  → document_hash
         │
         ▼
4. Sign document_hash with Ed25519 private key
         │
         ▼
5. Base58btc-encode the 64-byte signature → proofValue
         │
         ▼
6. Attach `proof` object to receipt
         │
         ▼
7. Return signed receipt JSON-LD
```

**Pseudocode:**

```python
import json, hashlib, base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize  # RFC 8785

def mint_receipt(context: OBOTokenContext, private_key: Ed25519PrivateKey, key_id: str) -> dict:
    receipt = build_unsigned_receipt(context)          # dict, no `proof` field

    # Step 2-3: canonicalize then hash
    canonical_bytes = canonicalize(receipt)            # deterministic UTF-8 bytes
    document_hash = hashlib.sha256(canonical_bytes).digest()

    # Step 4-5: sign
    signature_bytes = private_key.sign(document_hash)  # Ed25519 signs the hash
    proof_value = base58.b58encode(signature_bytes).decode()

    receipt["proof"] = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": receipt["issuanceDate"],
        "verificationMethod": f"did:web:receipts.your-org.example#{key_id}",
        "proofPurpose": "assertionMethod",
        "proofValue": proof_value
    }
    return receipt
```

### 5.4 Verification Flow

```
Verifier receives receipt JSON-LD
         │
         ▼
1. Extract and remove `proof` object → unsigned_receipt
         │
         ▼
2. Resolve `proof.verificationMethod` DID fragment
   → fetch public key from JWKS endpoint (or local cache)
         │
         ▼
3. JCS-canonicalize unsigned_receipt → canonical_bytes
   SHA-256 hash → document_hash
         │
         ▼
4. Base58btc-decode `proof.proofValue` → signature_bytes
         │
         ▼
5. Ed25519 verify(document_hash, signature_bytes, public_key)
   → PASS or FAIL
         │
         ▼
6. Structural checks:
   a. `expirationDate` > now
   b. `issuanceDate` ≤ now + clock_skew (5 s)
   c. Delegation chain integrity (each hop links correctly)
   d. `grantedScopes` ⊆ scopes at root hop
         │
         ▼
7. Replay check: `nonce` not seen in verifier's nonce store
   (store nonces TTL = receipt `expirationDate`)
         │
         ▼
8. Return ReceiptVerificationResult { valid, claims, errors }
```

### 5.5 Trust Model

```
Receipt Issuer DID Document
  └── asserts: key-1 is a valid assertionMethod

Verifier resolves DID → gets JWKS → gets Ed25519 public key

No trust in receipt content required — signature speaks for itself.
The only trusted anchor is: "Does this DID/key belong to a trusted issuer?"
```

Verifiers should maintain a **trusted issuer registry** — a local allowlist of issuer DIDs or JWKS URIs they accept. Receipts from unknown issuers should be rejected even if the signature is mathematically valid.

### 5.6 JWKS Endpoint Contract

```jsonc
// GET /.well-known/jwks.json

{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "key-1",
      "use": "sig",
      "x": "<base64url public key bytes>"
    },
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "key-0",
      "use": "sig",
      "x": "<base64url retired public key bytes>"
    }
  ]
}
```

- Served over HTTPS only
- Cache-Control: `max-age=3600` (1 hour) — verifiers may cache
- On key rotation: new key appears; old key stays until its retirement window closes

### 5.7 Revocation (Optional Extension)

The base design is **revocation-free** (stateless verification). For use cases requiring revocation:

| Mechanism | When to use |
|---|---|
| **Short TTL receipts** (≤ 1 h) | Default — expiry is the revocation |
| **Status List 2021** (W3C) | When receipts must be revocable before expiry; adds a `credentialStatus` field pointing to a published bitstring |
| **JTI blocklist** | Simple: issuer publishes a signed list of revoked receipt IDs; verifier checks before accepting |

---

## 6. Security Considerations

| Threat | Mitigation |
|---|---|
| Receipt tampering | Ed25519 signature over JCS canonical form — any field change invalidates signature |
| Replay attack | Nonce stored by verifier for receipt lifetime; reject duplicates |
| Expired receipt reuse | `expirationDate` checked on every verification |
| Token leakage via receipt | Token digest only (SHA-256 hash), never raw token embedded |
| Parameter data leakage | `action.parameters` must be sanitized before mint — no bearer tokens, passwords, PII |
| Key compromise | Short rotation window (90 days); HSM/KMS for private key storage |
| Clock skew abuse | 5-second tolerance on `issuanceDate`; receipt TTL enforced by verifier |
| Chain inflation attack | Max delegation chain depth enforced (recommend: 5 hops) |

---

## 7. Open Questions — RESOLVED (2026-06-18)

All five carried over from the BMad session were decided with Jim on 2026-06-18.

| # | Question | Decision | Rationale |
|---|---|---|---|
| Q1 | JSON-LD context URL hosted or `did:web`? | **Defer both for v1.** Keep the placeholder `@context` URL; serve keys via the plain JWKS endpoint (`buildJwks`). Revisit `did:web` + hosted context at publish time. | Verification never dereferences the `@context` (JCS canonicalizes literal bytes), so hosting buys nothing yet. JWKS already covers key trust. Avoids premature infra. |
| Q2 | JCS (RFC 8785) vs. URDNA2015? | **Keep JCS.** | Already implemented + tested; the declared `eddsa-jcs-2022` cryptosuite is built on JCS, so we're standards-aligned. URDNA2015 only matters for heavy RDF/VC interop — defer until a partner requires it. |
| Q3 | Nonce store backing? | **In-process `Map` in the library; pluggable interface for Sprint 2.** Keep `NonceStore` as an interface so the HTTP service can drop in a Redis-backed impl when multi-replica. | Right scope for single-instance now; defers distributed-store cost without locking it out. |
| Q4 | Human-readable summary needed? | **Yes — embed a one-line plain-English summary field in the receipt.** Primary audience = **enterprise / compliance officers**; viewer leans audit-oriented. | Audit-log UIs can render the summary without running the CLI. Audience choice also resolves handoff open-decision #3. |
| Q5 | Chain max depth = 5? | **Keep 5.** Already a named constant (`MAX_CHAIN_DEPTH` in `builder.ts`). Consider exporting it so consumers/tests can reference it. | 5 covers human → service → agent → sub-agent → tool. Constant makes it tunable without code spelunking. |

### Resulting follow-up work (feeds Sprint 2 / backlog)
- **Q4 →** add an optional `summary: string` field to `OBOAuditReceipt` (and generate it at mint time from principals + action). *Schema change — see §4.*
- **Q5 →** done (constant exists); optionally export `MAX_CHAIN_DEPTH` from the barrel.
- **Q3 →** define a `NonceStore` interface boundary before adding the Redis impl in the HTTP service.

---

## 8. AT Protocol Publication

**Added 2026-07-16** (PM + Architect, Opus planning session). Extends §1–§7; nothing in §1–§7
changes. Implementation story: [`../stories/sprint_03.md`](../stories/sprint_03.md). Project note:
[[ATProto Receipts PoC]] · wiki [[AT Protocol as Agent Identity Substrate]].

### 8.1 Goal & scope

Give a minted receipt a **public, addressable, tamper-evident home** and give the issuer a
**portable, host-independent identity**, by publishing receipts as records in an AT Protocol
repository and letting any third party verify one from its `at://` URI with no keys and no auth.
This answers the prototype's largest open question — *who mints, where do receipts live, how are
they discovered* — and retires the deferred `did:web` issuer document (§7 Q1, Sprint 02 DoD) for
`did:plc`.

The atproto layer sits *around* the existing library; it does not modify the receipt schema
(§3–§4), the crypto (§5), or the trust model. **Anchoring decision:** single-issuer signing stays —
atproto adds **publication + discovery**, not a new trust model.

### 8.2 Identity model — two keys, one clean separation

| Role | Key / identity | Owner | Used for | Status |
|---|---|---|---|---|
| **Receipt signing** (trust anchor) | Ed25519 `key-1`, in JWKS; `proof.verificationMethod` | issuer *service* | Signing the payload; what `verifyReceipt()` checks | Unchanged from §5 |
| **Repo / publication** (addressing) | atproto account key behind a `did:plc` | issuer *agent account* on a PDS | Authenticating `putRecord`; owning the repo | New |

The `did:plc` is *where the receipt lives and who published it*; `key-1` is *what proves the
contents authentic*. A verifier fetching from an `at://` URI still verifies the **Ed25519 proof**
exactly as today — atproto changes discovery, not the check.

**Why `did:plc` over `did:web`:** portable/host-independent (survives a PDS move via account
migration), key rotation without identity loss, resolvable through the PLC directory. Trade-off:
depends on the PLC directory as availability/neutrality anchor (being spun out to an independent
Swiss association). Acceptable for a PoC. The receipt's `issuer` field may migrate to the `did:plc`
later — kept **decoupled** from the repo identity for v1 (Q8).

### 8.3 Lexicon & record design

**NSID.** The early working name `receipts.obo.v1` is not a valid NSID (NSIDs are reverse-DNS, the
last segment is the type name, versioning lives in the name not a trailing segment). Use:

```
dev.delegationreceipts.auditReceipt      # collection NSID; record $type must equal this
```

Authority domain `delegationreceipts.dev` is a **placeholder we intend to control**. Publishing the
*lexicon schema record* + PDS validation needs a `_lexicon` DNS TXT record under that domain; the
PoC does **not** need it — records are written with the PDS's **optimistic ("fail-open") validation**,
which allows unknown-lexicon records (Q9).

**Architectural risk — CBOR round-trip vs. the JCS signature.** The receipt is signed with
`eddsa-jcs-2022` (JCS-canonicalize minus `proof` → SHA-256 → Ed25519); verification re-canonicalizes.
atproto stores records as **DAG-CBOR** and can re-serialize to JSON, where a naive field-by-field
mapping can silently break the signature: DAG-CBOR **disallows floats** (receipt is int-only today —
latent trap if `action.parameters` ever holds a float), and records carry a reserved top-level
`$type`. **Decision D-1: store the signed receipt verbatim.** The atproto record is a **wrapper**;
the complete signed receipt is stored as an **opaque JSON string** so DAG-CBOR never touches the
signed payload, with a few **indexed mirror** fields for discovery. On read, `JSON.parse` the string
→ exact receipt → `verifyReceipt()` unchanged. Native field mapping is deferred behind a round-trip
fixture test (Q10).

Draft lexicon `dev.delegationreceipts.auditReceipt` — a `record` (key `any`, rkey = the receipt's
ULID) whose required fields are `receiptJson` (verbatim signed payload, the only trusted field) plus
indexed mirrors `issuer` (did), `subject` (at-identifier), `issuanceDate`/`expirationDate` (datetime),
`summary`, `schemaVersion` (`obo-receipt/v1`). Mirrors are untrusted; a verifier relies solely on
`receiptJson` + the Ed25519 proof, and checks the mirrors match before display. Full JSON in
`sprint_03.md` Task 1 / the 2026-07-16 addendum.

**Addressing:** `at://did:plc:<issuer>/dev.delegationreceipts.auditReceipt/<receipt-ULID>`.

### 8.4 Publish flow

```
mintReceipt() → signed receipt
  → buildRecord(receipt)  { $type, receiptJson, issuer, subject, dates, summary }
  → createSession(identifier, appPassword) → accessJwt          [auth — see caveat]
  → com.atproto.repo.putRecord(repo=did:plc:<issuer>,
        collection=dev.delegationreceipts.auditReceipt,
        rkey=receipt.id, record=wrapper, validate=false)        → at:// URI
```

**Headless-auth caveat.** atproto OAuth scopes are still stabilizing and OAuth is not yet recommended
for headless bots (mid-2026). **Decision D-2:** authenticate with an **app password** via
`com.atproto.server.createSession`, isolated behind an `AtpAuth` seam so OAuth can replace it later
without touching publish/verify (Q7).

### 8.5 Verify-from-`at://` flow (the headline)

```
at:// URI (verifier holds no keys, no auth)
  1. parse at:// → { did, collection, rkey }
  2. resolve did:plc → DID doc → PDS endpoint            (PLC directory)
  3. com.atproto.repo.getRecord(...)                     (public GET, no auth)
  4. record.receiptJson → JSON.parse → receipt; confirm indexed mirrors match
  5. verifyReceipt(receipt, issuerKey)                   (unchanged §5 logic)
  6. return { valid, errors } + renderReceipt
```

Step 5 is the existing verifier, untouched. atproto contributes steps 1–4 + the mirror-integrity
check. Nonce/expiry semantics are unchanged.

### 8.6 Design-for-live, mock-for-now (decided 2026-07-16)

The path is **architected for the real Bluesky/`did:plc` network** (app-password auth, real
`putRecord`/`getRecord`, real PLC resolution), but sprint_03's **CI-testable path runs against a
local/mock PDS** implementing the exact `putRecord`/`getRecord` XRPC shapes — deterministic, no live
account. A single manual live publish is the sprint's stretch task; swapping the mock for a real PDS
client is a config change, not a rewrite.

### 8.7 Open questions (continuing §7's registry)

| # | Question | Leaning |
|---|---|---|
| Q6 | Wrapper record vs. verbatim-string storage of the signed payload | **Decided (D-1): verbatim string + indexed mirrors** for v1 |
| Q7 | Headless auth: app password vs. OAuth | **Decided (D-2): app password** behind an `AtpAuth` seam; revisit OAuth when scopes stabilize |
| Q8 | Should `receipt.issuer` become the `did:plc`, or stay decoupled from the repo identity? | **Decoupled for v1**; unifying is a v2 option |
| Q9 | Own `delegationreceipts.dev`, publish the lexicon schema record + `_lexicon` DNS TXT, strict validation | Later; PoC uses optimistic validation |
| Q10 | Native field-by-field lexicon mapping, gated on a CBOR round-trip fixture test | v2, only after the round-trip proves signature-stable |
| Q11 | Firehose/discovery: announce receipts (labeler/feed) or only fetch by known `at://` URI? | Out of scope for sprint_03; connects to the KYA-labeler follow-on |

---

*Document maintained in `.bmad/docs/`. §1–§7 from the 2026-06-18 BMad session; §8 added 2026-07-16.
Next artifact: `EPIC-001.md` (implementation epics).*
