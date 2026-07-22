---
type: diagram
date: 2026-07-18
status: active
tags: [delegation-receipts, architecture, sequence-diagram, atproto]
---

# Delegation Receipt — Full Lifecycle Sequence

High-level design of the `delegation-receipts` software, end to end: build & sign a receipt (issuer side), publish it to an AT Protocol repository, and verify it from its `at://` URI with no keys and no auth. Source of truth: [[Agent Delegation Receipts - Project Brief]] · spec [`.bmad/docs/PRD_ARCH.md`](.bmad/docs/PRD_ARCH.md) (§8) · [`README.md`](README.md) · atproto layer [[ATProto Receipts PoC]].

The key idea: **the Ed25519 signature is the single source of truth end to end.** The HTTP issuer service and the atproto layer both wrap the same core mint/verify pair rather than replacing it — atproto adds *where the receipt lives and how it's discovered*, not a new trust model.

```mermaid
sequenceDiagram
    autonumber
    actor App as Issuer app / orchestrator
    participant B as builder<br/>extractContext()
    participant S as signer<br/>mintReceipt()
    participant K as KeyStore<br/>(HSM/KMS, key-1)
    participant P as atproto<br/>publishReceipt()
    participant PDS as PDS<br/>(AT Proto repo)
    actor V as Verifier<br/>(3rd party, no keys)
    participant PLC as PLC directory
    participant VF as verifyFromUri()
    participant VR as verifyReceipt()

    rect rgb(237,242,247)
    note over App,K: 1 — Build & sign (issuer side)
    App->>B: extractContext(rawInput)
    note right of B: SHA-256 digest each token,<br/>sort chain, validate rules<br/>(linkage, scope subset, depth<=5)
    B-->>App: OBOTokenContext
    App->>S: mintReceipt(context, kid, issuerDid)
    S->>K: get private key-1
    K-->>S: Ed25519 private key
    note right of S: build unsigned JSON-LD ->
JCS canonicalize (RFC 8785) ->
SHA-256 -> Ed25519 sign ->
attach proof
    S-->>App: signed OBOAuditReceipt
    end

    rect rgb(237,247,240)
    note over App,PDS: 2 — Publish to AT Protocol
    App->>P: publishReceipt(receipt, did:plc)
    note right of P: buildRecord: verbatim<br/>receiptJson + indexed mirrors
    P->>PDS: createSession(identifier, appPassword)
    PDS-->>P: accessJwt
    P->>PDS: putRecord(collection, rkey, validate=false)
    PDS-->>P: at:// URI
    P-->>App: at://did:plc:.../.../rkey
    end

    rect rgb(245,240,247)
    note over V,VR: 3 — Verify from at:// URI (no auth)
    V->>VF: verifyFromUri(at:// URI, issuer JWKS)
    note right of VF: parse URI -> did, collection, rkey
    VF->>PLC: resolve did:plc
    PLC-->>VF: DID doc -> PDS endpoint
    VF->>PDS: getRecord (public, no auth)
    PDS-->>VF: record
    note right of VF: JSON.parse receiptJson,<br/>check mirrors match payload
    VF->>VR: verifyReceipt(receipt, issuerKey)
    note right of VR: nonce replay, Ed25519 sig over<br/>JCS, expiry, clock skew,<br/>chain integrity, scope subset
    VR-->>VF: { valid, errors }
    VF-->>V: { valid, errors, receipt, render }
    end
```

## Reading the three phases

**1 — Build & sign (issuer side).** `extractContext()` takes raw token input, SHA-256-digests each token (the raw token is never stored), sorts and validates the delegation chain, and returns an `OBOTokenContext`. `mintReceipt()` builds the unsigned JSON-LD receipt, JCS-canonicalizes it (RFC 8785), hashes it, and signs with the issuer's Ed25519 `key-1`.

**2 — Publish to AT Protocol.** `publishReceipt()` wraps the signed receipt *verbatim* as an opaque `receiptJson` string — so DAG-CBOR re-serialization can never break the JCS signature — plus indexed mirror fields for discovery. It authenticates with an app password and `putRecord`s the wrapper, returning an `at://` URI: a public, addressable, tamper-evident home for the receipt.

**3 — Verify from the URI.** Anyone with just the URI and the issuer's public JWKS can verify, with no auth. `verifyFromUri()` resolves the `did:plc` through the PLC directory to the PDS endpoint, fetches the record, confirms the untrusted mirror fields match the payload, then hands the untouched receipt to the same `verifyReceipt()` from phase 1.
