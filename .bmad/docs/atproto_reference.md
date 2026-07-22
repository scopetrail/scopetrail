# AT Protocol — Implementation Reference (for sprint_03)

**Captured 2026-07-16** from the atproto.com specs so the build doesn't need live fetches.
Scope = only what sprint_03 touches: publishing a receipt record and verifying it from an `at://`
URI. Source URLs + section anchors are inline; re-check them only if something below looks stale.

> Facts marked **[fetched]** are transcribed from the spec pages pulled 2026-07-16 (Lexicon,
> Identity, AT-URI). Facts marked **[stable-API]** are the long-standing `com.atproto.*` XRPC
> shapes from working knowledge — confirm exact field names against the live lexicon JSON the first
> time you call each endpoint, then delete this caveat.

---

## 1. NSID (Namespaced Identifier) — the collection name

Source: https://atproto.com/specs/lexicon (§Lexicon Publication) · https://atproto.com/specs/nsid **[fetched]**

- NSIDs are **reverse-DNS**: authority domain reversed + a final "name" segment. Versioning goes in
  the *name*, not a trailing segment.
- Our collection: **`dev.delegationreceipts.auditReceipt`** → authority `delegationreceipts.dev`,
  name `auditReceipt`.
- A record's `$type` **must equal** the NSID. The `at://` collection segment is the NSID.
- **Authority = DNS control.** Publishing the *lexicon schema record* (type `com.atproto.lexicon.schema`,
  rkey = the NSID) and having PDSes validate against it requires a DNS TXT record
  `_lexicon.delegationreceipts.dev` with value `did=did:plc:...`. Resolution is **not** hierarchical
  (no walking up/down the domain). **We skip all of this for the PoC** — see validation below.

## 2. Lexicon record definition (what we author)

Source: https://atproto.com/specs/lexicon (§Primary Types → Record) **[fetched]**

A Lexicon file: `{ "lexicon": 1, "id": "<NSID>", "defs": { "main": { ... } } }`. The primary def is
`main`, type `record`, with:

- `key` — record-key type. **`"any"`** lets us use the receipt's ULID as the rkey (stable, sortable).
- `record` — an `object` schema (`properties`, `required`, optional `nullable`).

Field types we use: `string` (with `format`, `maxLength`, `const`), and that's it — the signed
payload rides as a `string`. String `format` values available include `did`, `at-identifier`,
`at-uri`, `datetime`, `nsid`, `tid`, `record-key`, `cid`, `uri`. `datetime` = strict RFC-3339 with
upper-case `T` and required timezone (prefer `Z`).

Lexicon **evolution** rules (matter once published): new fields must be optional; can't remove
non-optional fields, change types, or rename fields — a breaking change needs a new NSID.

## 3. Data-model constraints — why we store the receipt verbatim

Source: https://atproto.com/specs/data-model, https://atproto.com/specs/lexicon **[fetched]**

- Records are stored as **DAG-CBOR** and can be re-serialized to JSON. Round-tripping a signed
  JSON-LD receipt field-by-field through CBOR can break the `eddsa-jcs-2022` signature.
- **Floats are disallowed** in the data model. The receipt is int-only today (`maxLength: 500`); a
  float ever appearing in `action.parameters` would make the record unstorable.
- Reserved JSON keys are **`$`-prefixed** (`$type`, `$link`, `$bytes`). The receipt's JSON-LD keys
  are `@`-prefixed (`@context`, `@type`) → no direct collision, but the record's own required
  `$type` is an extra field that must **not** end up inside the signed payload.
- **Consequence (sprint_03 D-1):** store the whole signed receipt as an **opaque JSON string**
  (`receiptJson`); DAG-CBOR never parses it. Duplicate a few fields as untrusted indexed mirrors.
  Native mapping only after a fixture test proves a mint→putRecord→getRecord round-trip still verifies.

## 4. PDS validation options (how we publish without owning the domain)

Source: https://atproto.com/specs/lexicon (§Validation Options) **[fetched]**

Three modes on create/update: explicit-validate, explicit-no-validate, and **optimistic (default)** —
if the PDS knows the lexicon it validates, otherwise it allows the record ("fail-open"). **PoC uses
optimistic / `validate: false`**, so we can publish under our NSID before the schema record + DNS
exist. The PDS success response flags whether validation actually ran.

## 5. XRPC endpoints we call

Source: https://atproto.com/specs/xrpc, https://atproto.com/guides/reads-and-writes **[stable-API]**

All are HTTP under `<PDS>/xrpc/<nsid>`. JSON in/out.

**Auth — app password (headless path):**
```
POST /xrpc/com.atproto.server.createSession
body: { "identifier": "<handle-or-did>", "password": "<app-password>" }
→    { "accessJwt", "refreshJwt", "handle", "did" }
```
App passwords are created in account settings (format `xxxx-xxxx-xxxx-xxxx`); they can't change
account auth/email, which is why they suit a bot. OAuth is the eventual replacement once headless
scopes stabilize (not yet, mid-2026).

**Write a receipt:**
```
POST /xrpc/com.atproto.repo.putRecord            (Authorization: Bearer <accessJwt>)
body: { "repo": "did:plc:<issuer>",
        "collection": "dev.delegationreceipts.auditReceipt",
        "rkey": "<receipt ULID>",
        "record": { "$type": "dev.delegationreceipts.auditReceipt", ... },
        "validate": false }
→    { "uri": "at://...", "cid": "..." }
```
(`createRecord` is the same minus `rkey`, which it auto-assigns a TID. We want a deterministic rkey,
so `putRecord`.)

**Read a receipt (public — no auth):**
```
GET /xrpc/com.atproto.repo.getRecord?repo=did:plc:<issuer>&collection=dev.delegationreceipts.auditReceipt&rkey=<ULID>
→    { "uri", "cid", "value": { ...the record... } }
```
`getRecord` is unauthenticated, which is what makes "verify from an `at://` URI with no keys" work.
Resolve `repo` DID → PDS host first (see §6); `getRecord` runs against that host.

## 6. Identity: did:plc resolution

Source: https://atproto.com/guides/identity, https://atproto.com/specs/did **[fetched]**

- Every account has a DID (mostly **`did:plc`**), host-independent and stable.
- Resolve a `did:plc` via the **PLC directory** → a **DID document** containing the account's signing
  key(s) and its **PDS `serviceEndpoint`** (the host to call `getRecord`/`putRecord` on).
- Handles (DNS names) resolve to a DID via DNS TXT `_atproto.<handle>` or an HTTPS well-known
  endpoint, confirmed by the DID doc. For records, **address by DID, not handle** (handles can change).
- We keep the receipt's Ed25519 signing key (JWKS / `proof.verificationMethod`) **separate** from the
  did:plc account key — the did:plc is publication identity, not the receipt trust anchor.

## 7. AT URI structure

Source: https://atproto.com/specs/at-uri-scheme **[fetched]**

Restricted form used in Lexicons:
```
AT-URI     = "at://" AUTHORITY [ "/" COLLECTION [ "/" RKEY ] ]
AUTHORITY  = HANDLE | DID          (use DID for durable record refs)
COLLECTION = NSID
RKEY       = record key            (case-sensitive, not normalized)
```
Ours: `at://did:plc:<issuer>/dev.delegationreceipts.auditReceipt/<receipt-ULID>`.

Parsing notes: the authority is a DID here, so **don't** use a URL parser that splits `host:port`
(Go `net/url` and most Rust URL crates break on DIDs; Python `urllib` and JS `url-parse` are fine —
for us, parse by hand: strip `at://`, split on `/` into did / collection / rkey). No trailing slash;
no query/fragment in record refs. An `at://` ref is **not** content-addressed — record contents can
change; use a CID alongside if a strong reference is ever needed.

---

## Source links (for deeper re-fetch if needed)

- Lexicon spec — https://atproto.com/specs/lexicon
- Data Model — https://atproto.com/specs/data-model
- NSID — https://atproto.com/specs/nsid
- Identity guide — https://atproto.com/guides/identity · DID spec — https://atproto.com/specs/did
- AT URI scheme — https://atproto.com/specs/at-uri-scheme
- Reads and Writes — https://atproto.com/guides/reads-and-writes · XRPC — https://atproto.com/specs/xrpc
- OAuth / headless-scope status — https://docs.bsky.app/blog/oauth-atproto · https://github.com/bluesky-social/atproto/discussions/4118

*Reference for `sprint_03.md`; pairs with `PRD_ARCH.md` §8. Delete the [stable-API] caveat in §5 once
the endpoint field names are confirmed against a live PDS.*
