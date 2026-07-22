# Publishing `dev.scopetrail.auditReceipt` as an atproto lexicon schema record

Research pass for Sprint 05 Task 4. Sources are the current (accessed 2026-07-22) atproto.com
spec/guide pages, fetched live rather than reconstructed from memory or the 2026-07-16 capture in
`.bmad/docs/atproto_reference.md` (which predates this sprint and turns out to still be directionally
correct, but this doc is the authoritative version going forward).

## Sources

- [Lexicon spec — "Lexicon Publication and Resolution" + "Authority and Control"](https://atproto.com/specs/lexicon) — accessed 2026-07-22
- [Publishing Lexicons guide](https://atproto.com/guides/publishing-lexicons) — accessed 2026-07-22
- [Namespaced Identifiers (NSID) spec](https://atproto.com/specs/nsid) — accessed 2026-07-22
- [Record Key spec](https://atproto.com/specs/record-key) — accessed 2026-07-22

## What's actually required

### 1. The record type

Lexicon schemas are published as ordinary atproto records of type `com.atproto.lexicon.schema`,
written into the authority's own repo — there is no separate registry. The record shape:

- `$type`: fixed `com.atproto.lexicon.schema`
- `lexicon`: integer, `1` (same field as in the lexicon JSON file itself)
- `id`: the NSID of the schema being published — **must be a simple NSID with no `#` fragment,
  and must match the record key**
- `defs`: the same map-of-definitions as the lexicon file's `defs`
- `description`: optional

In practice this means the `com.atproto.lexicon.schema` record is (almost) the lexicon JSON file
itself, with `$type` added. Nothing about the lexicon's semantics changes — the wrapping is just
an envelope. Our `lexicons/dev.scopetrail.auditReceipt.json` source file is untouched; the publish
script reads it and adds `$type` when constructing the record, never edits the file on disk.

### 2. Record key

Record key type: `nsid` (per the Record Key spec) — the rkey must itself be a syntactically valid
NSID, and per the Lexicon spec it "must match" the `id` field. So for us: **rkey =
`dev.scopetrail.auditReceipt`**, same string as `id`.

### 3. DNS `_lexicon` TXT delegation

Authority for an NSID is the domain-authority portion (everything except the final "name"
segment), reversed into a normal hostname. For `dev.scopetrail.auditReceipt`:

- name segment: `auditReceipt`
- domain authority: `dev.scopetrail`
- reversed → hostname: `scopetrail.dev`

The DNS TXT record name is `_lexicon.<authority-domain>`, i.e. **`_lexicon.scopetrail.dev`**, and
its value is **`did=<issuer DID>`** (the literal `did=` prefix is part of the value, same
convention as `_atproto` handle-verification TXT records but a distinct record name/purpose).

Two details that matter and are easy to get wrong:

- **Resolution is not hierarchical.** A resolver looks up exactly `_lexicon.scopetrail.dev` and,
  if that fails, does **not** walk up to `_lexicon.dev` or down into subdomains. One TXT record
  per authority-domain, no fallback.
- **Authority is scoped to the whole NSID group, not just this one NSID.** Every NSID that shares
  the same domain-authority prefix (`dev.scopetrail.*`, e.g. a future `dev.scopetrail.someOtherThing`)
  resolves through the *same* `_lexicon.scopetrail.dev` record and therefore must live in the
  *same* repo (same DID). If we ever split NSIDs across repos, each distinct authority prefix needs
  its own TXT record.

### 4. Which repo the schema record lives in

Whatever DID the `_lexicon.scopetrail.dev` TXT record points to is the repo that must hold the
`com.atproto.lexicon.schema` record at rkey `dev.scopetrail.auditReceipt`. There is no requirement
that this be the same DID that *issues* audit receipts (`dev.scopetrail.auditReceipt` data
records) — those are two independent roles (schema authority vs. receipt issuer) that happen to
share an NSID prefix. See the Jim's Turn handoff for the account tradeoff.

### 5. Resolution walk (what a verifier's client actually does)

1. Start from the NSID `dev.scopetrail.auditReceipt`.
2. DNS-over-HTTPS TXT lookup on `_lexicon.scopetrail.dev`.
3. Parse `did=...` from the TXT value → resolve that DID (standard atproto DID resolution, e.g.
   PLC directory) → find its PDS.
4. `com.atproto.repo.getRecord` against that PDS: `collection=com.atproto.lexicon.schema`,
   `rkey=dev.scopetrail.auditReceipt`.
5. If any step fails, resolution fails outright — no fallback path.

### 6. Validation is a separate, optional layer

Publishing the schema record does **not**, by itself, force strict validation anywhere. A PDS has
three validation modes when writing a record (explicit-required, explicit-none, or the default
"optimistic"/fail-open — accepts records under an unknown/unresolvable lexicon). `dev.scopetrail.auditReceipt`
records are already being written with `validate: false` (`src/atproto/publish.ts`) and that does
not need to change; publishing the schema record makes strict validation *possible* for clients
that choose to opt into it, it doesn't retroactively require it.

### 7. Tooling

Bluesky's `goat` CLI (`goat lex publish`) is the sanctioned tool for this, but it's an external
binary requiring its own login flow — not something to shell out to from this repo's own scripts
without adding a new dependency/credential path. Since the underlying operation is just a
`putRecord` against a known collection/rkey, and this repo already has a working `AtpClient` +
`AtpAuth` + `DidResolver` seam (`src/atproto/client.ts`, `src/atproto/auth.ts`), the publish script
in this repo (`scripts/publish-lexicon-record.mjs`) builds and writes the record directly through
that same seam rather than depending on `goat`. This keeps the lexicon-record publish path testable
against the existing mock PDS the same way `scripts/publish-receipt-task6.mjs` is.

## No change to signed-payload semantics

None of the above touches `src/signer.ts`, `verifyReceipt`, canonicalization, `buildJwks`, or any
field of the signed `OBOAuditReceipt`. The `com.atproto.lexicon.schema` record is a completely
separate collection/NSID (`com.atproto.lexicon.schema`, not `dev.scopetrail.auditReceipt`) that
happens to describe the shape of the receipt wrapper — it does not wrap, sign, or otherwise touch
any receipt data. `lexicons/dev.scopetrail.auditReceipt.json` is read verbatim; its `defs` are
copied into the schema record without modification.
