#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * publish-lexicon-record.mjs — Sprint 05 Task 4.
 *
 * Publishes `lexicons/dev.scopetrail.auditReceipt.json` as a `com.atproto.lexicon.schema` record,
 * so the NSID `dev.scopetrail.auditReceipt` is resolvable the atproto-native way (per
 * docs/lexicon-publication.md, researched fresh for this task — atproto.com/specs/lexicon,
 * accessed 2026-07-22).
 *
 * The lexicon source file itself is read and copied verbatim into the record's `defs` — this
 * script never edits `lexicons/dev.scopetrail.auditReceipt.json` on disk, and does not import
 * from `../dist/signer.js` or touch any signed-receipt logic. It is a completely separate
 * collection (`com.atproto.lexicon.schema`) from the one that holds actual receipts
 * (`dev.scopetrail.auditReceipt`, imported from dist so this always agrees with whatever NSID
 * Task 1/2's build actually shipped) — publishing the schema record does not wrap, sign, or
 * modify any receipt data.
 *
 * Record shape (docs/lexicon-publication.md §1-2):
 *   $type:   'com.atproto.lexicon.schema'
 *   lexicon: 1                                   (copied from the lexicon file)
 *   id:      '<NSID>'                             (copied from the lexicon file's "id")
 *   defs:    { ... }                               (copied verbatim from the lexicon file)
 *   rkey:    same string as "id" (record-key type `nsid` — rkey must equal id)
 *
 * Two modes, same convention as scripts/publish-receipt-task6.mjs:
 *
 *   --mock (default, or bare `--dry-run`): publish + read back the schema record against the
 *     in-memory mock PDS (src/atproto/mock-pds.ts). No network of any kind. Asserts the
 *     round-tripped record matches what was sent and exits non-zero if not.
 *
 *   --live: the real thing (Jim only — needs credentials). Requires ATP_PDS, ATP_IDENTIFIER,
 *     ATP_APP_PASSWORD in the environment; missing any of them prints a clear message and exits
 *     non-zero WITHOUT attempting any network call. Does NOT set the `_lexicon` DNS TXT record —
 *     that's a separate, Jim-gated registrar step (see docs/lexicon-publication.md and the
 *     "Lexicon schema record" section of the Sprint 05 Jim's Turn note).
 *
 * Run from the package root (after `npm run build`):
 *   node scripts/publish-lexicon-record.mjs --mock
 *   node scripts/publish-lexicon-record.mjs --live        # Jim only, needs env vars
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { AppPasswordAuth, FakeAuth, FAKE_ACCESS_JWT } from '../dist/atproto/auth.js';
import { AtpClient, FetchTransport, createPlcDidResolver } from '../dist/atproto/client.js';
import { MockPds, createMockDidResolver, MOCK_TEST_DID, MOCK_PDS_URL } from '../dist/atproto/mock-pds.js';
import { RECEIPT_NSID } from '../dist/atproto/record.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LEXICON_SCHEMA_COLLECTION = 'com.atproto.lexicon.schema';
const LEXICON_JSON_PATH = join(__dirname, '..', 'lexicons', 'dev.scopetrail.auditReceipt.json');

function parseArgs(argv) {
  const args = argv.slice(2);
  const live = args.includes('--live');
  return { live };
}

/** Load the lexicon source file verbatim — read-only, never written to by this script. */
function loadLexicon(path) {
  const parsed = JSON.parse(readFileSync(path, 'utf8'));
  if (parsed.lexicon !== 1) {
    throw new Error(`${path}: expected "lexicon": 1, got ${JSON.stringify(parsed.lexicon)}`);
  }
  if (!parsed.id || typeof parsed.id !== 'string') {
    throw new Error(`${path}: missing or invalid "id"`);
  }
  if (!parsed.defs || typeof parsed.defs !== 'object') {
    throw new Error(`${path}: missing or invalid "defs"`);
  }
  return parsed;
}

/**
 * Build the `com.atproto.lexicon.schema` record for a lexicon document (docs/lexicon-publication.md
 * §1). Copies `lexicon`, `id`, `defs`, and `description` (if present) verbatim; adds `$type`.
 * Does not mutate the input.
 */
function buildSchemaRecord(lexicon) {
  const record = {
    $type: LEXICON_SCHEMA_COLLECTION,
    lexicon: lexicon.lexicon,
    id: lexicon.id,
    defs: lexicon.defs,
  };
  if (lexicon.description) {
    record.description = lexicon.description;
  }
  return record;
}

/**
 * Derive the `_lexicon` DNS authority domain for an NSID (docs/lexicon-publication.md §3):
 * drop the final "name" segment, reverse the remaining "domain authority" segments.
 * `dev.scopetrail.auditReceipt` -> `scopetrail.dev`.
 */
function authorityDomainForNsid(nsid) {
  const segments = nsid.split('.');
  if (segments.length < 3) {
    throw new Error(`authorityDomainForNsid: "${nsid}" does not have at least 3 segments`);
  }
  const authoritySegments = segments.slice(0, -1); // drop the name segment
  return [...authoritySegments].reverse().join('.');
}

/**
 * Recursively sort object keys so two structurally identical values stringify identically,
 * regardless of key insertion order. Arrays are left in place — their order IS significant
 * (e.g. `defs.main.record.required`), so they must never be sorted.
 */
function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((k) => [k, canonicalize(value[k])])
    );
  }
  return value;
}

/**
 * Structural equality, insensitive to object key ORDER but sensitive to array order.
 *
 * A naive `JSON.stringify(a) === JSON.stringify(b)` is wrong here: a real PDS stores records as
 * DAG-CBOR, whose canonical form mandates map keys sorted by length first, then bytewise. So a
 * record read back from a live PDS has different key order than the object we sent, even though
 * it is byte-for-byte the same record. (Observed 2026-07-25: sent `$type, lexicon, id, defs`,
 * read back `id(2), defs(4), $type(5), lexicon(7)`.) The mock PDS hands back the same JS object
 * and so preserves insertion order, which is why --mock never caught this and --live "failed" on
 * a correct publish.
 */
function deepEqual(a, b) {
  return JSON.stringify(canonicalize(a)) === JSON.stringify(canonicalize(b));
}

// ── --mock / --dry-run: publish + read back against the in-memory mock PDS, no network ────────

async function runMock() {
  console.log('=== Sprint 05 Task 4 — DRY-RUN (--mock) against the in-memory mock PDS ===\n');

  const lexicon = loadLexicon(LEXICON_JSON_PATH);
  console.log(`Loaded lexicon: ${LEXICON_JSON_PATH}`);
  console.log(`  id:   ${lexicon.id}`);
  console.log(`  defs: ${Object.keys(lexicon.defs).join(', ')}`);

  if (lexicon.id !== RECEIPT_NSID) {
    throw new Error(
      `Lexicon file id "${lexicon.id}" does not match the built RECEIPT_NSID "${RECEIPT_NSID}" ` +
        `(dist/atproto/record.js) — these must agree.`
    );
  }

  const record = buildSchemaRecord(lexicon);
  const rkey = lexicon.id; // record-key type `nsid`: rkey must equal id (docs/lexicon-publication.md §2)
  const authorityDomain = authorityDomainForNsid(lexicon.id);

  console.log(`\nCollection:      ${LEXICON_SCHEMA_COLLECTION}`);
  console.log(`Record key:      ${rkey}`);
  console.log(`_lexicon DNS:    _lexicon.${authorityDomain}  TXT  "did=<authority DID>"`);

  console.log('\n--- Step 1: publish the schema record to the mock PDS ---');
  const pds = new MockPds([FAKE_ACCESS_JWT]);
  const auth = new FakeAuth();
  const didResolver = createMockDidResolver({ [MOCK_TEST_DID]: MOCK_PDS_URL });
  const client = new AtpClient({ auth, transport: pds, didResolver });

  const putResult = await client.putRecord({
    repo: MOCK_TEST_DID,
    collection: LEXICON_SCHEMA_COLLECTION,
    rkey,
    record,
    validate: false,
  });
  const uri = putResult.uri;
  console.log(`Published (mock): ${uri}`);
  if (!uri.includes(`/${LEXICON_SCHEMA_COLLECTION}/${rkey}`)) {
    throw new Error(`Published URI does not carry the expected collection/rkey: ${uri}`);
  }

  console.log('\n--- Step 2: read the record back and verify it round-trips unchanged ---');
  const got = await client.getRecord({ repo: MOCK_TEST_DID, collection: LEXICON_SCHEMA_COLLECTION, rkey });
  const roundTripOk = deepEqual(got.value, record);
  console.log(`Round-trip match: ${roundTripOk}`);
  if (!roundTripOk) {
    console.error('Fetched record does not match what was published:');
    console.error('  sent:', JSON.stringify(record));
    console.error('  got: ', JSON.stringify(got.value));
    process.exit(1);
  }

  console.log('\n--- Step 3: sanity checks ---');
  const checks = [
    ['record.$type === com.atproto.lexicon.schema', got.value.$type === LEXICON_SCHEMA_COLLECTION],
    ['record.id === rkey (record-key type nsid)', got.value.id === rkey],
    ['record.id === lexicon file id', got.value.id === lexicon.id],
    ['record.defs deep-equals lexicon file defs', deepEqual(got.value.defs, lexicon.defs)],
  ];
  let allOk = true;
  for (const [label, ok] of checks) {
    console.log(`  ${ok ? 'OK  ' : 'FAIL'} ${label}`);
    if (!ok) allOk = false;
  }
  if (!allOk) {
    console.error('\nFAILED: one or more sanity checks failed.');
    process.exit(1);
  }

  console.log('\n=== SUMMARY ===');
  console.log(`NSID:              ${lexicon.id}`);
  console.log(`Collection:        ${LEXICON_SCHEMA_COLLECTION}`);
  console.log(`Record key:        ${rkey}`);
  console.log(`at:// URI (mock):  ${uri}`);
  console.log(`_lexicon DNS TXT:  _lexicon.${authorityDomain}  "did=<authority DID>"`);
  console.log('\nDRY-RUN OK — the real publish (a live PDS account + registrar DNS change) is');
  console.log('Jim-gated; run with --live (+ ATP_PDS/ATP_IDENTIFIER/ATP_APP_PASSWORD) when ready,');
  console.log('then set the _lexicon TXT record at the registrar for the DID that published it.');
}

// ── --live: the real thing (Jim only) ──────────────────────────────────────────────────────────

async function must(name) {
  const v = process.env[name];
  return v || null;
}

async function runLive() {
  const service = await must('ATP_PDS');
  const rawIdentifier = await must('ATP_IDENTIFIER');
  const appPassword = await must('ATP_APP_PASSWORD');

  if (!service || !rawIdentifier || !appPassword) {
    console.error('--live requires ATP_PDS, ATP_IDENTIFIER, and ATP_APP_PASSWORD in the environment.');
    console.error('None of these were used and no network call was attempted.');
    console.error(
      'Missing: ' +
        [!service && 'ATP_PDS', !rawIdentifier && 'ATP_IDENTIFIER', !appPassword && 'ATP_APP_PASSWORD']
          .filter(Boolean)
          .join(', ')
    );
    console.error('\nRun the dry-run instead: node scripts/publish-lexicon-record.mjs --mock');
    process.exit(1);
  }

  const identifier = rawIdentifier.replace(/^@/, '');

  console.log('=== Sprint 05 Task 4 — LIVE publish of the com.atproto.lexicon.schema record ===\n');

  const lexicon = loadLexicon(LEXICON_JSON_PATH);
  if (lexicon.id !== RECEIPT_NSID) {
    throw new Error(
      `Lexicon file id "${lexicon.id}" does not match the built RECEIPT_NSID "${RECEIPT_NSID}" ` +
        `(dist/atproto/record.js) — these must agree.`
    );
  }
  const record = buildSchemaRecord(lexicon);
  const rkey = lexicon.id;
  const authorityDomain = authorityDomainForNsid(lexicon.id);

  console.log('--- Step 1: authenticate + resolve the publishing DID ---');
  const auth = new AppPasswordAuth({ service, identifier, appPassword });
  const session = await auth.session();
  const issuerDid = session.did;
  console.log(`Authenticated as ${identifier} -> ${issuerDid}`);
  console.log('\nThis is the DID that MUST be the target of the _lexicon DNS TXT record — see');
  console.log(`docs/lexicon-publication.md and set _lexicon.${authorityDomain} = "did=${issuerDid}"`);
  console.log('at the registrar (separate, Jim-gated step; not performed by this script).');

  console.log('\n--- Step 2: publish the schema record ---');
  const client = new AtpClient({
    auth,
    transport: new FetchTransport(),
    didResolver: createPlcDidResolver(),
  });
  const putResult = await client.putRecord({
    repo: issuerDid,
    collection: LEXICON_SCHEMA_COLLECTION,
    rkey,
    record,
    validate: false,
  });
  console.log(`Published: ${putResult.uri}`);

  console.log('\n--- Step 3: read the record back and verify it round-trips unchanged ---');
  const got = await client.getRecord({ repo: issuerDid, collection: LEXICON_SCHEMA_COLLECTION, rkey });
  const roundTripOk = deepEqual(got.value, record);
  console.log(`Round-trip match: ${roundTripOk}`);
  if (!roundTripOk) {
    console.error('FAILED: fetched record does not match what was published.');
    console.error('  sent:', JSON.stringify(record));
    console.error('  got: ', JSON.stringify(got.value));
    console.error('\n  (comparison is key-order insensitive — a mismatch here is a real');
    console.error('   structural difference, not DAG-CBOR key reordering.)');
    process.exit(1);
  }

  console.log('\n=== SUMMARY ===');
  console.log(`NSID:              ${lexicon.id}`);
  console.log(`Published DID:     ${issuerDid}`);
  console.log(`at:// URI:         ${putResult.uri}`);
  console.log(`_lexicon DNS TXT:  _lexicon.${authorityDomain}  "did=${issuerDid}"`);
  console.log('\nDNS is a separate step — resolution will not work until the TXT record above is');
  console.log('live at the registrar. Record the at:// URI and DNS values in the project note.');
}

async function main() {
  const { live } = parseArgs(process.argv);
  if (live) {
    await runLive();
    return;
  }
  await runMock();
}

main().catch((err) => {
  console.error('FAILED:', err);
  process.exit(1);
});
