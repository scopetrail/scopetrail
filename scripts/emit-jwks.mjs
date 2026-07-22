#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * emit-jwks.mjs — Sprint 04 Task 5.
 *
 * Writes a static `jwks.json` artifact from the EXISTING `buildJwks()` (src/signer.ts) output,
 * serialized verbatim — no reshaping, no re-derivation, no touching key-derivation logic. This
 * is the file a static host (gh-pages, the scopetrail domain, ...) serves at
 * `/.well-known/jwks.json` so a verifier can fetch the issuer's public key with no server
 * running and no in-process key handoff (closes the Sprint 03 Task 5 follow-up — see
 * sprint_03.md line 113 / sprint_04.md Task 5).
 *
 * Usage:
 *   node scripts/emit-jwks.mjs [--out <path>] [--kid <kid>] [--jwk-file <path>]
 *
 *   (no --jwk-file, the default): generates a FRESH, throwaway DEMO Ed25519 keypair on the spot
 *     and emits its public key as the JWKS. This is what produced the EXAMPLE
 *     `.well-known/jwks.json` committed in this repo — it is a DEMO artifact, NOT the real
 *     issuer key. Jim regenerates this file from the real issuer key pair at deploy time; see
 *     README "No-keys verification" section.
 *
 *   --jwk-file <path>: path to a JSON file `{ "kid": "...", "publicJwk": {...} }` holding a real
 *     issuer public key (already exported via signer.js `exportPublicKeyAsJwk`) to import and
 *     emit instead of generating a demo key. `--kid` overrides the file's `kid` if both given.
 *
 * This script only ever CALLS `buildJwks()` from the built `dist/signer.js` and serializes its
 * return value verbatim — it does not reimplement, alter, or bypass any key-derivation/JWKS-
 * shaping logic. Run `npm run build` first so `dist/signer.js` is current.
 */
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';
import { generateKeyPair, buildJwks } from '../dist/signer.js';

const { subtle } = webcrypto;
const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..');

function parseArgs(argv) {
  const args = argv.slice(2);
  let out = join(repoRoot, '.well-known', 'jwks.json');
  let kid = 'key-1';
  let jwkFile = null;
  let kidExplicit = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--out') out = args[++i];
    else if (args[i] === '--kid') {
      kid = args[++i];
      kidExplicit = true;
    } else if (args[i] === '--jwk-file') jwkFile = args[++i];
  }

  return { out, kid, jwkFile, kidExplicit };
}

async function main() {
  const { out, kid, jwkFile, kidExplicit } = parseArgs(process.argv);

  let publicKey;
  let effectiveKid = kid;

  if (jwkFile) {
    const parsed = JSON.parse(readFileSync(jwkFile, 'utf8'));
    if (!parsed.publicJwk) {
      console.error(`"${jwkFile}" must contain a "publicJwk" field (see script header doc).`);
      process.exit(1);
    }
    publicKey = await subtle.importKey('jwk', parsed.publicJwk, 'Ed25519', true, ['verify']);
    if (parsed.kid && !kidExplicit) effectiveKid = parsed.kid;
    console.log(`Loaded issuer public key from ${jwkFile} (kid: ${effectiveKid})`);
  } else {
    console.log(
      'No --jwk-file given — generating a DEMO keypair. This is NOT a real issuer key; ' +
        'Jim regenerates this artifact from the real issuer key at deploy time (see README).'
    );
    const kp = await generateKeyPair();
    publicKey = kp.publicKey;
  }

  // Call the EXISTING buildJwks() unchanged and serialize its output verbatim.
  const jwks = await buildJwks([{ kid: effectiveKid, publicKey }]);

  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, JSON.stringify(jwks, null, 2) + '\n');
  console.log(`Wrote ${out}`);
}

main().catch((err) => {
  console.error('FAILED:', err);
  process.exit(1);
});
