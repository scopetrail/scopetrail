#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * generate-issuer-key.mjs — one-time issuer keypair generator (Sprint 04, step 3 support).
 *
 * The rest of Sprint 04 assumes a STABLE issuer key: step 3 hosts its public half at
 * `.well-known/jwks.json`, and step 4's live publish must SIGN with the matching private half
 * so a third party can verify keyless against that hosted JWKS. Until now no persistent key
 * existed — every script called `generateKeyPair()` and threw the key away. This script mints
 * that key ONCE and writes it to disk so both steps can share it.
 *
 * It calls the existing `generateKeyPair()` / `exportPublicKeyAsJwk()` from the built
 * `dist/signer.js` (never reimplements crypto) and serializes their output verbatim.
 *
 * Usage (run from the package root, after `npm run build`):
 *   node scripts/generate-issuer-key.mjs [--kid <kid>] [--out-dir <dir>]
 *
 *   --kid       key id embedded in the JWKS + used at mint time (default: key-1)
 *   --out-dir   where to write the two files      (default: ./keys)
 *
 * Writes two files:
 *   <out-dir>/issuer-private.jwk.json   {kid, privateJwk, publicJwk}  — SECRET. Never commit.
 *   <out-dir>/issuer-public.jwk.json    {kid, publicJwk}              — safe. Feed to emit-jwks.
 *
 * Then:
 *   node scripts/emit-jwks.mjs --jwk-file keys/issuer-public.jwk.json --kid <kid> \
 *       --out .well-known/jwks.json
 *   # and point step 4 at the private file via ATP_ISSUER_KEY=keys/issuer-private.jwk.json
 *
 * SAFETY: refuses to overwrite an existing private key file (a re-run would silently orphan
 * every receipt already signed by the old key). Delete it deliberately if you truly mean to
 * rotate.
 */
import { webcrypto } from 'node:crypto';
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, exportPublicKeyAsJwk } from '../dist/signer.js';

const { subtle } = webcrypto;
const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..');

function parseArgs(argv) {
  const args = argv.slice(2);
  let kid = 'key-1';
  let outDir = join(repoRoot, 'keys');
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--kid') kid = args[++i];
    else if (args[i] === '--out-dir') outDir = args[++i];
  }
  return { kid, outDir };
}

async function main() {
  const { kid, outDir } = parseArgs(process.argv);

  const privatePath = join(outDir, 'issuer-private.jwk.json');
  const publicPath = join(outDir, 'issuer-public.jwk.json');

  if (existsSync(privatePath)) {
    console.error(`Refusing to overwrite existing private key: ${privatePath}`);
    console.error('Delete it deliberately first if you really intend to rotate the issuer key.');
    process.exit(1);
  }

  const { privateKey, publicKey } = await generateKeyPair();
  const privateJwk = await subtle.exportKey('jwk', privateKey); // includes the secret `d`
  const publicJwk = await exportPublicKeyAsJwk(publicKey); // public half only

  mkdirSync(outDir, { recursive: true });
  writeFileSync(privatePath, JSON.stringify({ kid, privateJwk, publicJwk }, null, 2) + '\n', {
    mode: 0o600,
  });
  writeFileSync(publicPath, JSON.stringify({ kid, publicJwk }, null, 2) + '\n');

  console.log(`Wrote SECRET private key: ${privatePath}  (mode 0600 — never commit)`);
  console.log(`Wrote public key file:    ${publicPath}`);
  console.log(`kid: ${kid}`);
  console.log('\nNext:');
  console.log(
    `  node scripts/emit-jwks.mjs --jwk-file ${publicPath} --kid ${kid} --out .well-known/jwks.json`
  );
  console.log(`  export ATP_ISSUER_KEY=${privatePath}   # for step 4's live publish`);
}

main().catch((err) => {
  console.error('FAILED:', err);
  process.exit(1);
});
