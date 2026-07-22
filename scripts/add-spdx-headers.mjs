/**
 * add-spdx-headers.mjs — Sprint 04 Task 4.
 *
 * Idempotently prepends `// SPDX-License-Identifier: Apache-2.0` to every
 * src/**\/*.ts file. If the file already contains an SPDX line anywhere,
 * it is left untouched. Files that start with a shebang (`#!...`) keep
 * the shebang as line 1 — TypeScript requires `#!` to be the literal
 * first character of the file (verified: putting anything before it is
 * a compile error) — so the SPDX line is inserted as line 2 instead.
 * Otherwise the SPDX line is inserted as line 1, above any existing
 * block comment.
 *
 * This script does not touch anything else in the file — no code changes.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';

const SPDX_LINE = '// SPDX-License-Identifier: Apache-2.0';

const files = execSync('find src -name "*.ts"', { encoding: 'utf8' })
  .trim()
  .split('\n')
  .filter(Boolean)
  .sort();

let added = 0;
let skipped = 0;

for (const file of files) {
  const content = readFileSync(file, 'utf8');

  if (content.includes('SPDX-License-Identifier')) {
    skipped++;
    continue;
  }

  let newContent;
  if (content.startsWith('#!')) {
    const newlineIdx = content.indexOf('\n');
    const shebangLine = content.slice(0, newlineIdx + 1);
    const rest = content.slice(newlineIdx + 1);
    newContent = shebangLine + SPDX_LINE + '\n' + rest;
  } else {
    newContent = SPDX_LINE + '\n' + content;
  }

  writeFileSync(file, newContent, 'utf8');
  added++;
}

console.log(`SPDX headers: added ${added}, already present ${skipped}, total ${files.length}`);
