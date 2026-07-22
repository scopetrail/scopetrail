// SPDX-License-Identifier: Apache-2.0
/**
 * viewer.ts — Task 3: Terminal ASCII / Markdown Flow Viewer
 *
 * Responsibilities:
 *   - loadReceipt(): parse an OBOAuditReceipt from a file path or stdin
 *   - renderChain(): delegation chain as an ASCII flow diagram or Markdown code block
 *   - renderAction(): action summary in a box (ASCII) or table (Markdown)
 *   - renderProof(): proof metadata block
 *   - renderVerificationResult(): VERIFIED / INVALID / UNVERIFIED banner
 *   - renderReceipt(): full render pipeline with top/bottom border
 *
 * @see PRD_ARCH.md §5.3, §5.4
 * @see sprint_01.md Task 3
 */
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
// ── Helpers ───────────────────────────────────────────────────────────────────
/**
 * Shorten a token digest for display: `sha256:abcdefgh…`
 * Shows the first 8 hex chars after the `sha256:` prefix.
 */
function shortDigest(digest) {
    const prefix = 'sha256:';
    if (digest.startsWith(prefix)) {
        return `${prefix}${digest.slice(prefix.length, prefix.length + 8)}…`;
    }
    return digest.length > 20 ? digest.slice(0, 18) + '…' : digest;
}
/**
 * Return the time portion of an ISO-8601 UTC string: `HH:MM:SSZ`
 * "2026-06-18T14:22:31Z" → "14:22:31Z"
 * Empty/missing input → "n/a" (e.g. opaque tokens carry no expiry).
 */
function shortTime(iso) {
    if (!iso)
        return 'n/a';
    const t = iso.indexOf('T');
    return t !== -1 ? iso.slice(t + 1) : iso;
}
// ── §3.2 — Receipt loader ─────────────────────────────────────────────────────
/**
 * Load and validate the top-level structure of an `OBOAuditReceipt` from:
 *   - `'stdin'` — reads all of stdin (useful for pipes)
 *   - Any other string — treated as a file path
 *
 * Throws a descriptive `Error` if the JSON is invalid or required fields are missing.
 */
export async function loadReceipt(source) {
    const raw = source === 'stdin' ? await readStdin() : readFileSync(source, 'utf8');
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch (e) {
        throw new Error(`Not a valid OBOAuditReceipt — JSON parse failed: ${e.message}`);
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new Error('Not a valid OBOAuditReceipt — root value must be a JSON object');
    }
    const obj = parsed;
    const required = [
        '@context', '@type', 'id', 'issuer', 'issuanceDate', 'expirationDate',
        'credentialSubject', 'delegationContext', 'action', 'nonce', 'proof',
    ];
    for (const field of required) {
        if (!(field in obj)) {
            throw new Error(`Not a valid OBOAuditReceipt — missing field: ${field}`);
        }
    }
    const types = obj['@type'];
    if (!Array.isArray(types) || !types.includes('OBOAuditReceipt')) {
        throw new Error('Not a valid OBOAuditReceipt — @type must include "OBOAuditReceipt"');
    }
    return obj;
}
function readStdin() {
    return new Promise((resolve, reject) => {
        const chunks = [];
        const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
        rl.on('line', line => chunks.push(line));
        rl.on('close', () => resolve(chunks.join('\n')));
        rl.on('error', reject);
    });
}
// ── §3.3 — Delegation chain renderer ─────────────────────────────────────────
/**
 * Render the delegation chain as a vertical ASCII flow diagram or a Markdown code block.
 *
 * ASCII format:
 * ```
 * ROOT  did:web:…/jim  [human]
 *   │   authorizedAt: 2026-06-18T14:20:00Z
 *   │   token: sha256:a3f1c9… (jwt / expires 14:20:00Z)
 *   ▼   scopes: read:documents, invoke:summarize
 * HOP 1  did:web:…/orchestrator  [service]
 *   │   …
 *   ▼   …
 * ACTOR  did:web:…/summarizer-v2  [agent]
 * ```
 */
export function renderChain(receipt, mode) {
    const { rootPrincipal, delegationChain } = receipt.delegationContext;
    const actor = receipt.credentialSubject;
    const lines = [];
    lines.push(`ROOT  ${rootPrincipal.id}  [${rootPrincipal.type}]`);
    for (let i = 0; i < delegationChain.length; i++) {
        const hop = delegationChain[i];
        const isLast = i === delegationChain.length - 1;
        const nodeLabel = isLast ? 'ACTOR' : `HOP ${i + 1}`;
        lines.push(`  │   authorizedAt: ${hop.authorizedAt}`);
        const expiryClause = hop.tokenRef.tokenExpiresAt
            ? ` / expires ${shortTime(hop.tokenRef.tokenExpiresAt)}`
            : '';
        lines.push(`  │   token: ${shortDigest(hop.tokenRef.tokenDigest)}` +
            ` (${hop.tokenRef.tokenType}${expiryClause})`);
        lines.push(`  ▼   scopes: ${hop.scopeAtHop.join(', ')}`);
        lines.push(`${nodeLabel}  ${hop.delegate.id}  [${hop.delegate.type}]`);
    }
    // No hops: root acted directly
    if (delegationChain.length === 0) {
        lines.push(`ACTOR  ${actor.id}  [${actor.type}]`);
    }
    const body = lines.join('\n');
    if (mode === 'ascii') {
        return body;
    }
    else {
        return '```\n' + body + '\n```';
    }
}
// ── §3.4 — Action summary block ───────────────────────────────────────────────
/**
 * Render the receipt's action in a box (ASCII) or table (Markdown).
 */
export function renderAction(receipt, mode) {
    const { verb, resourceUri, parameters, metadata } = receipt.action;
    const correlationId = metadata?.['correlationId'];
    if (mode === 'ascii') {
        const inner = [
            `  verb:         ${verb}`,
            `  resource:     ${resourceUri}`,
        ];
        if (parameters && Object.keys(parameters).length > 0) {
            inner.push(`  parameters:   ${JSON.stringify(parameters)}`);
        }
        if (correlationId) {
            inner.push(`  correlationId: ${correlationId}`);
        }
        const boxWidth = Math.max(12, ...inner.map(l => l.length));
        const top = '┌─ ACTION ' + '─'.repeat(boxWidth - 9) + '┐';
        const bottom = '└' + '─'.repeat(boxWidth) + '┘';
        const rows = inner.map(l => '│' + l.padEnd(boxWidth) + '│');
        return [top, ...rows, bottom].join('\n');
    }
    else {
        const tableRows = [
            '| Field | Value |',
            '|---|---|',
            `| verb | \`${verb}\` |`,
            `| resource | \`${resourceUri}\` |`,
        ];
        if (parameters && Object.keys(parameters).length > 0) {
            tableRows.push(`| parameters | \`${JSON.stringify(parameters)}\` |`);
        }
        if (correlationId) {
            tableRows.push(`| correlationId | \`${correlationId}\` |`);
        }
        return `**Action**\n\n${tableRows.join('\n')}`;
    }
}
// ── §3.5 — Proof metadata block ───────────────────────────────────────────────
/**
 * Render proof metadata: cryptosuite, key reference, creation time, truncated proofValue.
 */
export function renderProof(receipt, mode) {
    const { proof } = receipt;
    const shortProof = proof.proofValue.slice(0, 16) + '…';
    if (mode === 'ascii') {
        return [
            'Proof',
            `  cryptosuite:         ${proof.cryptosuite}`,
            `  verificationMethod:  ${proof.verificationMethod}`,
            `  created:             ${proof.created}`,
            `  proofValue:          ${shortProof}`,
        ].join('\n');
    }
    else {
        return [
            '**Proof**',
            '',
            '| Field | Value |',
            '|---|---|',
            `| cryptosuite | \`${proof.cryptosuite}\` |`,
            `| verificationMethod | \`${proof.verificationMethod}\` |`,
            `| created | \`${proof.created}\` |`,
            `| proofValue | \`${shortProof}\` |`,
        ].join('\n');
    }
}
// ── §3.6 — Verification result banner ────────────────────────────────────────
/**
 * Render the verification outcome.
 *
 * ASCII:
 *   `[ VERIFIED ]`
 *   `[ INVALID — SIGNATURE_INVALID, RECEIPT_EXPIRED ]`
 *   `[ UNVERIFIED — no key supplied ]`
 *
 * Markdown:
 *   `> **VERIFIED**`
 *   `> **INVALID**` + error list
 *   `> **UNVERIFIED** — no key supplied`
 *
 * @param result - `null` means no public key was provided; skip crypto verification.
 */
export function renderVerificationResult(result, mode) {
    if (result === null) {
        return mode === 'ascii'
            ? '[ UNVERIFIED — no key supplied ]'
            : '> **UNVERIFIED** — no key supplied';
    }
    if (result.valid) {
        return mode === 'ascii'
            ? '[ VERIFIED ]'
            : '> **VERIFIED**';
    }
    const errorList = result.errors.join(', ');
    if (mode === 'ascii') {
        return `[ INVALID — ${errorList} ]`;
    }
    else {
        const items = result.errors.map(e => `> - \`${e}\``).join('\n');
        return `> **INVALID**\n${items}`;
    }
}
// ── §3.7 — Full render pipeline ───────────────────────────────────────────────
/**
 * Render a complete receipt: chain → action → proof → verification result.
 *
 * ASCII mode wraps everything in a top/bottom border.
 * Markdown mode joins sections with blank lines (no borders).
 */
export function renderReceipt(receipt, result, mode) {
    const sections = [
        renderChain(receipt, mode),
        renderAction(receipt, mode),
        renderProof(receipt, mode),
        renderVerificationResult(result, mode),
    ];
    if (mode === 'ascii') {
        const HEADER = '═══ OBO AUDIT RECEIPT ═══';
        const FOOTER = '═'.repeat(HEADER.length);
        return [HEADER, '', ...sections.join('\n\n').split('\n'), '', FOOTER].join('\n');
    }
    else {
        return sections.join('\n\n');
    }
}
//# sourceMappingURL=viewer.js.map