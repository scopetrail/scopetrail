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
import type { OBOAuditReceipt, VerificationResult } from './types.js';
/**
 * Load and validate the top-level structure of an `OBOAuditReceipt` from:
 *   - `'stdin'` — reads all of stdin (useful for pipes)
 *   - Any other string — treated as a file path
 *
 * Throws a descriptive `Error` if the JSON is invalid or required fields are missing.
 */
export declare function loadReceipt(source: string): Promise<OBOAuditReceipt>;
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
export declare function renderChain(receipt: OBOAuditReceipt, mode: 'ascii' | 'markdown'): string;
/**
 * Render the receipt's action in a box (ASCII) or table (Markdown).
 */
export declare function renderAction(receipt: OBOAuditReceipt, mode: 'ascii' | 'markdown'): string;
/**
 * Render proof metadata: cryptosuite, key reference, creation time, truncated proofValue.
 */
export declare function renderProof(receipt: OBOAuditReceipt, mode: 'ascii' | 'markdown'): string;
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
export declare function renderVerificationResult(result: VerificationResult | null, mode: 'ascii' | 'markdown'): string;
/**
 * Render a complete receipt: chain → action → proof → verification result.
 *
 * ASCII mode wraps everything in a top/bottom border.
 * Markdown mode joins sections with blank lines (no borders).
 */
export declare function renderReceipt(receipt: OBOAuditReceipt, result: VerificationResult | null, mode: 'ascii' | 'markdown'): string;
//# sourceMappingURL=viewer.d.ts.map