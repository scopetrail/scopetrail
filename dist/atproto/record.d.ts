/**
 * record.ts — Sprint 03 Task 1: Lexicon schema & record builder.
 *
 * Builds/parses the `dev.scopetrail.auditReceipt` wrapper record that publishes a
 * signed `OBOAuditReceipt` into an AT Protocol repository.
 *
 * Decision D-1 (PRD_ARCH.md §8.3 / atproto_reference.md §3): the signed receipt is stored
 * **verbatim** as an opaque JSON string (`receiptJson`) so AT Protocol's DAG-CBOR data model
 * never touches — and never risks silently reshaping — the bytes that were JCS-canonicalized
 * and signed. A handful of fields are duplicated onto the wrapper as **untrusted indexed
 * mirrors** for discovery only (feed/list UIs, PDS queries). A verifier must always re-parse
 * `receiptJson` and run the existing `verifyReceipt()` (unchanged, untouched by this module) —
 * the mirrors are never a substitute for the Ed25519 proof.
 *
 * This module does not import from `./signer.js` and performs no cryptographic operations.
 *
 * @see PRD_ARCH.md §8.3 (Lexicon & record design)
 * @see atproto_reference.md §2–§3 (lexicon record shape, data-model constraints)
 * @see sprint_03.md Task 1
 * @see lexicons/dev.scopetrail.auditReceipt.json (the lexicon document this mirrors)
 */
import type { OBOAuditReceipt } from '../types.js';
/**
 * Collection NSID for the audit-receipt wrapper record.
 * A record's `$type` must equal this exactly (atproto_reference.md §1).
 */
export declare const RECEIPT_NSID = "dev.scopetrail.auditReceipt";
/** Schema-version tag stamped onto every wrapper record (PRD_ARCH.md §8.3). */
export declare const SCHEMA_VERSION = "obo-receipt/v1";
/**
 * The `dev.scopetrail.auditReceipt` record as written to / read from an AT Protocol
 * repository. Mirrors the `lexicons/dev.scopetrail.auditReceipt.json` lexicon document.
 *
 * `receiptJson` is the only trusted field. `issuer`, `subject`, `issuanceDate`,
 * `expirationDate`, and `summary` are untrusted mirrors duplicated from the parsed receipt for
 * discovery — always verify with `verifyMirrors()` before relying on them.
 */
export interface AtpReceiptRecord {
    /** Must equal `RECEIPT_NSID`. */
    $type: typeof RECEIPT_NSID;
    /** Verbatim `JSON.stringify(receipt)` — the only trusted field. */
    receiptJson: string;
    /** Untrusted mirror of `receipt.issuer`. */
    issuer: string;
    /** Untrusted mirror of `receipt.credentialSubject.id`. */
    subject: string;
    /** Untrusted mirror of `receipt.issuanceDate`. */
    issuanceDate: string;
    /** Untrusted mirror of `receipt.expirationDate`. */
    expirationDate: string;
    /** Untrusted mirror of `receipt.summary`. */
    summary: string;
    /** Fixed to `SCHEMA_VERSION` ('obo-receipt/v1'). */
    schemaVersion: string;
}
/**
 * Derive the atproto record key (rkey) for a receipt.
 *
 * `receipt.id` has the form `urn:obo-receipt:<base36-timestamp><20-hex-random>`
 * (see `signer.ts` `generateReceiptId` — despite some docs calling it a "ULID", it is not
 * Crockford-base32 ULID; it's a bespoke time-sortable ID of the same shape and intent).
 * The full URN is not a legal atproto record key (rkeys forbid `:` per the `record-key`
 * format), so the rkey is the bare identifier **after** the `urn:obo-receipt:` prefix — still
 * time-sortable, and unique per receipt. `publishReceipt` (Task 3) and `atUriFor` must both use
 * this same derivation so a published record's rkey and its computed `at://` URI always agree.
 */
export declare function rkeyFor(receipt: OBOAuditReceipt): string;
/**
 * Build the `at://` URI a published receipt will live at.
 * Form: `at://<did>/<RECEIPT_NSID>/<rkey>` (atproto_reference.md §7).
 */
export declare function atUriFor(did: string, receipt: OBOAuditReceipt): string;
/**
 * Build the atproto wrapper record for a signed receipt.
 *
 * `receiptJson` is produced with a single `JSON.stringify(receipt)` call — verbatim, no
 * reordering or reshaping — so DAG-CBOR storage never touches the signed payload's bytes.
 */
export declare function buildRecord(receipt: OBOAuditReceipt): AtpReceiptRecord;
/**
 * Recover the exact original signed receipt from a wrapper record.
 * A straight `JSON.parse` of the verbatim `receiptJson` string — no field mapping.
 */
export declare function parseRecord(record: AtpReceiptRecord): OBOAuditReceipt;
/**
 * Check that every untrusted indexed mirror on the wrapper record matches the corresponding
 * value in the verbatim payload (`receiptJson`, parsed). This is a cheap integrity check to
 * catch a tampered/stale mirror *before* paying for cryptographic verification — it is not a
 * substitute for `verifyReceipt()`, which is the actual trust boundary.
 *
 * Returns `false` (rather than throwing) if `receiptJson` fails to parse, since an unparsable
 * payload can never be said to "match" its mirrors.
 */
export declare function verifyMirrors(record: AtpReceiptRecord): boolean;
//# sourceMappingURL=record.d.ts.map