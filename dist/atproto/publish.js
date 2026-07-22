// SPDX-License-Identifier: Apache-2.0
/**
 * publish.ts — Sprint 03 Task 3: publish a signed receipt to an AT Protocol repo.
 *
 * Thin glue over Task 1 (record.ts) and Task 2 (client.ts): build the wrapper record, write it
 * under a deterministic rkey, and hand back the `at://` URI a verifier can later fetch with no
 * keys and no auth (PRD_ARCH.md §8.4).
 *
 * Performs no cryptographic operations and does not import from `../signer.js`.
 *
 * @see PRD_ARCH.md §8.4 (Publish flow)
 * @see sprint_03.md Task 3
 */
import { RECEIPT_NSID, buildRecord, rkeyFor, atUriFor } from './record.js';
/**
 * Publish a signed receipt to `issuerDid`'s repo and return its `at://` URI.
 *
 * The sprint story text says "rkey = receipt.id" — that predates Task 1's finding that atproto
 * rkeys can't contain `:` (the `urn:obo-receipt:` prefix is illegal in a record key). `rkeyFor`
 * is the corrected derivation and is what's actually written here; `atUriFor` uses the same
 * derivation internally, so the returned URI and the record's real address can never disagree.
 */
export async function publishReceipt(receipt, client, issuerDid) {
    const record = buildRecord(receipt);
    await client.putRecord({
        repo: issuerDid,
        collection: RECEIPT_NSID,
        rkey: rkeyFor(receipt),
        record,
        validate: false,
    });
    return atUriFor(issuerDid, receipt);
}
//# sourceMappingURL=publish.js.map