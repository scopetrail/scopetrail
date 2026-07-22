/**
 * jwks.ts — Sprint 04 Task 5: fetch-by-URL key resolution for true "no keys" verification.
 *
 * Sprint 03's verify-from-`at://` flow (verify-uri.ts) already accepted either an in-process
 * `CryptoKey` or an in-process `JsonWebKeySet` — but a caller still had to obtain that JWKS
 * document itself, in-process, with no defined way to fetch it from a hosted URL. Sprint 03
 * Task 5's live-publish follow-up flagged exactly this gap: the verify step was handed the
 * issuer's public `CryptoKey` directly because there was no hosted JWKS a third party could
 * fetch from.
 *
 * This module closes that gap: given a JWKS URL, fetch the document (over an injectable
 * `fetch`, so tests need no real network — see `fetchFn`), select the right key by `kid`, and
 * import it to a verification-ready `CryptoKey` via
 * `crypto.subtle.importKey('jwk', jwk, 'Ed25519', false, ['verify'])`.
 *
 * This module does NOT touch `buildJwks`, key derivation, or any signing/canonicalization logic
 * in `src/signer.ts` — it only ever *consumes* JWKS documents that `buildJwks()` (or an
 * equivalent hosted endpoint serving its output verbatim) already produced.
 *
 * @see src/atproto/verify-uri.ts (wires this into the verify-from-`at://` pipeline)
 * @see scripts/emit-jwks.mjs (produces the static jwks.json this module fetches)
 * @see sprint_04.md Task 5
 * @see sprint_03.md Task 5 (the JWKS-hosting follow-up this task closes)
 */
import type { JsonWebKeySet } from './verify-uri.js';
/** Thrown when a JWKS URL can't be fetched, or the response isn't a valid JWKS document. */
export declare class JwksFetchError extends Error {
    readonly url: string;
    constructor(url: string, message: string);
}
/**
 * Fetch a JWKS document from a URL. Injectable `fetchFn` (defaults to `globalThis.fetch`) so
 * tests never touch the real network. Throws `JwksFetchError` on any network/HTTP/parse
 * failure — the verify-from-`at://` pipeline (verify-uri.ts) catches this and turns it into the
 * typed, non-throwing `KEY_IMPORT_FAILED` result rather than letting it propagate as a crash.
 */
export declare function fetchJwks(url: string, fetchFn?: typeof fetch): Promise<JsonWebKeySet>;
/**
 * Select a key from an already-fetched JWKS document by `kid`, then import it to a `CryptoKey`.
 * Falls back to the sole Ed25519/OKP key when there is exactly one and no `kid` was given to
 * match against. Returns `null` (never throws) when no suitable key is found or import fails —
 * the caller turns that into the typed `KEY_IMPORT_FAILED` result, never a crash.
 */
export declare function selectAndImportKey(jwks: JsonWebKeySet, kid: string | null): Promise<CryptoKey | null>;
/**
 * Fetch a JWKS document from a URL and resolve it to an imported `CryptoKey`, matching the
 * `kid` fragment of a `verificationMethod` (`did:...#key-1` → `key-1`) when present. This is
 * the single call the verify-from-`at://` pipeline (verify-uri.ts) makes when a caller passes a
 * JWKS URL instead of an in-process key/JWKS.
 *
 * Lets `JwksFetchError` propagate for network/HTTP/parse failures (see `fetchJwks`); returns
 * `null` for a resolvable-but-empty/no-match JWKS (wrong or missing `kid`). Either outcome is
 * turned into the same typed `KEY_IMPORT_FAILED` result by verify-uri.ts — never a crash.
 */
export declare function resolveKeyFromJwksUrl(url: string, verificationMethod: string, fetchFn?: typeof fetch): Promise<CryptoKey | null>;
//# sourceMappingURL=jwks.d.ts.map