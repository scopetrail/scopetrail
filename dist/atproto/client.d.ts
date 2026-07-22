/**
 * AT Protocol XRPC client seam (Sprint 03, Task 2 — PRD_ARCH.md §8.4/§8.6).
 *
 * `AtpClient` is transport-agnostic: it depends on an `AtpAuth` (session/token), an
 * `AtpTransport` (does the actual put/get), and a `DidResolver` (did → PDS base URL). Both the
 * mock PDS (src/atproto/mock-pds.ts) and a real PDS satisfy the exact same `AtpTransport`
 * interface, so swapping mock for real is pure config/injection — no call-site changes.
 *
 * Records are treated as opaque (`unknown`) here; this file does not import or depend on the
 * record builder (src/atproto/record.ts, built concurrently by another task).
 */
import type { AtpAuth } from './auth.js';
/** Parameters for `com.atproto.repo.putRecord`. */
export interface PutRecordParams {
    /** Repo DID that owns the record (the issuer's did:plc). */
    repo: string;
    /** Collection NSID, e.g. `dev.scopetrail.auditReceipt`. */
    collection: string;
    /** Record key — a deterministic rkey (the receipt's ULID) rather than an auto-assigned TID. */
    rkey: string;
    /** The record body. Opaque to the client — shape is the caller's concern. */
    record: unknown;
    /** Optimistic (fail-open) validation is the default per PRD_ARCH.md §8.3/§8.6. */
    validate?: boolean;
}
export interface PutRecordResult {
    uri: string;
    cid: string;
}
/** Parameters for `com.atproto.repo.getRecord`. */
export interface GetRecordParams {
    repo: string;
    collection: string;
    rkey: string;
}
export interface GetRecordResult {
    uri: string;
    cid: string;
    value: unknown;
}
/**
 * Transport seam: anything that can perform the two XRPC operations against a given PDS base
 * URL. The real implementation (`FetchTransport`) calls out over HTTP; the mock (`MockPds`)
 * does everything in memory. Both throw `RecordNotFound` / `AuthRequired` from this module so
 * callers can `instanceof`-check regardless of which transport is wired in.
 */
export interface AtpTransport {
    putRecord(pdsUrl: string, accessJwt: string, params: PutRecordParams): Promise<PutRecordResult>;
    getRecord(pdsUrl: string, params: GetRecordParams): Promise<GetRecordResult>;
}
/** Resolves a DID to the base URL of the PDS that hosts its repo. */
export type DidResolver = (did: string) => Promise<string>;
/** Thrown by `getRecord` when the given repo/collection/rkey has no record. */
export declare class RecordNotFound extends Error {
    readonly repo: string;
    readonly collection: string;
    readonly rkey: string;
    constructor(repo: string, collection: string, rkey: string);
}
/** Thrown when `putRecord` is attempted without a valid/authenticated session. */
export declare class AuthRequired extends Error {
    constructor(message?: string);
}
/**
 * Real transport: calls `<pdsUrl>/xrpc/com.atproto.repo.{putRecord,getRecord}` over HTTP.
 * `putRecord` is authenticated (`Authorization: Bearer <accessJwt>`); `getRecord` is a public,
 * unauthenticated GET (PRD_ARCH.md §8.5 — verification needs no keys, no auth).
 */
export declare class FetchTransport implements AtpTransport {
    private readonly fetchFn;
    constructor(fetchFn?: typeof fetch);
    putRecord(pdsUrl: string, accessJwt: string, params: PutRecordParams): Promise<PutRecordResult>;
    getRecord(pdsUrl: string, params: GetRecordParams): Promise<GetRecordResult>;
}
/**
 * Real `did:plc` resolution via the PLC directory (PRD_ARCH.md §8.4/§8.5, atproto_reference.md
 * §6): `GET https://plc.directory/<did>` → DID document → the `serviceEndpoint` of the
 * `AtprotoPersonalDataServer` service entry. Only ever exercised outside tests — tests inject a
 * stub `DidResolver` instead (see mock-pds.ts).
 */
export declare function createPlcDidResolver(fetchFn?: typeof fetch): DidResolver;
export interface AtpClientConfig {
    auth: AtpAuth;
    transport: AtpTransport;
    didResolver: DidResolver;
}
/**
 * Thin XRPC client for publishing/fetching atproto records. Identical call shapes whether
 * `transport`/`didResolver` point at a real PDS + PLC directory or the in-memory mock — the
 * real-vs-mock choice lives entirely in what gets passed to the constructor.
 */
export declare class AtpClient {
    private readonly auth;
    private readonly transport;
    private readonly didResolver;
    constructor(config: AtpClientConfig);
    /** Resolves a did:plc to the base URL of the PDS hosting its repo. */
    resolveDidToPds(did: string): Promise<string>;
    /** Writes a record, authenticated via the configured `AtpAuth`. Default `validate: false`. */
    putRecord(params: PutRecordParams): Promise<PutRecordResult>;
    /** Reads a record. Public — no auth is used or required, per PRD_ARCH.md §8.5. */
    getRecord(params: GetRecordParams): Promise<GetRecordResult>;
}
//# sourceMappingURL=client.d.ts.map