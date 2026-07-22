// SPDX-License-Identifier: Apache-2.0
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
export class RecordNotFound extends Error {
  readonly repo: string;
  readonly collection: string;
  readonly rkey: string;

  constructor(repo: string, collection: string, rkey: string) {
    super(`Record not found: repo=${repo} collection=${collection} rkey=${rkey}`);
    this.name = 'RecordNotFound';
    this.repo = repo;
    this.collection = collection;
    this.rkey = rkey;
  }
}

/** Thrown when `putRecord` is attempted without a valid/authenticated session. */
export class AuthRequired extends Error {
  constructor(message = 'Authentication required: missing or invalid session token') {
    super(message);
    this.name = 'AuthRequired';
  }
}

/**
 * Real transport: calls `<pdsUrl>/xrpc/com.atproto.repo.{putRecord,getRecord}` over HTTP.
 * `putRecord` is authenticated (`Authorization: Bearer <accessJwt>`); `getRecord` is a public,
 * unauthenticated GET (PRD_ARCH.md §8.5 — verification needs no keys, no auth).
 */
export class FetchTransport implements AtpTransport {
  private readonly fetchFn: typeof fetch;

  constructor(fetchFn: typeof fetch = globalThis.fetch) {
    this.fetchFn = fetchFn;
  }

  async putRecord(pdsUrl: string, accessJwt: string, params: PutRecordParams): Promise<PutRecordResult> {
    const res = await this.fetchFn(`${pdsUrl.replace(/\/$/, '')}/xrpc/com.atproto.repo.putRecord`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${accessJwt}`,
      },
      body: JSON.stringify({
        repo: params.repo,
        collection: params.collection,
        rkey: params.rkey,
        record: params.record,
        validate: params.validate ?? false,
      }),
    });

    if (res.status === 401 || res.status === 403) {
      const detail = await res.text().catch(() => '');
      throw new AuthRequired(`putRecord unauthorized (${res.status}): ${detail}`);
    }
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`putRecord failed with status ${res.status}: ${detail}`);
    }

    return (await res.json()) as PutRecordResult;
  }

  async getRecord(pdsUrl: string, params: GetRecordParams): Promise<GetRecordResult> {
    const url = new URL(`${pdsUrl.replace(/\/$/, '')}/xrpc/com.atproto.repo.getRecord`);
    url.searchParams.set('repo', params.repo);
    url.searchParams.set('collection', params.collection);
    url.searchParams.set('rkey', params.rkey);

    const res = await this.fetchFn(url.toString());

    if (res.status === 400 || res.status === 404) {
      throw new RecordNotFound(params.repo, params.collection, params.rkey);
    }
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`getRecord failed with status ${res.status}: ${detail}`);
    }

    return (await res.json()) as GetRecordResult;
  }
}

/**
 * Real `did:plc` resolution via the PLC directory (PRD_ARCH.md §8.4/§8.5, atproto_reference.md
 * §6): `GET https://plc.directory/<did>` → DID document → the `serviceEndpoint` of the
 * `AtprotoPersonalDataServer` service entry. Only ever exercised outside tests — tests inject a
 * stub `DidResolver` instead (see mock-pds.ts).
 */
export function createPlcDidResolver(fetchFn: typeof fetch = globalThis.fetch): DidResolver {
  return async (did: string): Promise<string> => {
    const res = await fetchFn(`https://plc.directory/${encodeURIComponent(did)}`);
    if (!res.ok) {
      throw new Error(`PLC resolution failed for ${did}: ${res.status}`);
    }

    const doc = (await res.json()) as {
      service?: Array<{ id: string; type: string; serviceEndpoint: string }>;
    };
    const pds = doc.service?.find((entry) => entry.type === 'AtprotoPersonalDataServer');
    if (!pds) {
      throw new Error(`No AtprotoPersonalDataServer service found in DID document for ${did}`);
    }

    return pds.serviceEndpoint;
  };
}

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
export class AtpClient {
  private readonly auth: AtpAuth;
  private readonly transport: AtpTransport;
  private readonly didResolver: DidResolver;

  constructor(config: AtpClientConfig) {
    this.auth = config.auth;
    this.transport = config.transport;
    this.didResolver = config.didResolver;
  }

  /** Resolves a did:plc to the base URL of the PDS hosting its repo. */
  async resolveDidToPds(did: string): Promise<string> {
    return this.didResolver(did);
  }

  /** Writes a record, authenticated via the configured `AtpAuth`. Default `validate: false`. */
  async putRecord(params: PutRecordParams): Promise<PutRecordResult> {
    const pdsUrl = await this.resolveDidToPds(params.repo);
    const session = await this.auth.session();
    if (!session?.accessJwt) {
      throw new AuthRequired();
    }
    return this.transport.putRecord(pdsUrl, session.accessJwt, params);
  }

  /** Reads a record. Public — no auth is used or required, per PRD_ARCH.md §8.5. */
  async getRecord(params: GetRecordParams): Promise<GetRecordResult> {
    const pdsUrl = await this.resolveDidToPds(params.repo);
    return this.transport.getRecord(pdsUrl, params);
  }
}
