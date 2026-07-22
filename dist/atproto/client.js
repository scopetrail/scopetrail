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
/** Thrown by `getRecord` when the given repo/collection/rkey has no record. */
export class RecordNotFound extends Error {
    repo;
    collection;
    rkey;
    constructor(repo, collection, rkey) {
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
export class FetchTransport {
    fetchFn;
    constructor(fetchFn = globalThis.fetch) {
        this.fetchFn = fetchFn;
    }
    async putRecord(pdsUrl, accessJwt, params) {
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
        return (await res.json());
    }
    async getRecord(pdsUrl, params) {
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
        return (await res.json());
    }
}
/**
 * Real `did:plc` resolution via the PLC directory (PRD_ARCH.md §8.4/§8.5, atproto_reference.md
 * §6): `GET https://plc.directory/<did>` → DID document → the `serviceEndpoint` of the
 * `AtprotoPersonalDataServer` service entry. Only ever exercised outside tests — tests inject a
 * stub `DidResolver` instead (see mock-pds.ts).
 */
export function createPlcDidResolver(fetchFn = globalThis.fetch) {
    return async (did) => {
        const res = await fetchFn(`https://plc.directory/${encodeURIComponent(did)}`);
        if (!res.ok) {
            throw new Error(`PLC resolution failed for ${did}: ${res.status}`);
        }
        const doc = (await res.json());
        const pds = doc.service?.find((entry) => entry.type === 'AtprotoPersonalDataServer');
        if (!pds) {
            throw new Error(`No AtprotoPersonalDataServer service found in DID document for ${did}`);
        }
        return pds.serviceEndpoint;
    };
}
/**
 * Thin XRPC client for publishing/fetching atproto records. Identical call shapes whether
 * `transport`/`didResolver` point at a real PDS + PLC directory or the in-memory mock — the
 * real-vs-mock choice lives entirely in what gets passed to the constructor.
 */
export class AtpClient {
    auth;
    transport;
    didResolver;
    constructor(config) {
        this.auth = config.auth;
        this.transport = config.transport;
        this.didResolver = config.didResolver;
    }
    /** Resolves a did:plc to the base URL of the PDS hosting its repo. */
    async resolveDidToPds(did) {
        return this.didResolver(did);
    }
    /** Writes a record, authenticated via the configured `AtpAuth`. Default `validate: false`. */
    async putRecord(params) {
        const pdsUrl = await this.resolveDidToPds(params.repo);
        const session = await this.auth.session();
        if (!session?.accessJwt) {
            throw new AuthRequired();
        }
        return this.transport.putRecord(pdsUrl, session.accessJwt, params);
    }
    /** Reads a record. Public — no auth is used or required, per PRD_ARCH.md §8.5. */
    async getRecord(params) {
        const pdsUrl = await this.resolveDidToPds(params.repo);
        return this.transport.getRecord(pdsUrl, params);
    }
}
//# sourceMappingURL=client.js.map