/**
 * AT Protocol authentication seam (Sprint 03, Task 2).
 *
 * `AtpAuth` isolates "how we get an accessJwt" from the publish/verify flow so app-password
 * auth (decision D-2, PRD_ARCH.md §8.4) can be swapped for OAuth later without touching
 * `AtpClient`, `publishReceipt`, or `verifyFromUri`.
 *
 * `AppPasswordAuth` is the real, network-calling implementation (never invoked in tests).
 * `FakeAuth` is the deterministic, no-network double used by unit/integration tests and by
 * the mock PDS to recognize a "valid session" without any real auth.
 */
/** The subset of an atproto session a caller needs to make authenticated XRPC calls. */
export interface AtpSession {
    accessJwt: string;
    did: string;
}
/** Auth seam: anything that can produce a usable session on demand. */
export interface AtpAuth {
    session(): Promise<AtpSession>;
}
/** Thrown when `AppPasswordAuth.session()` fails to establish a session with the PDS. */
export declare class AtpAuthError extends Error {
    constructor(message: string);
}
export interface AppPasswordAuthConfig {
    /** PDS base URL, e.g. "https://bsky.social" (no trailing `/xrpc/...`). */
    service: string;
    /** Handle or DID used to log in. */
    identifier: string;
    /** App password (format `xxxx-xxxx-xxxx-xxxx`), never the account password. */
    appPassword: string;
    /** Injectable fetch for testability; defaults to the global `fetch`. Real path only. */
    fetchFn?: typeof fetch;
}
/**
 * Real `com.atproto.server.createSession` auth via an app password (PRD_ARCH.md §8.4 D-2).
 * Network is only ever touched when `session()` is actually called — construction alone
 * does nothing, so this class is safe to instantiate in any environment.
 */
export declare class AppPasswordAuth implements AtpAuth {
    private readonly service;
    private readonly identifier;
    private readonly appPassword;
    private readonly fetchFn;
    private cached;
    constructor(config: AppPasswordAuthConfig);
    /** Returns the cached session if one exists, otherwise creates and caches a new one. */
    session(): Promise<AtpSession>;
}
/** Fixed token `FakeAuth` uses by default — the mock PDS is pre-seeded to accept it. */
export declare const FAKE_ACCESS_JWT = "fake-access-jwt-for-tests";
/** Fixed DID `FakeAuth` uses by default when no override is given. */
export declare const FAKE_DID = "did:plc:fake0000000000000000test";
export interface FakeAuthConfig {
    accessJwt?: string;
    did?: string;
}
/** No-network `AtpAuth` double for tests. Always returns the same fixed session. */
export declare class FakeAuth implements AtpAuth {
    private readonly fixed;
    constructor(config?: FakeAuthConfig);
    session(): Promise<AtpSession>;
}
//# sourceMappingURL=auth.d.ts.map