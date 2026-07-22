/**
 * Dependency-free, in-memory mock PDS (Sprint 03, Task 2 — PRD_ARCH.md §8.6).
 *
 * Implements `AtpTransport` with the exact `putRecord`/`getRecord` request/response shapes a
 * real PDS uses (atproto_reference.md §5), so `AtpClient` runs identically against this mock or
 * a real network PDS — swapping one for the other is a constructor-argument change, nothing
 * more. No network, no timers, no external state: safe for unit/integration tests to construct
 * fresh per test.
 */
import { type AtpTransport, type DidResolver, type GetRecordParams, type GetRecordResult, type PutRecordParams, type PutRecordResult } from './client.js';
/** Fake base URL for the mock PDS — never dialed over the network. */
export declare const MOCK_PDS_URL = "https://mock-pds.invalid";
/** A DID pre-registered against `MOCK_PDS_URL` for convenience in tests. */
export declare const MOCK_TEST_DID = "did:plc:mocktestissuer00000000000";
/**
 * In-memory PDS. Accepts a list of access tokens that count as "authenticated" (pair this with
 * `FakeAuth`'s token, e.g. `new MockPds([FAKE_ACCESS_JWT])`) — `putRecord` without a recognized
 * token throws the typed `AuthRequired` error, exactly as a real PDS would reject a bad/missing
 * bearer token.
 */
export declare class MockPds implements AtpTransport {
    private readonly records;
    private readonly validTokens;
    private cidCounter;
    constructor(validAccessTokens?: string[]);
    private static key;
    private static uri;
    /** Deterministic, clearly-fake CID — labeled as such, never a real CIDv1 digest. */
    private nextFakeCid;
    putRecord(_pdsUrl: string, accessJwt: string, params: PutRecordParams): Promise<PutRecordResult>;
    getRecord(_pdsUrl: string, params: GetRecordParams): Promise<GetRecordResult>;
    /**
     * Test-only accessor: overwrite an already-stored record's value in place, without going
     * through `putRecord` (so no auth token / session is needed). Used by integration tests
     * (Sprint 03 Task 3) to simulate a tampered record already sitting on a PDS — e.g. an
     * attacker (or a bug) editing `receiptJson` or an indexed mirror after publish — which is not
     * something a well-behaved client can do via the normal `putRecord` XRPC call. Throws
     * `RecordNotFound` if there's nothing stored at that address yet, matching `getRecord`'s
     * behavior. Not part of the `AtpTransport` interface a real PDS implements.
     */
    _setRecordValueForTest(repo: string, collection: string, rkey: string, value: unknown): void;
}
/**
 * Stub DID resolver mapping known test DIDs straight to a mock PDS base URL — no PLC directory,
 * no network. Use `createMockDidResolver({ [MOCK_TEST_DID]: MOCK_PDS_URL })` or the
 * `defaultMockDidResolver` convenience below.
 */
export declare function createMockDidResolver(mapping: Record<string, string>): DidResolver;
/** Convenience resolver mapping `MOCK_TEST_DID` → `MOCK_PDS_URL`, nothing else. */
export declare const defaultMockDidResolver: DidResolver;
//# sourceMappingURL=mock-pds.d.ts.map