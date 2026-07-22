// SPDX-License-Identifier: Apache-2.0
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
export class AtpAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AtpAuthError';
  }
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
export class AppPasswordAuth implements AtpAuth {
  private readonly service: string;
  private readonly identifier: string;
  private readonly appPassword: string;
  private readonly fetchFn: typeof fetch;
  private cached: AtpSession | null = null;

  constructor(config: AppPasswordAuthConfig) {
    this.service = config.service.replace(/\/$/, '');
    this.identifier = config.identifier;
    this.appPassword = config.appPassword;
    this.fetchFn = config.fetchFn ?? globalThis.fetch;
  }

  /** Returns the cached session if one exists, otherwise creates and caches a new one. */
  async session(): Promise<AtpSession> {
    if (this.cached) {
      return this.cached;
    }

    const res = await this.fetchFn(`${this.service}/xrpc/com.atproto.server.createSession`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ identifier: this.identifier, password: this.appPassword }),
    });

    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new AtpAuthError(`createSession failed with status ${res.status}: ${detail}`);
    }

    const body = (await res.json()) as { accessJwt?: string; did?: string };
    if (!body.accessJwt || !body.did) {
      throw new AtpAuthError('createSession response missing accessJwt or did');
    }

    this.cached = { accessJwt: body.accessJwt, did: body.did };
    return this.cached;
  }
}

/** Fixed token `FakeAuth` uses by default — the mock PDS is pre-seeded to accept it. */
export const FAKE_ACCESS_JWT = 'fake-access-jwt-for-tests';

/** Fixed DID `FakeAuth` uses by default when no override is given. */
export const FAKE_DID = 'did:plc:fake0000000000000000test';

export interface FakeAuthConfig {
  accessJwt?: string;
  did?: string;
}

/** No-network `AtpAuth` double for tests. Always returns the same fixed session. */
export class FakeAuth implements AtpAuth {
  private readonly fixed: AtpSession;

  constructor(config: FakeAuthConfig = {}) {
    this.fixed = {
      accessJwt: config.accessJwt ?? FAKE_ACCESS_JWT,
      did: config.did ?? FAKE_DID,
    };
  }

  async session(): Promise<AtpSession> {
    return this.fixed;
  }
}
