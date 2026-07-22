/**
 * Barrel export for the atproto publication layer (Sprint 03).
 *
 * Kept separate from the core barrel (src/index.ts) so the crypto path's
 * import graph stays free of atproto code.
 *
 * Usage:
 *   import { buildRecord, AtpClient, MockPds, publishReceipt } from '@scopetrail/core/atproto';
 */
export * from './record.js';
export * from './auth.js';
export * from './client.js';
export * from './mock-pds.js';
export * from './publish.js';
export * from './verify-uri.js';
export * from './jwks.js';
//# sourceMappingURL=index.d.ts.map