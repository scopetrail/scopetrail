// SPDX-License-Identifier: Apache-2.0
/**
 * Core type definitions for the OBO Audit Receipt library.
 * Interfaces correspond directly to PRD_ARCH.md §3 (Input Schema) and §4 (JSON-LD Artifact).
 */
/**
 * Typed validation error thrown by `extractContext()` when input fails validation.
 * Collects all field errors in a single throw rather than failing on the first.
 */
export class ContextValidationError extends Error {
    errors;
    constructor(errors) {
        const detail = errors.map(e => `  [${e.field}] ${e.rule}`).join('\n');
        super(`OBO context validation failed (${errors.length} error${errors.length === 1 ? '' : 's'}):\n${detail}`);
        this.name = 'ContextValidationError';
        this.errors = errors;
    }
}
//# sourceMappingURL=types.js.map