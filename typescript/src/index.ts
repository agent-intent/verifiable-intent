/**
 * Verifiable Intent — TypeScript implementation.
 *
 * A layered SD-JWT delegation chain (Issuer → User → Agent) for cryptographic
 * agent authorization in commerce. Port of the Python reference implementation.
 *
 * Surface: crypto primitives, models, issuance, and verification
 * (chain verification, integrity bindings, and the constraint checker).
 */

export const VERSION = '0.1.0';

export * from './crypto/index.js';
export * from './models/index.js';
export * from './issuance/index.js';
export * from './verification/index.js';
