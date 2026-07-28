/**
 * Internal runtime type guards shared across modules.
 *
 * Intentionally NOT re-exported from src/index.ts — these are implementation
 * details. Centralized so the security-critical `isJsonObject` check (which underpins
 * fail-closed validation throughout the verifier) can never drift between call
 * sites.
 */

import type { JsonObject } from '../models/constraints.js';

/** True for a plain object — not null, not an array. */
export const isJsonObject = (v: unknown): v is JsonObject => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Coerce to an array, or `[]` when the value isn't one (defensive handling of untrusted input). */
export const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
