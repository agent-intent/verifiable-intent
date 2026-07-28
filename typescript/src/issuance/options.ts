/** Shared issuance options. */

/**
 * Produces disclosure salts. Defaults to a cryptographically random source.
 * Tests inject a deterministic FIFO source to reproduce recorded vectors.
 */
export type SaltSource = () => string | Promise<string>;

export interface IssueOptions {
  /** Key identifier placed in the JWT header. Defaults per layer. */
  kid?: string;
  /** Override the disclosure salt source (e.g. for deterministic tests). */
  saltSource?: SaltSource;
}
