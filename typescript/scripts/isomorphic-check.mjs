/**
 * Browser-readiness proof for the BUILT artifact (dist/): delete Node's
 * `Buffer` global, then load both entry points (ESM `dist/index.mjs` and CJS
 * `dist/index.cjs`) and run a minimal issue → verify flow through each. Any
 * accidental Node-builtin dependency in the bundle would throw here.
 *
 * Wired as `npm run test:isomorphic` (builds first, so dist is always fresh).
 */

// Must run BEFORE the library is imported.
delete globalThis.Buffer;

if (typeof globalThis.Buffer !== 'undefined') {
  throw new Error('failed to delete the Buffer global');
}

const now = Math.floor(Date.now() / 1000);

async function exercise(vi, label) {
  const issuer = await vi.generateEs256Key();
  const user = await vi.generateEs256Key();
  const l1 = await vi.createLayer1(
    new vi.IssuerCredential({
      iss: 'https://www.mastercard.com',
      sub: 'user-123',
      iat: now,
      exp: now + 3600,
      cnfJwk: user.publicKey,
      email: 'user@example.com',
      panLastFour: '1234',
      scheme: 'Mastercard',
    }),
    issuer.privateKey,
  );
  const parsed = vi.decodeSdJwt(l1.serialize());
  if (!(await vi.verifySdJwtSignature(parsed, issuer.publicKey))) {
    throw new Error(`${label}: L1 signature did not verify`);
  }
  const resolved = await vi.resolveDisclosures(parsed);
  if (resolved.email !== 'user@example.com') {
    throw new Error(`${label}: disclosure resolution mismatch`);
  }
  const hash = await vi.hashAscii(l1.serialize());
  if (!/^[A-Za-z0-9_-]{43}$/.test(hash)) {
    throw new Error(`${label}: hashAscii returned an unexpected value`);
  }
  console.log(`${label}: issue -> verify -> resolve -> hash OK (Buffer undefined)`);
}

const esm = await import('../dist/index.mjs');
await exercise(esm, 'dist/index.mjs (ESM)');

const { createRequire } = await import('node:module');
const require = createRequire(import.meta.url);
await exercise(require('../dist/index.cjs'), 'dist/index.cjs (CJS)');

console.log('isomorphic check passed: the package runs with no Node Buffer global');
