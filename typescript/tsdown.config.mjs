import { defineConfig } from 'tsdown';

/**
 * Build config for the publishable npm package. Produces dual ESM (.mjs) + CJS
 * (.cjs) output with bundled type declarations. The `@sd-jwt/*` runtime deps are
 * auto-externalized (they're in "dependencies"), so they stay as deps rather
 * than being inlined. `platform: 'node'` targets node:crypto (via
 * @sd-jwt/crypto-nodejs) and emits fixed .mjs/.cjs extensions.
 *
 * Authored as .mjs (not .ts) so tsdown loads it natively without a TS config loader.
 */
export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  platform: 'node',
  dts: true,
  sourcemap: true,
  clean: true,
  // exports map is maintained by hand in package.json (nested per-condition
  // types for clean ESM+CJS type resolution); don't let tsdown overwrite it.
  exports: false,
  // publint runs as a separate step (`npm run check:pkg`), not inside the build:
  // running it during the build breaks the `npm publish` lifecycle here because
  // tsdown's publint step shells out to `npm pack`, which collides with publish.
});
