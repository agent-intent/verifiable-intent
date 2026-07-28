import { defineConfig } from 'tsdown';

/**
 * Build config for the publishable npm package. Produces dual ESM (.mjs) + CJS
 * (.cjs) output with bundled type declarations. The package has zero runtime
 * dependencies and uses only Web-standard globals (WebCrypto, TextEncoder), so
 * `platform: 'neutral'` keeps the bundle environment-agnostic — it runs on
 * Node >= 20 and in modern browsers. Emits fixed .mjs/.cjs extensions.
 *
 * Authored as .mjs (not .ts) so tsdown loads it natively without a TS config loader.
 */
export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  platform: 'neutral',
  // fixedExtension defaults to true only on platform 'node'; force it so the
  // ESM/CJS outputs keep the fixed .mjs/.cjs extensions the exports map expects.
  fixedExtension: true,
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
