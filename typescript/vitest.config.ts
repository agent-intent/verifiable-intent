import { defineConfig } from 'vitest/config';

/**
 * The library uses explicit `.js` extensions on relative imports (correct for
 * the NodeNext ESM build). This pre-resolver maps `./foo.js` to `./foo.ts` so
 * Vitest can run the TypeScript sources directly without a build step.
 */
export default defineConfig({
  plugins: [
    {
      name: 'vi-resolve-js-to-ts',
      enforce: 'pre',
      async resolveId(source, importer) {
        if (importer && source.startsWith('.') && source.endsWith('.js')) {
          const resolved = await this.resolve(source.slice(0, -3) + '.ts', importer, { skipSelf: true });
          if (resolved) return resolved.id;
        }
        return null;
      },
    },
  ],
  test: {
    globals: true,
    environment: 'node',
    include: ['test/**/*.test.ts'],
  },
});
