import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  target: 'es2022',
  // jose is small but we ship it as a regular dep, so let tsup handle
  // the import correctly across ESM and CJS. Mark as external so we
  // don't bundle it — npm consumers get a single resolved copy.
  external: ['jose'],
});
