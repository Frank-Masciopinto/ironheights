import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    'cli/index': 'src/cli/index.ts',
    'openclaw/plugin': 'src/openclaw/plugin.ts',
  },
  format: ['esm'],
  target: 'node20',
  clean: true,
  // Declarations so package.json "types" points at a file the build emits.
  // Suggested by psfazila02-hub in https://github.com/Frank-Masciopinto/ironheights/pull/120.
  dts: true,
  sourcemap: true,
  outDir: 'dist',
  banner: { js: '#!/usr/bin/env node' },
});
