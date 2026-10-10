import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    'cli/index': 'src/cli/index.ts',
    'openclaw/plugin': 'src/openclaw/plugin.ts',
  },
  format: ['esm'],
  target: 'node20',
  clean: true,
  dts: false,
  sourcemap: true,
  outDir: 'dist',
  banner: { js: '#!/usr/bin/env node' },
});
