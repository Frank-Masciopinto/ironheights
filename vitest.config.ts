import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/core/**/*.ts', 'src/rules/**/*.ts'],
      exclude: ['src/rules/data/**'],
      thresholds: {
        lines: 85,
        statements: 85,
      },
    },
  },
});
