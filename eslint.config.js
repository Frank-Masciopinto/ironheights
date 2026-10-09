import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'dist-scripts/**',
      'dist-types/**',
      'coverage/**',
      'bench/results/**',
      'node_modules/**',
      'scripts/generate-fixtures.mjs',
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.strict,
  {
    rules: {
      'no-console': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
  {
    files: ['src/cli/**/*.ts', 'src/util/terminal.ts', 'scripts/**/*.ts'],
    rules: { 'no-console': 'off' },
  },
  {
    files: ['test/**/*.ts', 'bench/**/*.ts', 'vitest.config.ts', 'tsup.config.ts'],
    rules: { 'no-console': 'off' },
  },
);
