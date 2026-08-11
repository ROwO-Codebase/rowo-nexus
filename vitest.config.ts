import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
    },
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      'tests/browser-e2e/**',
      'tests/worker-integration/**',
    ],
    include: ['packages/**/*.test.ts', 'tests/{protocol,security}/**/*.test.ts'],
  },
});
