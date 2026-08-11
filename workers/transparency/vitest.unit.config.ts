import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: [
      'src/http.test.ts',
      'src/keyset.test.ts',
      'src/merkle.test.ts',
      'src/sharding.test.ts',
    ],
  },
});
