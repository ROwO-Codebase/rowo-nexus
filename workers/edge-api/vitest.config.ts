import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

const fromHere = (path: string): string => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@nexus/cloudflare-common': fromHere('../../packages/cloudflare-common/src/index.ts'),
      '@nexus/crypto': fromHere('../../packages/crypto/src/index.ts'),
      '@nexus/protocol': fromHere('../../packages/protocol/src/index.ts'),
    },
  },
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
  },
});
