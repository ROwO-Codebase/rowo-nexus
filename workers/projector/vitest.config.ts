import path from 'node:path';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

export default defineConfig(async () => {
  const migrations = await readD1Migrations(
    path.resolve(import.meta.dirname, '../../migrations/d1'),
  );

  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: './wrangler.test.jsonc' },
        miniflare: {
          // The current pool's bundled workerd trails the production
          // compatibility date by a few days. Keep deployment on 2026-08-11
          // and use the newest date this test runtime advertises.
          compatibilityDate: '2026-07-29',
          bindings: { TEST_MIGRATIONS: migrations },
        },
      }),
    ],
    test: {
      include: ['test/**/*.test.ts'],
      setupFiles: ['./test/apply-migrations.ts'],
    },
  };
});
