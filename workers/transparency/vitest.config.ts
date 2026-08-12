import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

const TEST_SIGNING_KID = 'transparency-test-2026-08';
const TEST_PRIVATE_KEY_PKCS8 = 'MC4CAQAwBQYDK2VwBCIEIMWqjfQ_n4N77bdELzHct7Fm04U1B28JS4XOOi4LRFj3'; // gitleaks:allow -- fixed test-only Ed25519 fixture
const TEST_PUBLIC_KEY = '_FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU';

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      // The currently installed workerd build tops out at this date. Production
      // remains pinned to 2026-08-11 in Wrangler; no tested API depends on the gap.
      miniflare: {
        compatibilityDate: '2026-07-29',
        bindings: {
          TRANSPARENCY_SIGNING_KID: TEST_SIGNING_KID,
          TRANSPARENCY_SIGNING_KEY_PKCS8_B64URL: TEST_PRIVATE_KEY_PKCS8,
          TRANSPARENCY_PUBLIC_KEYSET_JSON: JSON.stringify({
            keys: [
              {
                kty: 'OKP',
                crv: 'Ed25519',
                alg: 'EdDSA',
                kid: TEST_SIGNING_KID,
                x: TEST_PUBLIC_KEY,
                use: 'sig',
              },
            ],
          }),
        },
      },
    }),
  ],
  test: {
    include: ['src/scheduled-publication.test.ts', 'src/transparency-shard-do.test.ts'],
  },
});
