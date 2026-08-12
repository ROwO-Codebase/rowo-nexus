import path from 'node:path';

import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

const queueScript = `
  import { WorkerEntrypoint } from 'cloudflare:workers';

  let messages = [];

  export default class AcceptanceQueue extends WorkerEntrypoint {
    async send(message) {
      messages.push(structuredClone(message));
    }

    async reset() {
      messages = [];
    }

    async getMessages() {
      return structuredClone(messages);
    }
  }
`;

export default defineConfig(async () => {
  const repositoryRoot = path.resolve(import.meta.dirname, '../..');
  const migrations = await readD1Migrations(path.join(repositoryRoot, 'migrations/d1'));

  return {
    root: repositoryRoot,
    resolve: {
      alias: {
        '@nexus/cloudflare-common': path.join(
          repositoryRoot,
          'packages/cloudflare-common/src/index.ts',
        ),
        '@nexus/crypto': path.join(repositoryRoot, 'packages/crypto/src/index.ts'),
        '@nexus/protocol': path.join(repositoryRoot, 'packages/protocol/src/index.ts'),
        '@nexus/test-vectors': path.join(repositoryRoot, 'packages/test-vectors/src/index.ts'),
        '@nexus/verifier': path.join(repositoryRoot, 'packages/verifier/src/index.ts'),
      },
    },
    plugins: [
      cloudflareTest({
        wrangler: {
          configPath: path.join(repositoryRoot, 'workers/registry/wrangler.test.jsonc'),
        },
        miniflare: {
          compatibilityDate: '2026-07-29',
          bindings: { TEST_MIGRATIONS: migrations },
          d1Databases: { INDEX_DB: 'nexus-index-acceptance' },
          serviceBindings: {
            REGISTRY_EVENTS: 'acceptance-registry-queue',
            REGISTRY_DEVICE_EVENTS: 'acceptance-registry-device-queue',
            TEST_QUEUE_CONTROL: 'acceptance-registry-queue',
            TEST_DEVICE_QUEUE_CONTROL: 'acceptance-registry-device-queue',
          },
          workers: [
            {
              name: 'acceptance-registry-queue',
              modules: true,
              script: queueScript,
            },
            {
              name: 'acceptance-registry-device-queue',
              modules: true,
              script: queueScript,
            },
          ],
        },
      }),
    ],
    test: {
      include: [
        'tests/concurrency/**/*.acceptance.ts',
        'tests/worker-integration/**/*.acceptance.ts',
      ],
      setupFiles: ['tests/worker-integration/setup.ts'],
    },
  };
});
