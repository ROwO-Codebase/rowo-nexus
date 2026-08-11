import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

const failureQueueScript = `
  import { WorkerEntrypoint } from 'cloudflare:workers';
  let shouldFail = true;
  let messages = [];

  export default class TestQueue extends WorkerEntrypoint {
    async send(message) {
      messages.push(message);
      if (shouldFail) throw new Error('simulated queue outage');
    }
    async setFailure(value) { shouldFail = value; }
    async reset(value = true) { shouldFail = value; messages = []; }
    async getMessages() { return messages; }
  }
`;

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.test.jsonc' },
      miniflare: {
        serviceBindings: {
          REGISTRY_EVENTS: 'registry-test-queue',
          TEST_QUEUE_CONTROL: 'registry-test-queue',
        },
        workers: [
          {
            name: 'registry-test-queue',
            modules: true,
            script: failureQueueScript,
          },
        ],
      },
    }),
  ],
  test: {
    include: ['test/**/*.worker.test.ts'],
  },
});
