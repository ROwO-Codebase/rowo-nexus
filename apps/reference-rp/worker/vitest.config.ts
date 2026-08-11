import { cloudflareTest } from '@cloudflare/vitest-pool-workers';

const lifecycleService = `
  const identities = new Map();
  const signature = 'A'.repeat(86);

  export default {
    async fetch(request) {
      const url = new URL(request.url);
      const text = request.method === 'POST' ? await request.text() : '';
      const body = text.length === 0 ? {} : JSON.parse(text);
      if (url.pathname === '/__test/reset') {
        identities.clear();
        return Response.json({ ok: true });
      }
      if (url.pathname === '/__test/register') {
        identities.set(body.subject, { genesis: body.genesis, state: 'active' });
        return Response.json({ ok: true });
      }
      if (url.pathname === '/__test/revoke') {
        const current = identities.get(body.subject);
        if (current) identities.set(body.subject, { ...current, state: 'revoked' });
        return Response.json({ ok: true });
      }
      if (url.pathname !== '/v1/identity/status') return new Response('Not Found', { status: 404 });
      const identity = identities.get(body.subject);
      if (!identity) return Response.json({ error: { code: 'IDENTITY_NOT_FOUND', message: 'Not found.' } }, { status: 404 });
      const now = Math.floor(Date.now() / 1000);
      const revoked = identity.state === 'revoked';
      const status = {
        subject: body.subject,
        state: identity.state,
        sequence: revoked ? 1 : 0,
        registeredAt: now - 60,
        revokedAt: revoked ? now : null,
        genesis: identity.genesis,
        statusStatement: {
          payload: {
            protocol: 'nexus.status-statement.v1',
            subject: body.subject,
            state: identity.state,
            sequence: revoked ? 1 : 0,
            registeredAt: now - 60,
            ...(revoked ? { revokedAt: now } : {}),
            iat: now,
            exp: now + 60,
            signerKid: 'test-status-key'
          },
          signature
        }
      };
      return Response.json(status);
    }
  };
`;

const rateLimitService = `
  import { WorkerEntrypoint } from 'cloudflare:workers';
  let mode = 'allow';
  let keys = [];

  export default class TestRateLimiter extends WorkerEntrypoint {
    async limit(input) {
      keys.push(input.key);
      if (mode === 'fail') return {};
      return { success: mode === 'allow' };
    }
    setMode(value) { mode = value; }
    reset() { mode = 'allow'; keys = []; }
    getKeys() { return keys; }
    fetch() { return new Response('Not Found', { status: 404 }); }
  }
`;

export default {
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './worker/wrangler.test.jsonc' },
      miniflare: {
        compatibilityDate: '2026-07-29',
        bindings: { RP_AUDIENCE: 'https://notes.example.test' },
        serviceBindings: {
          NEXUS_API: 'reference-rp-lifecycle-test',
          RP_API_RATE_LIMITER: 'reference-rp-rate-limit-test',
          TEST_LIFECYCLE: 'reference-rp-lifecycle-test',
        },
        workers: [
          {
            name: 'reference-rp-lifecycle-test',
            modules: true,
            script: lifecycleService,
          },
          {
            name: 'reference-rp-rate-limit-test',
            modules: true,
            script: rateLimitService,
          },
        ],
      },
    }),
  ],
  test: {
    include: ['worker/**/*.worker.test.ts'],
  },
};
