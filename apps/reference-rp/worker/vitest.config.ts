import { cloudflareTest } from '@cloudflare/vitest-pool-workers';

const lifecycleService = `
  const identities = new Map();
  const devices = new Map();
  const signature = 'A'.repeat(86);
  const statusPrivateKey = 'MC4CAQAwBQYDK2VwBCIEIMWqjfQ_n4N77bdELzHct7Fm04U1B28JS4XOOi4LRFj3'; // gitleaks:allow -- fixed test-only Ed25519 fixture
  let deviceStatusMode = 'fresh';

  const decode = (value) => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4)), (character) => character.charCodeAt(0));
  const encode = (value) => btoa(String.fromCharCode(...value)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
  const canonical = (value) => {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
    return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  };
  const signStatus = async (payload) => {
    const privateKey = await crypto.subtle.importKey('pkcs8', decode(statusPrivateKey), { name: 'Ed25519' }, false, ['sign']);
    const preimage = new TextEncoder().encode('NEXUS-SIGNATURE\\0' + payload.protocol + '\\0' + canonical(payload));
    return encode(new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, preimage)));
  };

  export default {
    async fetch(request) {
      const url = new URL(request.url);
      const text = request.method === 'POST' ? await request.text() : '';
      const body = text.length === 0 ? {} : JSON.parse(text);
      if (url.pathname === '/__test/reset') {
        identities.clear();
        devices.clear();
        deviceStatusMode = 'fresh';
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
      if (url.pathname === '/__test/device') {
        devices.set(body.deviceId, { ...body, state: 'active' });
        return Response.json({ ok: true });
      }
      if (url.pathname === '/__test/revoke-device') {
        const current = devices.get(body.deviceId);
        if (current) devices.set(body.deviceId, { ...current, state: 'revoked' });
        return Response.json({ ok: true });
      }
      if (url.pathname === '/__test/device-status-mode') {
        deviceStatusMode = body.mode;
        return Response.json({ ok: true });
      }
      if (url.pathname === '/v2/device/status') {
        const device = devices.get(body.deviceId);
        if (!device || device.subject !== body.subject || device.authorizationId !== body.authorizationId) {
          return Response.json({ error: { code: 'DEVICE_NOT_FOUND', message: 'Not found.' } }, { status: 404 });
        }
        const now = Math.floor(Date.now() / 1000);
        const identity = identities.get(body.subject);
        const identityState = identity?.state === 'active' ? 'active' : 'revoked';
        const deviceState = deviceStatusMode === 'expiry-boundary' ? 'expired' : device.state;
        const statementAuthorizationId = deviceStatusMode === 'wrong-tuple' ? 'nxa2_' + 'A'.repeat(43) : body.authorizationId;
        const issuedAt = deviceStatusMode === 'stale' ? now - 120 : now;
        const authorizationExpiresAt = deviceStatusMode === 'expiry-boundary' || deviceStatusMode === 'active-expiry-boundary' ? now : device.authorizationExpiresAt;
        const payload = {
          protocol: 'nexus.device-status-statement.v2',
          subject: body.subject,
          genesisHash: device.genesisHash,
          identityState,
          identitySequence: identityState === 'active' ? 0 : 1,
          deviceLedgerSequence: deviceState === 'revoked' ? 2 : 1,
          deviceId: body.deviceId,
          authorizationId: statementAuthorizationId,
          deviceState,
          activatedAt: device.activatedAt,
          ...(deviceState === 'revoked' ? { revokedAt: now } : {}),
          authorizationExpiresAt,
          iat: issuedAt,
          exp: issuedAt + 60,
          signerKid: 'test-status-key'
        };
        const validSignature = await signStatus(payload);
        const deviceSignature = deviceStatusMode === 'forged'
          ? (validSignature[0] === 'A' ? 'B' : 'A') + validSignature.slice(1)
          : validSignature;
        return Response.json({
          subject: body.subject,
          genesisHash: device.genesisHash,
          identityState: payload.identityState,
          identitySequence: payload.identitySequence,
          deviceLedgerSequence: payload.deviceLedgerSequence,
          deviceId: body.deviceId,
          authorizationId: statementAuthorizationId,
          deviceState,
          activatedAt: device.activatedAt,
          revokedAt: deviceState === 'revoked' ? now : null,
          authorizationExpiresAt,
          statusStatement: { payload, signature: deviceSignature }
        });
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
        bindings: {
          RP_AUDIENCE: 'https://notes.example.test',
          SERVICE_JWKS_JSON: JSON.stringify({
            keys: [
              {
                kty: 'OKP',
                crv: 'Ed25519',
                alg: 'EdDSA',
                kid: 'test-status-key',
                x: '_FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU',
                use: 'sig',
              },
            ],
          }),
        },
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
