import { describe, expect, it, vi } from 'vitest';

import { deriveGenesisHash, deriveSubject } from '@nexus/crypto';
import {
  REGISTRY_EVENT_PROTOCOL_V1,
  encodeBase64Url,
  identityGenesisV1Schema,
  registryEventV1Schema,
  registryReceiptV1Schema,
  statusStatementV1Schema,
  type RegistryReceiptPayloadV1,
  type StatusStatementPayloadV1,
} from '@nexus/protocol';

import {
  createEdgeApi,
  type EdgeDependencies,
  type Env,
  type PublicApiRateLimiter,
  type RegistryService,
} from '../src/index.js';

const API_ORIGIN = 'https://nexus.rowo.link';
const WALLET_ORIGIN = 'https://wallet.rowo.link';
const B64_32_ZERO = encodeBase64Url(new Uint8Array(32));
const B64_32_ONE = encodeBase64Url(new Uint8Array(32).fill(1));
const B64_64_ZERO = encodeBase64Url(new Uint8Array(64));
const NONCE = encodeBase64Url(new Uint8Array(16).fill(2));
const REVOCATION_SECRET = encodeBase64Url(new Uint8Array(32).fill(3));

const genesis = identityGenesisV1Schema.parse({
  protocol: 'nexus.identity.v1',
  suite: 'NX-25519-SHA256-JCS-v1',
  signingKey: { alg: 'Ed25519', publicKey: B64_32_ZERO },
  agreementKey: { alg: 'X25519', publicKey: B64_32_ONE },
  revocationCommitment: B64_32_ONE,
});

async function fixture() {
  const subject = await deriveSubject(genesis);
  const genesisHash = encodeBase64Url(await deriveGenesisHash(genesis));
  const active = {
    subject,
    state: 'active' as const,
    sequence: 0,
    registeredAt: 1_700_000_000,
    revokedAt: null,
    genesis,
    genesisHash,
    eventId: `nxe1_${B64_32_ZERO}`,
    eventType: 'registered' as const,
    acceptedAt: 1_700_000_000,
  };
  const activeMutation = {
    ...active,
    event: registryEventV1Schema.parse({
      protocol: REGISTRY_EVENT_PROTOCOL_V1,
      eventId: active.eventId,
      eventType: active.eventType,
      subject,
      genesisHash,
      sequence: 0,
      state: 'active' as const,
      acceptedAt: active.acceptedAt,
      actionHash: B64_32_ONE,
    }),
  };
  const revoked = {
    subject,
    state: 'revoked' as const,
    sequence: 1,
    registeredAt: active.registeredAt,
    revokedAt: 1_700_000_100,
    genesis,
    genesisHash,
    eventId: `nxe1_${B64_32_ONE}`,
    eventType: 'revoked' as const,
    acceptedAt: 1_700_000_100,
  };
  const revokedMutation = {
    ...revoked,
    event: registryEventV1Schema.parse({
      protocol: REGISTRY_EVENT_PROTOCOL_V1,
      eventId: revoked.eventId,
      eventType: revoked.eventType,
      subject,
      genesisHash,
      sequence: 1,
      state: 'revoked' as const,
      acceptedAt: revoked.acceptedAt,
      actionHash: B64_32_ZERO,
    }),
  };
  return { subject, active, activeMutation, revoked, revokedMutation };
}

function fakeSignReceipt(payload: RegistryReceiptPayloadV1) {
  return Promise.resolve(registryReceiptV1Schema.parse({ payload, signature: B64_64_ZERO }));
}

function fakeSignStatus(payload: StatusStatementPayloadV1) {
  return Promise.resolve(statusStatementV1Schema.parse({ payload, signature: B64_64_ZERO }));
}

async function setup(overrides: Pick<EdgeDependencies, 'rateLimitKey'> = {}) {
  const data = await fixture();
  const calls = {
    register: vi.fn<RegistryService['register']>(() =>
      Promise.resolve({ ok: true as const, value: data.activeMutation }),
    ),
    status: vi.fn<RegistryService['status']>(() =>
      Promise.resolve({ ok: true as const, value: data.active }),
    ),
    statusBatch: vi.fn<RegistryService['statusBatch']>(() =>
      Promise.resolve([{ ok: true as const, value: data.active }]),
    ),
    revokeBySignature: vi.fn<RegistryService['revokeBySignature']>(() =>
      Promise.resolve({
        ok: true as const,
        value: data.revokedMutation,
      }),
    ),
    revokeBySecret: vi.fn<RegistryService['revokeBySecret']>(() =>
      Promise.resolve({ ok: true as const, value: data.revokedMutation }),
    ),
    rateLimit: vi.fn<PublicApiRateLimiter['limit']>(() => Promise.resolve({ success: true })),
  };
  const registry: RegistryService = {
    register: calls.register,
    status: calls.status,
    statusBatch: calls.statusBatch,
    revokeBySignature: calls.revokeBySignature,
    revokeBySecret: calls.revokeBySecret,
  };
  const env: Env = {
    REGISTRY_SERVICE: registry,
    PUBLIC_API_RATE_LIMITER: { limit: calls.rateLimit },
    PUBLIC_API_ORIGIN: API_ORIGIN,
    WALLET_ORIGIN,
    STATUS_TTL_SECONDS: '60',
    SERVICE_JWKS_JSON: JSON.stringify({
      keys: [
        {
          kty: 'OKP',
          crv: 'Ed25519',
          alg: 'EdDSA',
          kid: 'receipt-key',
          x: B64_32_ZERO,
          use: 'sig',
        },
        {
          kty: 'OKP',
          crv: 'Ed25519',
          alg: 'EdDSA',
          kid: 'status-key',
          x: B64_32_ONE,
          use: 'sig',
        },
      ],
    }),
    RECEIPT_SIGNING_KID: 'receipt-key',
    RECEIPT_SIGNING_PRIVATE_KEY: 'test-receipt-private-key',
    STATUS_SIGNING_KID: 'status-key',
    STATUS_SIGNING_PRIVATE_KEY: 'test-status-private-key',
  };
  const app = createEdgeApi({
    now: () => 1_700_000_010,
    monotonicNow: () => 1,
    requestId: () => `nxr_${'A'.repeat(22)}`,
    metricSink: null,
    signReceipt: fakeSignReceipt,
    signStatus: fakeSignStatus,
    ...overrides,
  });
  return { ...data, calls, env, app };
}

function post(path: string, body: unknown, origin?: string): Request {
  return new Request(`${API_ORIGIN}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/nexus+json',
      ...(origin === undefined ? {} : { Origin: origin }),
    },
    body: JSON.stringify(body),
  });
}

async function body(response: Response): Promise<Record<string, unknown>> {
  const parsed: unknown = await response.json();
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new TypeError('Expected a JSON object.');
  }
  return parsed as Record<string, unknown>;
}

function expectApiHeaders(response: Response): void {
  expect(response.headers.get('Content-Type')).toBe('application/nexus+json');
  expect(response.headers.get('Cache-Control')).toBe('no-store');
  expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
  expect(response.headers.get('Referrer-Policy')).toBe('no-referrer');
  expect(response.headers.has('Set-Cookie')).toBe(false);
  expect(response.headers.has('Access-Control-Allow-Credentials')).toBe(false);
}

describe('edge API', () => {
  it('serves cacheable discovery and public Ed25519 key history', async () => {
    const { app, env, calls } = await setup();
    const discovery = await app.fetch(new Request(`${API_ORIGIN}/.well-known/nexus.json`), env);
    expect(discovery.status).toBe(200);
    expect(discovery.headers.get('Cache-Control')).toBe('public, max-age=300, must-revalidate');
    expect(discovery.headers.get('Access-Control-Allow-Origin')).toBe('*');
    expect(await discovery.json()).toEqual({
      protocols: ['nexus.identity.v1', 'nexus.ownership-proof.v1'],
      suites: ['NX-25519-SHA256-JCS-v1'],
      registry: `${API_ORIGIN}/v1`,
      jwks: `${API_ORIGIN}/.well-known/jwks.json`,
      wallet: WALLET_ORIGIN,
    });

    const jwks = await app.fetch(new Request(`${API_ORIGIN}/.well-known/jwks.json`), env);
    const jwksText = await jwks.text();
    expect(jwks.status).toBe(200);
    expect(jwksText).toContain('receipt-key');
    expect(jwksText).toContain('status-key');
    expect(jwksText).not.toContain('private');
    expect(calls.rateLimit).not.toHaveBeenCalled();
  });

  it('registers only a recomputed subject and never forwards the abuse token', async () => {
    const { app, env, calls, subject } = await setup();
    const response = await app.fetch(
      post(
        '/v1/identity/register',
        { subject, genesis, turnstileToken: 'ephemeral-token' },
        WALLET_ORIGIN,
      ),
      env,
    );
    expect(response.status).toBe(200);
    expectApiHeaders(response);
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe(WALLET_ORIGIN);
    expect(calls.register).toHaveBeenCalledWith({ subject, genesis });
    const result = await body(response);
    expect(result).toHaveProperty('receipt.payload.eventType', 'registered');
    expect(result).toHaveProperty('status.statusStatement.payload.exp', 1_700_000_070);
    expect(JSON.stringify(result)).not.toContain('ephemeral-token');
  });

  it('rejects an invalid computed subject before calling registry RPC', async () => {
    const { app, env, calls } = await setup();
    const response = await app.fetch(
      post('/v1/identity/register', { subject: `nx1_${B64_32_ONE}`, genesis }, WALLET_ORIGIN),
      env,
    );
    expect(response.status).toBe(400);
    expect(await body(response)).toHaveProperty('error.code', 'INVALID_SUBJECT');
    expect(calls.register).not.toHaveBeenCalled();
  });

  it('enforces methods, exact mutation origins, HTTPS, media type, and body limits', async () => {
    const { app, env, subject } = await setup();
    const wrongMethod = await app.fetch(
      new Request(`${API_ORIGIN}/v1/identity/register`, { method: 'GET' }),
      env,
    );
    expect(wrongMethod.status).toBe(405);
    expect(wrongMethod.headers.get('Allow')).toBe('POST');

    const wrongOrigin = await app.fetch(
      post('/v1/identity/register', { subject, genesis }, 'https://evil.example'),
      env,
    );
    expect(wrongOrigin.status).toBe(403);
    expect(wrongOrigin.headers.has('Access-Control-Allow-Origin')).toBe(false);

    const insecure = await app.fetch(
      new Request('http://nexus.rowo.link/v1/identity/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/nexus+json' },
        body: JSON.stringify({ subject }),
      }),
      env,
    );
    expect(insecure.status).toBe(400);
    expect(await body(insecure)).toHaveProperty('error.code', 'HTTPS_REQUIRED');

    const wrongType = await app.fetch(
      new Request(`${API_ORIGIN}/v1/identity/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject }),
      }),
      env,
    );
    expect(wrongType.status).toBe(415);

    const oversized = await app.fetch(
      new Request(`${API_ORIGIN}/v1/identity/status`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/nexus+json',
          'Content-Length': '1025',
        },
        body: JSON.stringify({ subject }),
      }),
      env,
    );
    expect(oversized.status).toBe(413);
  });

  it('allows HTTP only for localhost with an explicit local-development flag', async () => {
    const { app, env, subject } = await setup();
    const localRequest = (): Request =>
      new Request('http://localhost:8787/v1/identity/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/nexus+json' },
        body: JSON.stringify({ subject }),
      });

    const rejectedByDefault = await app.fetch(localRequest(), env);
    expect(rejectedByDefault.status).toBe(400);
    expect(await body(rejectedByDefault)).toHaveProperty('error.code', 'HTTPS_REQUIRED');

    const localEnv: Env = { ...env, ALLOW_LOCALHOST_HTTP: 'true' };
    const acceptedLocally = await app.fetch(localRequest(), localEnv);
    expect(acceptedLocally.status).toBe(200);

    const nonLocal = await app.fetch(
      new Request('http://nexus.rowo.link/v1/identity/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/nexus+json' },
        body: JSON.stringify({ subject }),
      }),
      localEnv,
    );
    expect(nonLocal.status).toBe(400);
    expect(await body(nonLocal)).toHaveProperty('error.code', 'HTTPS_REQUIRED');
  });

  it('rejects duplicate and unknown JSON fields', async () => {
    const { app, env, subject } = await setup();
    const duplicate = await app.fetch(
      new Request(`${API_ORIGIN}/v1/identity/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/nexus+json' },
        body: `{"subject":"${subject}","\\u0073ubject":"${subject}"}`,
      }),
      env,
    );
    expect(duplicate.status).toBe(400);

    const unknown = await app.fetch(
      post('/v1/identity/status', { subject, label: 'must-not-pass' }),
      env,
    );
    expect(unknown.status).toBe(400);
  });

  it('returns signed authoritative status with wildcard, credential-free CORS', async () => {
    const { app, env, calls, subject } = await setup();
    const response = await app.fetch(
      post('/v1/identity/status', { subject }, 'https://relying-party.example'),
      env,
    );
    expect(response.status).toBe(200);
    expectApiHeaders(response);
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
    expect(calls.status).toHaveBeenCalledWith(subject);
    expect(await body(response)).toHaveProperty('statusStatement.payload.subject', subject);
  });

  it('preserves batch order and contains per-item neutral errors', async () => {
    const { app, env, calls, subject, active } = await setup();
    calls.statusBatch.mockResolvedValueOnce([
      { ok: true, value: active },
      {
        ok: false,
        error: { code: 'IDENTITY_NOT_FOUND', message: `leaked internal subject ${subject}` },
      },
      { ok: true, value: active },
    ]);
    const response = await app.fetch(
      post('/v1/identity/status-batch', { subjects: [subject, subject, subject] }),
      env,
    );
    expect(response.status).toBe(200);
    const text = await response.text();
    const parsed = JSON.parse(text) as { results: Array<Record<string, unknown>> };
    expect(parsed.results.map((item) => item.ok)).toEqual([true, false, true]);
    expect(parsed.results[1]).toHaveProperty('error.code', 'IDENTITY_NOT_FOUND');
    expect(text).not.toContain('leaked internal');
  });

  it('rejects batches above 100 without invoking RPC', async () => {
    const { app, env, calls, subject } = await setup();
    const response = await app.fetch(
      post('/v1/identity/status-batch', { subjects: Array.from({ length: 101 }, () => subject) }),
      env,
    );
    expect(response.status).toBe(400);
    expect(calls.statusBatch).not.toHaveBeenCalled();
  });

  it('returns a neutral rate-limit response before registry RPC', async () => {
    const rateLimitKey = vi.fn<NonNullable<EdgeDependencies['rateLimitKey']>>(() =>
      Promise.resolve('deterministic-test-key'),
    );
    const { app, env, calls, subject } = await setup({ rateLimitKey });
    calls.rateLimit.mockResolvedValueOnce({ success: false });

    const response = await app.fetch(
      new Request(`${API_ORIGIN}/v1/identity/status`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/nexus+json',
          'CF-Connecting-IP': '203.0.113.10',
        },
        body: JSON.stringify({ subject }),
      }),
      env,
    );

    expect(response.status).toBe(429);
    expect(response.headers.get('Retry-After')).toBe('60');
    const responseText = await response.text();
    expect(JSON.parse(responseText)).toHaveProperty('error.code', 'RATE_LIMITED');
    expect(responseText).not.toContain(subject);
    expect(calls.rateLimit).toHaveBeenCalledWith({ key: 'deterministic-test-key' });
    expect(calls.status).not.toHaveBeenCalled();
    expect(rateLimitKey).toHaveBeenCalledWith(expect.any(Request), 'status', 1_700_000_010);
  });

  it('derives an ephemeral limiter key without exposing the subject or raw IP', async () => {
    const { app, env, calls, subject } = await setup();
    const rawIp = '203.0.113.77';
    const response = await app.fetch(
      new Request(`${API_ORIGIN}/v1/identity/status`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/nexus+json',
          'CF-Connecting-IP': rawIp,
        },
        body: JSON.stringify({ subject }),
      }),
      env,
    );

    expect(response.status).toBe(200);
    const limiterKey = calls.rateLimit.mock.calls[0]?.[0].key;
    expect(limiterKey).toMatch(/^nexus-edge-v1:status:[0-9]+:[A-Za-z0-9_-]{43}$/u);
    expect(limiterKey).not.toContain(rawIp);
    expect(limiterKey).not.toContain(subject);
  });

  it('accepts exactly one revocation mode and never echoes the secret', async () => {
    const { app, env, calls, subject } = await setup();
    const response = await app.fetch(
      post(
        '/v1/identity/revoke',
        {
          mode: 'secret',
          payload: {
            protocol: 'nexus.revoke-secret.v1',
            subject,
            expectedSequence: 0,
            revocationSecret: REVOCATION_SECRET,
          },
        },
        WALLET_ORIGIN,
      ),
      env,
    );
    expect(response.status).toBe(200);
    expect(calls.revokeBySecret).toHaveBeenCalledOnce();
    const text = await response.text();
    expect(text).toContain('revoked');
    expect(text).not.toContain(REVOCATION_SECRET);

    const ambiguous = await app.fetch(
      post(
        '/v1/identity/revoke',
        {
          mode: 'secret',
          payload: {
            protocol: 'nexus.revoke-secret.v1',
            subject,
            expectedSequence: 0,
            revocationSecret: REVOCATION_SECRET,
          },
          signature: B64_64_ZERO,
        },
        WALLET_ORIGIN,
      ),
      env,
    );
    expect(ambiguous.status).toBe(400);

    const signed = await app.fetch(
      post(
        '/v1/identity/revoke',
        {
          mode: 'signature',
          payload: {
            protocol: 'nexus.revoke.v1',
            subject,
            expectedSequence: 0,
            nonce: NONCE,
            iat: 1_700_000_010,
          },
          signature: B64_64_ZERO,
        },
        WALLET_ORIGIN,
      ),
      env,
    );
    expect(signed.status).toBe(200);
    expect(calls.revokeBySignature).toHaveBeenCalledOnce();
  });

  it('maps thrown RPC failures and logs only aggregate dimensions', async () => {
    const { env, calls, subject } = await setup();
    calls.status.mockRejectedValueOnce(new Error(`secret proof ${REVOCATION_SECRET}`));
    const records: unknown[] = [];
    const app = createEdgeApi({
      now: () => 1_700_000_010,
      monotonicNow: () => 1,
      requestId: () => `nxr_${'A'.repeat(22)}`,
      metricSink: { write: (record) => records.push(record) },
      signReceipt: fakeSignReceipt,
      signStatus: fakeSignStatus,
    });
    const response = await app.fetch(post('/v1/identity/status', { subject }), env);
    expect(response.status).toBe(503);
    const text = await response.text();
    expect(text).not.toContain(subject);
    expect(text).not.toContain(REVOCATION_SECRET);
    expect(JSON.stringify(records)).toBe(
      JSON.stringify([
        {
          event: 'api_result',
          operation: 'status',
          result: 'error',
          latencyBucket: 'lt10ms',
          errorCode: 'SERVICE_UNAVAILABLE',
        },
      ]),
    );
    expect(JSON.stringify(records)).not.toContain(subject);
  });

  it('handles exact and public preflights without enabling credentials', async () => {
    const { app, env } = await setup();
    const mutation = await app.fetch(
      new Request(`${API_ORIGIN}/v1/identity/revoke`, {
        method: 'OPTIONS',
        headers: {
          Origin: WALLET_ORIGIN,
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'content-type',
        },
      }),
      env,
    );
    expect(mutation.status).toBe(204);
    expect(mutation.headers.get('Access-Control-Allow-Origin')).toBe(WALLET_ORIGIN);
    expect(mutation.headers.has('Access-Control-Allow-Credentials')).toBe(false);

    const publicRead = await app.fetch(
      new Request(`${API_ORIGIN}/v1/identity/status`, {
        method: 'OPTIONS',
        headers: {
          Origin: 'https://rp.example',
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'content-type',
        },
      }),
      env,
    );
    expect(publicRead.status).toBe(204);
    expect(publicRead.headers.get('Access-Control-Allow-Origin')).toBe('*');
    expect(publicRead.headers.has('Access-Control-Allow-Credentials')).toBe(false);
  });
});
