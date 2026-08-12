import { describe, expect, it, vi } from 'vitest';

import { deriveGenesisHash, deriveSubject } from '@nexus/crypto';
import {
  DEVICE_REGISTRY_EVENT_PROTOCOL_V2,
  REGISTRY_EVENT_PROTOCOL_V1,
  deviceRegistryEventV2Schema,
  deviceRegistryReceiptV2Schema,
  deviceStatusStatementV2Schema,
  encodeBase64Url,
  identityGenesisV1Schema,
  registryEventV1Schema,
  registryReceiptV1Schema,
  statusStatementV1Schema,
  type RegistryReceiptPayloadV1,
  type DeviceRegistryReceiptPayloadV2,
  type DeviceStatusStatementPayloadV2,
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
  const deviceId = `nxd2_${B64_32_ONE}` as const;
  const authorizationId = `nxa2_${B64_32_ONE}` as const;
  const operationId = `nxo2_${B64_32_ONE}` as const;
  const deviceEventId = `nxde2_${B64_32_ONE}` as const;
  const deviceStatus = {
    subject,
    genesisHash,
    identityState: 'active' as const,
    identitySequence: 0,
    deviceLedgerSequence: 1,
    deviceId,
    authorizationId,
    deviceState: 'active' as const,
    activatedAt: 1_700_000_010,
    revokedAt: null,
    authorizationExpiresAt: 1_730_000_000,
  };
  const deviceActivationEvent = deviceRegistryEventV2Schema.parse({
    protocol: DEVICE_REGISTRY_EVENT_PROTOCOL_V2,
    eventId: deviceEventId,
    operationId,
    eventType: 'activated',
    subject,
    genesisHash,
    identitySequence: 0,
    identityState: 'active',
    deviceLedgerSequence: 1,
    deviceId,
    authorizationId,
    deviceState: 'active',
    authorizationExpiresAt: 1_730_000_000,
    acceptedAt: 1_700_000_010,
    actionHash: B64_32_ZERO,
  });
  const deviceActivationMutation = {
    ...deviceStatus,
    operationId,
    eventId: deviceEventId,
    eventType: 'activated' as const,
    acceptedAt: 1_700_000_010,
    event: deviceActivationEvent,
  };
  const deviceRevocationEvent = deviceRegistryEventV2Schema.parse({
    protocol: DEVICE_REGISTRY_EVENT_PROTOCOL_V2,
    eventId: `nxde2_${B64_32_ZERO}`,
    operationId: `nxo2_${B64_32_ZERO}`,
    eventType: 'revoked',
    subject,
    genesisHash,
    identitySequence: 0,
    identityState: 'active',
    deviceLedgerSequence: 2,
    deviceId,
    authorizationId,
    deviceState: 'revoked',
    authorizationExpiresAt: 1_730_000_000,
    acceptedAt: 1_700_000_020,
    actionHash: B64_32_ONE,
    revokedBy: 'device',
  });
  const deviceRevocationMutation = {
    ...deviceStatus,
    deviceLedgerSequence: 2,
    deviceState: 'revoked' as const,
    revokedAt: 1_700_000_020,
    operationId: deviceRevocationEvent.operationId,
    eventId: deviceRevocationEvent.eventId,
    eventType: 'revoked' as const,
    acceptedAt: deviceRevocationEvent.acceptedAt,
    event: deviceRevocationEvent,
  };
  const deviceRootRevocationEvent = deviceRegistryEventV2Schema.parse({
    ...deviceRevocationEvent,
    eventId: `nxde2_${B64_32_ONE}`,
    operationId: `nxo2_${B64_32_ONE}`,
    revokedBy: 'root',
  });
  const deviceRootRevocationMutation = {
    ...deviceRevocationMutation,
    operationId: deviceRootRevocationEvent.operationId,
    eventId: deviceRootRevocationEvent.eventId,
    event: deviceRootRevocationEvent,
  };
  return {
    subject,
    active,
    activeMutation,
    revoked,
    revokedMutation,
    deviceId,
    authorizationId,
    deviceStatus,
    deviceActivationMutation,
    deviceRevocationMutation,
    deviceRootRevocationMutation,
  };
}

function fakeSignReceipt(payload: RegistryReceiptPayloadV1) {
  return Promise.resolve(registryReceiptV1Schema.parse({ payload, signature: B64_64_ZERO }));
}

function fakeSignStatus(payload: StatusStatementPayloadV1) {
  return Promise.resolve(statusStatementV1Schema.parse({ payload, signature: B64_64_ZERO }));
}

function fakeSignDeviceReceipt(payload: DeviceRegistryReceiptPayloadV2) {
  return Promise.resolve(deviceRegistryReceiptV2Schema.parse({ payload, signature: B64_64_ZERO }));
}

function fakeSignDeviceStatus(payload: DeviceStatusStatementPayloadV2) {
  return Promise.resolve(deviceStatusStatementV2Schema.parse({ payload, signature: B64_64_ZERO }));
}

async function setup(overrides: Pick<EdgeDependencies, 'now' | 'rateLimitKey'> = {}) {
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
    activateDevice: vi.fn<RegistryService['activateDevice']>(() =>
      Promise.resolve({ ok: true as const, value: data.deviceActivationMutation }),
    ),
    deviceStatus: vi.fn<RegistryService['deviceStatus']>(() =>
      Promise.resolve({ ok: true as const, value: data.deviceStatus }),
    ),
    deviceStatusBatch: vi.fn<RegistryService['deviceStatusBatch']>(() =>
      Promise.resolve([{ ok: true as const, value: data.deviceStatus }]),
    ),
    revokeDeviceSelf: vi.fn<RegistryService['revokeDeviceSelf']>(() =>
      Promise.resolve({ ok: true as const, value: data.deviceRevocationMutation }),
    ),
    revokeDeviceRoot: vi.fn<RegistryService['revokeDeviceRoot']>(() =>
      Promise.resolve({ ok: true as const, value: data.deviceRootRevocationMutation }),
    ),
    rateLimit: vi.fn<PublicApiRateLimiter['limit']>(() => Promise.resolve({ success: true })),
  };
  const registry: RegistryService = {
    register: calls.register,
    status: calls.status,
    statusBatch: calls.statusBatch,
    revokeBySignature: calls.revokeBySignature,
    revokeBySecret: calls.revokeBySecret,
    activateDevice: calls.activateDevice,
    deviceStatus: calls.deviceStatus,
    deviceStatusBatch: calls.deviceStatusBatch,
    revokeDeviceSelf: calls.revokeDeviceSelf,
    revokeDeviceRoot: calls.revokeDeviceRoot,
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
    signDeviceReceipt: fakeSignDeviceReceipt,
    signDeviceStatus: fakeSignDeviceStatus,
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
    expect(await discovery.text()).toBe(
      JSON.stringify({
        protocols: ['nexus.identity.v1', 'nexus.ownership-proof.v1'],
        suites: ['NX-25519-SHA256-JCS-v1'],
        registry: `${API_ORIGIN}/v1`,
        jwks: `${API_ORIGIN}/.well-known/jwks.json`,
        wallet: WALLET_ORIGIN,
      }),
    );

    const discoveryV2 = await app.fetch(
      new Request(`${API_ORIGIN}/.well-known/nexus-v2.json`),
      env,
    );
    expect(discoveryV2.status).toBe(200);
    expect(discoveryV2.headers.get('Cache-Control')).toBe('public, max-age=300, must-revalidate');
    expect(discoveryV2.headers.get('Access-Control-Allow-Origin')).toBe('*');
    expect(await discoveryV2.json()).toEqual({
      protocols: [
        'nexus.identity.v1',
        'nexus.ownership-proof.v1',
        'nexus.device-authorization.v2',
        'nexus.ownership-proof.v2',
      ],
      suites: ['NX-25519-SHA256-JCS-v1'],
      registry: `${API_ORIGIN}/v1`,
      deviceRegistry: `${API_ORIGIN}/v2/device`,
      popupChannels: ['nexus.popup.v2', 'nexus.popup.v1'],
      v1Discovery: `${API_ORIGIN}/.well-known/nexus.json`,
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

  it('activates a v2 device and returns only a service-signed receipt', async () => {
    const { app, env, calls, subject, active, deviceId, authorizationId } = await setup();
    const authorization = {
      payload: {
        protocol: 'nexus.device-authorization.v2',
        subject,
        genesisHash: active.genesisHash,
        deviceId,
        signingKey: { alg: 'Ed25519', publicKey: B64_32_ONE },
        authorizationNonce: B64_32_ZERO,
        validFrom: 1_700_000_000,
        activationDeadline: 1_700_000_100,
        expiresAt: 1_730_000_000,
      },
      rootSignature: B64_64_ZERO,
    };
    const request = {
      authorization,
      payload: {
        protocol: 'nexus.device-activation.v2',
        subject,
        deviceId,
        authorizationId,
        requestId: B64_32_ONE,
        iat: 1_700_000_010,
        exp: 1_700_000_020,
      },
      deviceSignature: B64_64_ZERO,
    };
    const response = await app.fetch(post('/v2/device/activate', request, WALLET_ORIGIN), env);
    expect(response.status).toBe(200);
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe(WALLET_ORIGIN);
    expect(calls.activateDevice).toHaveBeenCalledWith(request);
    const responseBody = await body(response);
    expect(responseBody).toHaveProperty(
      'receipt.payload.protocol',
      'nexus.device-registry-receipt.v2',
    );
    expect(responseBody).toHaveProperty('receipt.payload.deviceId', deviceId);
    expect(responseBody).toHaveProperty('receipt.payload.authorizationId', authorizationId);
    expect(responseBody).toHaveProperty('receipt.payload.eventType', 'activated');
    expect(responseBody).toHaveProperty('receipt.signature', B64_64_ZERO);
  });

  it('refuses to sign a registry mutation for a different device authorization', async () => {
    const {
      app,
      env,
      calls,
      subject,
      active,
      deviceId,
      authorizationId,
      deviceActivationMutation,
    } = await setup();
    const otherAuthorizationId = `nxa2_${B64_32_ZERO}` as const;
    calls.activateDevice.mockResolvedValueOnce({
      ok: true,
      value: {
        ...deviceActivationMutation,
        authorizationId: otherAuthorizationId,
        event: deviceRegistryEventV2Schema.parse({
          ...deviceActivationMutation.event,
          authorizationId: otherAuthorizationId,
        }),
      },
    });
    const response = await app.fetch(
      post(
        '/v2/device/activate',
        {
          authorization: {
            payload: {
              protocol: 'nexus.device-authorization.v2',
              subject,
              genesisHash: active.genesisHash,
              deviceId,
              signingKey: { alg: 'Ed25519', publicKey: B64_32_ONE },
              authorizationNonce: B64_32_ZERO,
              validFrom: 1_700_000_000,
              activationDeadline: 1_700_000_100,
              expiresAt: 1_730_000_000,
            },
            rootSignature: B64_64_ZERO,
          },
          payload: {
            protocol: 'nexus.device-activation.v2',
            subject,
            deviceId,
            authorizationId,
            requestId: B64_32_ONE,
            iat: 1_700_000_010,
            exp: 1_700_000_020,
          },
          deviceSignature: B64_64_ZERO,
        },
        WALLET_ORIGIN,
      ),
      env,
    );
    expect(response.status).toBe(500);
    expect(await body(response)).toHaveProperty('error.code', 'INTERNAL_ERROR');
  });

  it('returns exact signed v2 device status and neutral ordered batch errors', async () => {
    const { app, env, calls, subject, deviceId, authorizationId, deviceStatus } = await setup();
    const query = { subject, deviceId, authorizationId };
    const response = await app.fetch(post('/v2/device/status', query, 'https://rp.example'), env);
    expect(response.status).toBe(200);
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
    expect(calls.deviceStatus).toHaveBeenCalledWith(query);
    expect(await body(response)).toHaveProperty(
      'statusStatement.payload.protocol',
      'nexus.device-status-statement.v2',
    );

    const otherAuthorizationId = `nxa2_${B64_32_ZERO}` as const;
    calls.deviceStatusBatch.mockResolvedValueOnce([
      { ok: true, value: deviceStatus },
      {
        ok: false,
        error: { code: 'DEVICE_NOT_FOUND', message: `must not leak ${subject}` },
      },
    ]);
    const batch = await app.fetch(
      post('/v2/device/status-batch', {
        devices: [query, { subject, deviceId, authorizationId: otherAuthorizationId }],
      }),
      env,
    );
    expect(batch.status).toBe(200);
    const batchText = await batch.text();
    const batchBody = JSON.parse(batchText) as { results: Array<Record<string, unknown>> };
    expect(batchBody.results.map((result) => result.ok)).toEqual([true, false]);
    expect(batchBody.results[1]).toHaveProperty('authorizationId', otherAuthorizationId);
    expect(batchBody.results[1]).toHaveProperty('error.code', 'DEVICE_NOT_FOUND');
    expect(batchText).not.toContain('must not leak');
  });

  it('exposes device errors only on v2 routes', async () => {
    const { app, env, calls, subject, deviceId, authorizationId } = await setup();
    calls.deviceStatus.mockResolvedValueOnce({
      ok: false,
      error: { code: 'DEVICE_REVOKED', message: `must not leak ${subject}` },
    });
    const deviceResponse = await app.fetch(
      post('/v2/device/status', { subject, deviceId, authorizationId }),
      env,
    );
    expect(deviceResponse.status).toBe(409);
    const deviceText = await deviceResponse.text();
    const deviceBody: unknown = JSON.parse(deviceText);
    expect(deviceBody).toMatchObject({ error: { code: 'DEVICE_REVOKED' } });
    expect(deviceText).not.toContain('must not leak');

    calls.status.mockResolvedValueOnce({
      ok: false,
      error: { code: 'DEVICE_NOT_FOUND', message: `must not leak ${subject}` },
    });
    const legacyResponse = await app.fetch(post('/v1/identity/status', { subject }), env);
    expect(legacyResponse.status).toBe(500);
    expect(await body(legacyResponse)).toHaveProperty('error.code', 'INTERNAL_ERROR');
  });

  it('never signs active device status beyond authorization expiry', async () => {
    const { app, env, calls, subject, deviceId, authorizationId, deviceStatus } = await setup();
    calls.deviceStatus.mockResolvedValueOnce({
      ok: true,
      value: { ...deviceStatus, authorizationExpiresAt: 1_700_000_030 },
    });
    const query = { subject, deviceId, authorizationId };
    const active = await app.fetch(post('/v2/device/status', query), env);
    expect(active.status).toBe(200);
    expect(await body(active)).toMatchObject({
      deviceState: 'active',
      statusStatement: { payload: { deviceState: 'active', exp: 1_700_000_030 } },
    });

    const boundary = await setup({ now: () => 1_730_000_000 });
    const expired = await boundary.app.fetch(
      post('/v2/device/status', {
        subject: boundary.subject,
        deviceId: boundary.deviceId,
        authorizationId: boundary.authorizationId,
      }),
      boundary.env,
    );
    expect(expired.status).toBe(200);
    expect(await body(expired)).toMatchObject({
      deviceState: 'expired',
      statusStatement: { payload: { deviceState: 'expired', iat: 1_730_000_000 } },
    });
  });

  it('strictly parses and origin-protects both v2 device revocation routes', async () => {
    const { app, env, calls, subject, active, deviceId, authorizationId } = await setup();
    const authorization = {
      payload: {
        protocol: 'nexus.device-authorization.v2',
        subject,
        genesisHash: active.genesisHash,
        deviceId,
        signingKey: { alg: 'Ed25519', publicKey: B64_32_ONE },
        authorizationNonce: B64_32_ZERO,
        validFrom: 1_700_000_000,
        activationDeadline: 1_700_000_100,
        expiresAt: 1_730_000_000,
      },
      rootSignature: B64_64_ZERO,
    };
    const selfRequest = {
      authorization,
      payload: {
        protocol: 'nexus.device-self-revoke.v2',
        subject,
        genesisHash: active.genesisHash,
        deviceId,
        authorizationId,
        requestId: B64_32_ZERO,
        issuedAt: 1_700_000_010,
      },
      deviceSignature: B64_64_ZERO,
    };
    const self = await app.fetch(post('/v2/device/revoke-self', selfRequest, WALLET_ORIGIN), env);
    expect(self.status).toBe(200);
    expect(calls.revokeDeviceSelf).toHaveBeenCalledWith(selfRequest);
    expect(await body(self)).toHaveProperty(
      'receipt.payload.protocol',
      'nexus.device-registry-receipt.v2',
    );

    const rootRequest = {
      payload: {
        protocol: 'nexus.device-root-revoke.v2',
        subject,
        genesisHash: active.genesisHash,
        deviceId,
        requestId: B64_32_ONE,
        issuedAt: 1_700_000_010,
      },
      rootSignature: B64_64_ZERO,
    };
    const wrongOrigin = await app.fetch(
      post('/v2/device/revoke-root', rootRequest, 'https://evil.example'),
      env,
    );
    expect(wrongOrigin.status).toBe(403);
    expect(calls.revokeDeviceRoot).not.toHaveBeenCalled();

    const unknownField = await app.fetch(
      post('/v2/device/revoke-root', { ...rootRequest, label: 'forbidden' }, WALLET_ORIGIN),
      env,
    );
    expect(unknownField.status).toBe(400);
    expect(calls.revokeDeviceRoot).not.toHaveBeenCalled();

    const root = await app.fetch(post('/v2/device/revoke-root', rootRequest, WALLET_ORIGIN), env);
    expect(root.status).toBe(200);
    expect(calls.revokeDeviceRoot).toHaveBeenCalledWith(rootRequest);
    expect(await body(root)).toHaveProperty('receipt.payload.revokedBy', 'root');
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
