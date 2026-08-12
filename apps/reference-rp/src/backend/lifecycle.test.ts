import { signProtocolPayload, WebCryptoProvider } from '@nexus/crypto';
import { DEVICE_STATUS_STATEMENT_PROTOCOL_V2, decodeBase64Url } from '@nexus/protocol';
import type {
  Base64Url32,
  Base64Url64,
  DeviceRegistryStatusV2,
  DeviceStatusStatementPayloadV2,
  NexusDeviceAuthorizationIdV2,
  NexusDeviceIdV2,
  NexusSubject,
  ServiceKeySet,
} from '@nexus/protocol';
import { describe, expect, it } from 'vitest';

import { AuthoritativeRegistryLifecycleProvider } from './lifecycle.js';

const TEST_KEYSET: ServiceKeySet = {
  keys: [
    {
      kty: 'OKP',
      crv: 'Ed25519',
      alg: 'EdDSA',
      kid: 'test-status-key',
      x: '_FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU' as Base64Url32,
      use: 'sig',
    },
  ],
};
const TEST_PRIVATE_KEY = 'MC4CAQAwBQYDK2VwBCIEIMWqjfQ_n4N77bdELzHct7Fm04U1B28JS4XOOi4LRFj3'; // gitleaks:allow -- fixed test-only Ed25519 fixture
const NOW = 1_800_000_000;
const SUBJECT: NexusSubject = `nx1_${'A'.repeat(43)}`;
const DEVICE_ID: NexusDeviceIdV2 = `nxd2_${'B'.repeat(42)}A`;
const AUTHORIZATION_ID: NexusDeviceAuthorizationIdV2 = `nxa2_${'C'.repeat(42)}A`;
const GENESIS_HASH = `${'D'.repeat(42)}A` as Base64Url32;
const cryptoProvider = new WebCryptoProvider();

describe('AuthoritativeRegistryLifecycleProvider', () => {
  it('uses the Nexus protocol media type for the fixed status endpoint', async () => {
    const subject: NexusSubject = `nx1_${'A'.repeat(43)}`;
    let requestedUrl = '';
    let requestedInit: RequestInit | undefined;
    const provider = new AuthoritativeRegistryLifecycleProvider(
      'https://nexus.rowo.link',
      TEST_KEYSET,
      (input, init) => {
        requestedUrl =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        requestedInit = init;
        return Promise.resolve(new Response(null, { status: 404 }));
      },
    );

    await expect(provider.getAuthoritativeStatus(subject)).resolves.toEqual({ state: 'not-found' });
    expect(requestedUrl).toBe('https://nexus.rowo.link/v1/identity/status');
    expect(new Headers(requestedInit?.headers).get('content-type')).toBe('application/nexus+json');
    expect(requestedInit?.method).toBe('POST');
    expect(requestedInit?.body).toBe(JSON.stringify({ subject }));
  });

  it.each(['stale', 'forged', 'wrong-tuple'] as const)(
    'rejects a %s signed device status response',
    async (mode) => {
      const response = await deviceStatusResponse(mode);
      const provider = new AuthoritativeRegistryLifecycleProvider(
        'https://nexus.rowo.link',
        TEST_KEYSET,
        () => Promise.resolve(response.clone()),
        () => NOW,
      );
      await expect(
        provider.getAuthoritativeDeviceStatus(SUBJECT, DEVICE_ID, AUTHORIZATION_ID),
      ).rejects.toThrow();
    },
  );

  it('returns a cryptographically verified revoked-identity device status', async () => {
    const response = await deviceStatusResponse('revoked-identity');
    const provider = new AuthoritativeRegistryLifecycleProvider(
      'https://nexus.rowo.link',
      TEST_KEYSET,
      () => Promise.resolve(response.clone()),
      () => NOW,
    );
    await expect(
      provider.getAuthoritativeDeviceStatus(SUBJECT, DEVICE_ID, AUTHORIZATION_ID),
    ).resolves.toMatchObject({ state: 'revoked', identityState: 'revoked', identitySequence: 1 });
  });

  it('treats an authorization as expired at its exact expiry second', async () => {
    const response = await deviceStatusResponse('expiry-boundary');
    const provider = new AuthoritativeRegistryLifecycleProvider(
      'https://nexus.rowo.link',
      TEST_KEYSET,
      () => Promise.resolve(response.clone()),
      () => NOW,
    );
    await expect(
      provider.getAuthoritativeDeviceStatus(SUBJECT, DEVICE_ID, AUTHORIZATION_ID),
    ).resolves.toMatchObject({ state: 'expired', authorizationExpiresAt: NOW });
  });

  it('rejects an active status at the exact authorization expiry second', async () => {
    const response = await deviceStatusResponse('active-expiry-boundary');
    const provider = new AuthoritativeRegistryLifecycleProvider(
      'https://nexus.rowo.link',
      TEST_KEYSET,
      () => Promise.resolve(response.clone()),
      () => NOW,
    );
    await expect(
      provider.getAuthoritativeDeviceStatus(SUBJECT, DEVICE_ID, AUTHORIZATION_ID),
    ).rejects.toThrow();
  });
});

async function deviceStatusResponse(
  mode:
    | 'stale'
    | 'forged'
    | 'wrong-tuple'
    | 'revoked-identity'
    | 'expiry-boundary'
    | 'active-expiry-boundary',
): Promise<Response> {
  const authorizationId: NexusDeviceAuthorizationIdV2 =
    mode === 'wrong-tuple' ? `nxa2_${'E'.repeat(42)}A` : AUTHORIZATION_ID;
  const identityState = mode === 'revoked-identity' ? 'revoked' : 'active';
  const deviceState =
    mode === 'revoked-identity' ? 'revoked' : mode === 'expiry-boundary' ? 'expired' : 'active';
  const issuedAt = mode === 'stale' ? NOW - 120 : NOW;
  const payload: DeviceStatusStatementPayloadV2 = {
    protocol: DEVICE_STATUS_STATEMENT_PROTOCOL_V2,
    subject: SUBJECT,
    genesisHash: GENESIS_HASH,
    identityState,
    identitySequence: identityState === 'active' ? 0 : 1,
    deviceLedgerSequence: 1,
    deviceId: DEVICE_ID,
    authorizationId,
    deviceState,
    activatedAt: NOW - 300,
    ...(deviceState === 'revoked' ? { revokedAt: NOW - 1 } : {}),
    authorizationExpiresAt:
      mode === 'expiry-boundary' || mode === 'active-expiry-boundary' ? NOW : NOW + 3_600,
    iat: issuedAt,
    exp: issuedAt + 60,
    signerKid: 'test-status-key',
  };
  const privateKey = await cryptoProvider.importEd25519PrivateKey(
    decodeBase64Url(TEST_PRIVATE_KEY),
  );
  const validSignature = (await signProtocolPayload(
    payload,
    privateKey,
    cryptoProvider,
  )) as Base64Url64;
  const signature: Base64Url64 =
    mode === 'forged'
      ? (`${validSignature[0] === 'A' ? 'B' : 'A'}${validSignature.slice(1)}` as Base64Url64)
      : validSignature;
  const status: DeviceRegistryStatusV2 = {
    subject: SUBJECT,
    genesisHash: GENESIS_HASH,
    identityState,
    identitySequence: payload.identitySequence,
    deviceLedgerSequence: payload.deviceLedgerSequence,
    deviceId: DEVICE_ID,
    authorizationId,
    deviceState,
    activatedAt: payload.activatedAt ?? null,
    revokedAt: payload.revokedAt ?? null,
    authorizationExpiresAt: payload.authorizationExpiresAt ?? null,
    statusStatement: { payload, signature },
  };
  return Response.json(status);
}
