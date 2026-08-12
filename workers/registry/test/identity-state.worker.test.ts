import { env } from 'cloudflare:workers';
import { runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { IdentityState } from '../src/identity-state-do';
import {
  base64Url64Schema,
  base64UrlAtLeast16Schema,
  deviceActivationPayloadV2Schema,
  deviceActivationRequestV2Schema,
  deviceAuthorizationPayloadV2Schema,
  deviceRootRevokeRequestV2Schema,
  deviceSelfRevokeRequestV2Schema,
  encodeBase64Url,
  ownershipProofPayloadV2Schema,
  ownershipProofV2Schema,
  revokeBySecretV1Schema,
} from '@nexus/protocol';
import type {
  DeviceActivationRequestV2,
  DeviceRegistryEventV2,
  NexusSubject,
  OwnershipProofV2,
  RegistryEventV1,
  VerificationExpectationV2,
} from '@nexus/protocol';
import {
  deriveDeviceAuthorizationIdV2,
  deriveDeviceIdV2,
  signProtocolPayload,
} from '@nexus/crypto';
import { verifyRpOperationV2 } from '@nexus/verifier';
import type { ChallengeStore, DeviceLifecycleProvider, LifecycleProvider } from '@nexus/verifier';
import {
  createDeviceFixture,
  createDeviceRootRevocation,
  createDeviceSelfRevocation,
  createIdentityFixture,
  createSecretRevocation,
  createSignatureRevocation,
} from './fixtures';
import type { DeviceFixture, IdentityFixture } from './fixtures';

interface QueueControl {
  setFailure(value: boolean): Promise<void>;
  reset(value?: boolean): Promise<void>;
  getMessages(): Promise<Array<RegistryEventV1 | DeviceRegistryEventV2>>;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace -- Cloudflare Vitest defines bindings through this ambient namespace.
  namespace Cloudflare {
    interface Env {
      IDENTITY_STATE: DurableObjectNamespace<IdentityState>;
      TEST_QUEUE_CONTROL: QueueControl;
    }
  }
}

async function inspect<T>(
  stub: DurableObjectStub<IdentityState>,
  query: (state: DurableObjectState) => T,
): Promise<T> {
  return await runInDurableObject(stub, (_instance, state) => query(state));
}

async function createTimedActivation(
  fixture: IdentityFixture,
  device: DeviceFixture,
  authorizationTimes: { validFrom: number; activationDeadline: number; expiresAt: number },
  requestTimes?: { iat: number; exp: number },
): Promise<DeviceActivationRequestV2> {
  const authorizationPayload = deviceAuthorizationPayloadV2Schema.parse({
    ...device.authorization.payload,
    ...authorizationTimes,
    authorizationNonce: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
  });
  const authorization = {
    payload: authorizationPayload,
    rootSignature: base64Url64Schema.parse(
      await signProtocolPayload(authorizationPayload, fixture.privateKey),
    ),
  };
  const authorizationId = await deriveDeviceAuthorizationIdV2(authorizationPayload);
  const now = Math.floor(Date.now() / 1_000);
  const activationPayload = deviceActivationPayloadV2Schema.parse({
    ...device.activation.payload,
    authorizationId,
    requestId: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    iat: requestTimes?.iat ?? now,
    exp: requestTimes?.exp ?? now + 60,
  });
  return deviceActivationRequestV2Schema.parse({
    authorization,
    payload: activationPayload,
    deviceSignature: await signProtocolPayload(activationPayload, device.privateKey),
  });
}

async function createOwnershipProof(
  fixture: IdentityFixture,
  device: DeviceFixture,
  nonce: VerificationExpectationV2['nonce'],
): Promise<OwnershipProofV2> {
  const now = Math.floor(Date.now() / 1_000);
  const payload = ownershipProofPayloadV2Schema.parse({
    protocol: 'nexus.ownership-proof.v2',
    subject: fixture.prepared.subject,
    genesis: fixture.genesis,
    deviceId: device.authorization.payload.deviceId,
    authorizationId: await deriveDeviceAuthorizationIdV2(device.authorization.payload),
    authorization: device.authorization,
    aud: 'https://rp.example',
    act: 'authenticate',
    resource: 'session',
    nonce,
    iat: now,
    exp: now + 60,
  });
  return ownershipProofV2Schema.parse({
    payload,
    deviceSignature: await signProtocolPayload(payload, device.privateKey),
  });
}

function proofExpectation(nonce: VerificationExpectationV2['nonce']): VerificationExpectationV2 {
  return {
    audience: 'https://rp.example',
    action: 'authenticate',
    resource: 'session',
    nonce,
    now: Math.floor(Date.now() / 1_000),
    maxClockSkewSeconds: 60,
    contextHash: null,
  };
}

function challengeStore(expected: VerificationExpectationV2): ChallengeStore {
  let consumed = false;
  return {
    get(nonce) {
      return Promise.resolve(
        nonce === expected.nonce
          ? {
              nonce,
              action: expected.action,
              resource: expected.resource,
              expiresAt: expected.now + 120,
              consumed,
            }
          : null,
      );
    },
    consumeAtomically(nonce) {
      if (nonce !== expected.nonce || consumed) return Promise.resolve(false);
      consumed = true;
      return Promise.resolve(true);
    },
  };
}

function authoritativeProviders(
  stub: DurableObjectStub<IdentityState>,
  expectedSubject: NexusSubject,
): { lifecycle: LifecycleProvider; devices: DeviceLifecycleProvider } {
  return {
    lifecycle: {
      async getAuthoritativeStatus(subject) {
        if (subject !== expectedSubject) return { state: 'not-found' };
        const result = await stub.status();
        if (!result.ok) return { state: 'not-found' };
        return result.value.state === 'active'
          ? {
              state: 'active',
              sequence: result.value.sequence,
              registeredAt: result.value.registeredAt,
            }
          : {
              state: 'revoked',
              sequence: result.value.sequence,
              registeredAt: result.value.registeredAt,
              ...(result.value.revokedAt === null ? {} : { revokedAt: result.value.revokedAt }),
            };
      },
    },
    devices: {
      async getAuthoritativeDeviceStatus(subject, deviceId, authorizationId) {
        if (subject !== expectedSubject) return { state: 'not-found' };
        const result = await stub.deviceStatus({ deviceId, authorizationId });
        if (!result.ok || result.value.deviceState === 'unknown') return { state: 'not-found' };
        return {
          state: result.value.deviceState,
          identityState: result.value.identityState,
          identitySequence: result.value.identitySequence,
          deviceId: result.value.deviceId,
          authorizationId: result.value.authorizationId,
          deviceLedgerSequence: result.value.deviceLedgerSequence,
          ...(result.value.activatedAt === null ? {} : { activatedAt: result.value.activatedAt }),
          ...(result.value.revokedAt === null ? {} : { revokedAt: result.value.revokedAt }),
          ...(result.value.authorizationExpiresAt === null
            ? {}
            : { authorizationExpiresAt: result.value.authorizationExpiresAt }),
        };
      },
    },
  };
}

function freshNonce(): VerificationExpectationV2['nonce'] {
  return base64UrlAtLeast16Schema.parse(
    encodeBase64Url(crypto.getRandomValues(new Uint8Array(16))),
  );
}

describe('IdentityState SQLite Durable Object', () => {
  beforeEach(async () => {
    await env.TEST_QUEUE_CONTROL.reset(false);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('keeps an unknown status read-only, then creates schema on registration', async () => {
    const fixture = await createIdentityFixture();
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);

    await expect(stub.status()).resolves.toMatchObject({
      ok: false,
      error: { code: 'IDENTITY_NOT_FOUND' },
    });
    await expect(stub.revokeBySecret(createSecretRevocation(fixture))).resolves.toMatchObject({
      ok: false,
      error: { code: 'IDENTITY_NOT_FOUND' },
    });
    const before = await inspect(stub, (state) =>
      state.storage.sql
        .exec<{ name: string }>(
          `SELECT name
             FROM sqlite_master
            WHERE type = 'table'
              AND name IN ('schema_meta', 'identity_state', 'actions', 'outbox')
            ORDER BY name`,
        )
        .toArray()
        .map((row) => row.name),
    );
    expect(before).toEqual([]);

    const registered = await stub.register(fixture.prepared);
    expect(registered.ok).toBe(true);
    const after = await inspect(stub, (state) =>
      state.storage.sql
        .exec<{ name: string }>(
          `SELECT name
             FROM sqlite_master
            WHERE type = 'table'
              AND name IN ('schema_meta', 'identity_state', 'actions', 'outbox')
            ORDER BY name`,
        )
        .toArray()
        .map((row) => row.name),
    );
    expect(after).toEqual(['actions', 'identity_state', 'outbox', 'schema_meta']);
  });

  it('serializes 50 identical first registrations into one state/action/outbox event', async () => {
    const fixture = await createIdentityFixture();
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);

    const results = await Promise.all(
      Array.from({ length: 50 }, async () => await stub.register(fixture.prepared)),
    );
    expect(results.every((result) => result.ok)).toBe(true);
    const eventIds = results.flatMap((result) => (result.ok ? [result.value.eventId] : []));
    expect(new Set(eventIds).size).toBe(1);

    const counts = await inspect(stub, (state) => ({
      identities: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM identity_state')
        .one().count,
      actions: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM actions')
        .one().count,
      outbox: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM outbox')
        .one().count,
      sequence: state.storage.sql
        .exec<{ sequence: number }>('SELECT sequence FROM identity_state WHERE singleton = 1')
        .one().sequence,
    }));
    expect(counts).toEqual({ identities: 1, actions: 1, outbox: 1, sequence: 0 });
  });

  it('allows only one terminal event when signature and secret revocations race', async () => {
    const fixture = await createIdentityFixture();
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    const registered = await stub.register(fixture.prepared);
    expect(registered.ok).toBe(true);

    const signature = await createSignatureRevocation(fixture);
    const secret = createSecretRevocation(fixture);
    const results = await Promise.all(
      Array.from({ length: 50 }, async (_unused, index) =>
        index % 2 === 0
          ? await stub.revokeBySignature(signature)
          : await stub.revokeBySecret(secret),
      ),
    );

    expect(results.every((result) => result.ok)).toBe(true);
    const terminalIds = results.flatMap((result) => (result.ok ? [result.value.eventId] : []));
    expect(new Set(terminalIds).size).toBe(1);

    const state = await inspect(stub, (durableState) => ({
      lifecycle: durableState.storage.sql
        .exec<{ state: string; sequence: number; revoked_at: number | null }>(
          'SELECT state, sequence, revoked_at FROM identity_state WHERE singleton = 1',
        )
        .one(),
      actionCount: durableState.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM actions')
        .one().count,
      revokeCount: durableState.storage.sql
        .exec<{ count: number }>(
          "SELECT COUNT(*) AS count FROM actions WHERE action_type = 'revoke'",
        )
        .one().count,
    }));
    expect(state.lifecycle.state).toBe('revoked');
    expect(state.lifecycle.sequence).toBe(1);
    expect(state.lifecycle.revoked_at).toEqual(expect.any(Number));
    expect(state.actionCount).toBe(2);
    expect(state.revokeCount).toBe(1);

    const repeatedRegistration = await stub.register(fixture.prepared);
    expect(repeatedRegistration.ok).toBe(true);
    if (repeatedRegistration.ok) {
      expect(repeatedRegistration.value.state).toBe('revoked');
      expect(repeatedRegistration.value.sequence).toBe(1);
      expect(repeatedRegistration.value.eventId).toBe(terminalIds[0]);
    }
  });

  it('writes nothing for a stale sequence or wrong secret while active', async () => {
    const fixture = await createIdentityFixture();
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);

    const stale = revokeBySecretV1Schema.parse({
      ...createSecretRevocation(fixture),
      expectedSequence: 1,
    });
    const wrong = revokeBySecretV1Schema.parse({
      ...createSecretRevocation(fixture),
      revocationSecret: encodeBase64Url(new Uint8Array(32).fill(255)),
    });
    const staleResult = await stub.revokeBySecret(stale);
    const wrongResult = await stub.revokeBySecret(wrong);
    expect(staleResult).toMatchObject({
      ok: false,
      error: { code: 'SEQUENCE_CONFLICT' },
    });
    expect(wrongResult).toMatchObject({
      ok: false,
      error: { code: 'INVALID_REVOCATION_SECRET' },
    });

    const unchanged = await inspect(stub, (state) => ({
      lifecycle: state.storage.sql
        .exec<{ state: string; sequence: number }>(
          'SELECT state, sequence FROM identity_state WHERE singleton = 1',
        )
        .one(),
      actions: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM actions')
        .one().count,
      outbox: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM outbox')
        .one().count,
    }));
    expect(unchanged).toEqual({
      lifecycle: { state: 'active', sequence: 0 },
      actions: 1,
      outbox: 1,
    });
  });

  it('retains a failed Queue publication and completes it through the alarm retry', async () => {
    const fixture = await createIdentityFixture();
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await env.TEST_QUEUE_CONTROL.setFailure(true);
    const result = await stub.register(fixture.prepared);
    expect(result.ok).toBe(true);

    // Let the post-commit waitUntil publication attempt reject.
    await new Promise((resolve) => setTimeout(resolve, 20));
    const failed = await inspect(stub, (state) =>
      state.storage.sql
        .exec<{
          event_id: string;
          published_at: number | null;
          attempt_count: number;
        }>('SELECT event_id, published_at, attempt_count FROM outbox')
        .one(),
    );
    expect(failed.event_id).toBe(result.ok ? result.value.eventId : '');
    expect(failed.published_at).toBeNull();
    expect(failed.attempt_count).toBeGreaterThanOrEqual(1);

    await env.TEST_QUEUE_CONTROL.setFailure(false);
    await expect(runDurableObjectAlarm(stub)).resolves.toBe(true);

    const recovered = await inspect(stub, (state) =>
      state.storage.sql
        .exec<{ published_at: number | null; attempt_count: number }>(
          'SELECT published_at, attempt_count FROM outbox',
        )
        .one(),
    );
    expect(recovered.published_at).toEqual(expect.any(Number));
    expect(recovered.attempt_count).toBeGreaterThanOrEqual(2);

    const attempts = await env.TEST_QUEUE_CONTROL.getMessages();
    expect(attempts.length).toBeGreaterThanOrEqual(2);
    expect(new Set(attempts.map((event) => event.eventId))).toEqual(
      new Set([result.ok ? result.value.eventId : '']),
    );
  });

  it('preserves the exact v1 lifecycle/action/outbox columns under additive schema v2', async () => {
    const fixture = await createIdentityFixture();
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);

    const schema = await inspect(stub, (state) => {
      const columns = (table: string): string[] =>
        state.storage.sql
          .exec<{ name: string }>(`PRAGMA table_info(${table})`)
          .toArray()
          .map((row) => row.name);
      return {
        version: state.storage.sql
          .exec<{ version: number }>('SELECT version FROM schema_meta WHERE singleton = 1')
          .one().version,
        identity: columns('identity_state'),
        actions: columns('actions'),
        outbox: columns('outbox'),
      };
    });

    expect(schema.version).toBe(2);
    expect(schema.identity).toEqual([
      'singleton',
      'subject',
      'protocol',
      'suite',
      'genesis_jcs',
      'genesis_hash',
      'signing_public_key',
      'agreement_public_key',
      'revocation_commitment',
      'state',
      'sequence',
      'registered_at',
      'revoked_at',
      'revocation_event_id',
    ]);
    expect(schema.actions).toEqual([
      'sequence',
      'event_id',
      'action_type',
      'event_hash',
      'accepted_at',
    ]);
    expect(schema.outbox).toEqual([
      'event_id',
      'payload_jcs',
      'created_at',
      'published_at',
      'attempt_count',
    ]);
  });

  it('activates an exact root-authorized device once without changing v1 lifecycle state', async () => {
    const fixture = await createIdentityFixture();
    const device = await createDeviceFixture(fixture);
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);

    const results = await Promise.all(
      Array.from({ length: 50 }, async () => await stub.activateDevice(device.activation)),
    );
    expect(results.every((result) => result.ok)).toBe(true);
    const eventIds = results.flatMap((result) => (result.ok ? [result.value.eventId] : []));
    expect(new Set(eventIds).size).toBe(1);

    const authorizationId = await deriveDeviceAuthorizationIdV2(device.authorization.payload);
    await expect(
      stub.deviceStatus({ deviceId: device.authorization.payload.deviceId, authorizationId }),
    ).resolves.toMatchObject({
      ok: true,
      value: {
        identityState: 'active',
        identitySequence: 0,
        deviceLedgerSequence: 1,
        deviceState: 'active',
      },
    });
    const stored = await inspect(stub, (state) => ({
      identity: state.storage.sql
        .exec<{ state: string; sequence: number }>(
          'SELECT state, sequence FROM identity_state WHERE singleton = 1',
        )
        .one(),
      deviceCount: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM device_state')
        .one().count,
      operationCount: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM device_operations')
        .one().count,
      deviceOutboxCount: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM device_outbox')
        .one().count,
    }));
    expect(stored).toEqual({
      identity: { state: 'active', sequence: 0 },
      deviceCount: 1,
      operationCount: 1,
      deviceOutboxCount: 1,
    });
  });

  it('serializes root and self revocation races into one permanent device tombstone', async () => {
    const fixture = await createIdentityFixture();
    const device = await createDeviceFixture(fixture);
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);
    await stub.activateDevice(device.activation);
    const root = await createDeviceRootRevocation(fixture, device.authorization.payload.deviceId);
    const self = await createDeviceSelfRevocation(fixture, device);

    const results = await Promise.all(
      Array.from({ length: 50 }, async (_unused, index) =>
        index % 2 === 0 ? await stub.revokeDeviceRoot(root) : await stub.revokeDeviceSelf(self),
      ),
    );
    expect(results.every((result) => result.ok)).toBe(true);
    const eventIds = results.flatMap((result) => (result.ok ? [result.value.eventId] : []));
    expect(new Set(eventIds).size).toBe(1);

    const state = await inspect(stub, (durableState) => ({
      identitySequence: durableState.storage.sql
        .exec<{ sequence: number }>('SELECT sequence FROM identity_state WHERE singleton = 1')
        .one().sequence,
      deviceLedgerSequence: durableState.storage.sql
        .exec<{ sequence: number }>('SELECT sequence FROM device_ledger WHERE singleton = 1')
        .one().sequence,
      revocationOperations: durableState.storage.sql
        .exec<{ count: number }>(
          "SELECT COUNT(*) AS count FROM device_operations WHERE operation_type <> 'activate'",
        )
        .one().count,
    }));
    expect(state).toEqual({
      identitySequence: 0,
      deviceLedgerSequence: 2,
      revocationOperations: 1,
    });
  });

  it('lets the root tombstone an unactivated device and permanently rejects delayed activation', async () => {
    const fixture = await createIdentityFixture();
    const device = await createDeviceFixture(fixture);
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);
    const root = await createDeviceRootRevocation(fixture, device.authorization.payload.deviceId);
    const revoked = await stub.revokeDeviceRoot(root);
    expect(revoked).toMatchObject({
      ok: true,
      value: { authorizationId: null, deviceState: 'revoked', activatedAt: null },
    });
    await expect(stub.activateDevice(device.activation)).resolves.toMatchObject({
      ok: false,
      error: { code: 'DEVICE_REVOKED' },
    });

    const authorizationId = await deriveDeviceAuthorizationIdV2(device.authorization.payload);
    const status = await stub.deviceStatus({
      deviceId: device.authorization.payload.deviceId,
      authorizationId,
    });
    expect(status).toMatchObject({
      ok: true,
      value: { deviceState: 'revoked', activatedAt: null },
    });
    expect(status.ok && typeof status.value.revokedAt === 'number').toBe(true);
  });

  it('makes terminal v1 identity revocation dominate an activation race', async () => {
    const fixture = await createIdentityFixture();
    const device = await createDeviceFixture(fixture);
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);

    const [activation, terminal] = await Promise.all([
      stub.activateDevice(device.activation),
      stub.revokeBySecret(createSecretRevocation(fixture)),
    ]);
    expect(terminal.ok).toBe(true);
    expect(activation.ok || activation.error.code === 'IDENTITY_REVOKED').toBe(true);

    const authorizationId = await deriveDeviceAuthorizationIdV2(device.authorization.payload);
    await expect(
      stub.deviceStatus({ deviceId: device.authorization.payload.deviceId, authorizationId }),
    ).resolves.toMatchObject({
      ok: true,
      value: { identityState: 'revoked', identitySequence: 1 },
    });
    const final = await stub.deviceStatus({
      deviceId: device.authorization.payload.deviceId,
      authorizationId,
    });
    if (final.ok) {
      expect(final.value.deviceState).toBe('revoked');
    }
  });

  it('recovers an exact committed activation after its timing windows close', async () => {
    vi.useFakeTimers();
    const startedAt = new Date('2026-08-12T00:00:00.000Z');
    vi.setSystemTime(startedAt);
    const fixture = await createIdentityFixture();
    const device = await createDeviceFixture(fixture);
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);
    const first = await stub.activateDevice(device.activation);
    expect(first.ok).toBe(true);

    vi.setSystemTime(new Date(startedAt.getTime() + 2 * 60 * 60 * 1_000));
    const replay = await stub.activateDevice(device.activation);
    expect(replay.ok).toBe(true);
    if (first.ok && replay.ok) {
      expect(replay.value.eventId).toBe(first.value.eventId);
      expect(replay.value.operationId).toBe(first.value.operationId);
    }
  });

  it('rejects stale uncommitted self and root revocations without writing device state', async () => {
    const fixture = await createIdentityFixture();
    const device = await createDeviceFixture(fixture);
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);
    const staleIssuedAt = Math.floor(Date.now() / 1_000) - 301;
    const self = await createDeviceSelfRevocation(fixture, device, staleIssuedAt);
    const root = await createDeviceRootRevocation(
      fixture,
      device.authorization.payload.deviceId,
      staleIssuedAt,
    );

    await expect(stub.revokeDeviceSelf(self)).resolves.toMatchObject({
      ok: false,
      error: { code: 'BAD_REQUEST' },
    });
    await expect(stub.revokeDeviceRoot(root)).resolves.toMatchObject({
      ok: false,
      error: { code: 'BAD_REQUEST' },
    });
    const counts = await inspect(stub, (state) => ({
      devices: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM device_state')
        .one().count,
      operations: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM device_operations')
        .one().count,
    }));
    expect(counts).toEqual({ devices: 0, operations: 0 });
  });

  it('applies terminal identity and device tombstone dominance before exact operation replay', async () => {
    const fixture = await createIdentityFixture();
    const activeDevice = await createDeviceFixture(fixture);
    const unactivatedDevice = await createDeviceFixture(fixture);
    const missingDevice = await createDeviceFixture(fixture);
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);
    await stub.activateDevice(activeDevice.activation);

    const self = await createDeviceSelfRevocation(fixture, activeDevice);
    const selfResult = await stub.revokeDeviceSelf(self);
    expect(selfResult.ok).toBe(true);
    await expect(stub.activateDevice(activeDevice.activation)).resolves.toMatchObject({
      ok: false,
      error: { code: 'DEVICE_REVOKED' },
    });

    const root = await createDeviceRootRevocation(
      fixture,
      unactivatedDevice.authorization.payload.deviceId,
    );
    const rootResult = await stub.revokeDeviceRoot(root);
    expect(rootResult.ok).toBe(true);
    await stub.revokeBySecret(createSecretRevocation(fixture));

    await expect(stub.revokeDeviceSelf(self)).resolves.toMatchObject({
      ok: false,
      error: { code: 'IDENTITY_REVOKED' },
    });
    await expect(stub.revokeDeviceRoot(root)).resolves.toMatchObject({
      ok: false,
      error: { code: 'IDENTITY_REVOKED' },
    });
    const unactivatedAuthorizationId = await deriveDeviceAuthorizationIdV2(
      unactivatedDevice.authorization.payload,
    );
    await expect(
      stub.deviceStatus({
        deviceId: unactivatedDevice.authorization.payload.deviceId,
        authorizationId: unactivatedAuthorizationId,
      }),
    ).resolves.toMatchObject({
      ok: true,
      value: { identityState: 'revoked', deviceState: 'revoked' },
    });
    const missingAuthorizationId = await deriveDeviceAuthorizationIdV2(
      missingDevice.authorization.payload,
    );
    await expect(
      stub.deviceStatus({
        deviceId: missingDevice.authorization.payload.deviceId,
        authorizationId: missingAuthorizationId,
      }),
    ).resolves.toMatchObject({
      ok: true,
      value: { identityState: 'revoked', deviceState: 'revoked' },
    });
  });

  it('rejects invalid root authorization and activation proof-of-possession signatures', async () => {
    const fixture = await createIdentityFixture();
    const device = await createDeviceFixture(fixture);
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);
    const invalidSignature = base64Url64Schema.parse(encodeBase64Url(new Uint8Array(64)));

    const invalidRoot = deviceActivationRequestV2Schema.parse({
      ...device.activation,
      authorization: { ...device.authorization, rootSignature: invalidSignature },
    });
    await expect(stub.activateDevice(invalidRoot)).resolves.toMatchObject({
      ok: false,
      error: { code: 'INVALID_SIGNATURE' },
    });

    const invalidPossession = deviceActivationRequestV2Schema.parse({
      ...device.activation,
      deviceSignature: invalidSignature,
    });
    await expect(stub.activateDevice(invalidPossession)).resolves.toMatchObject({
      ok: false,
      error: { code: 'INVALID_SIGNATURE' },
    });
    const counts = await inspect(stub, (state) => ({
      devices: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM device_state')
        .one().count,
      operations: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM device_operations')
        .one().count,
    }));
    expect(counts).toEqual({ devices: 0, operations: 0 });
  });

  it('rejects the identity root signing key when presented as a device key', async () => {
    const fixture = await createIdentityFixture();
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);
    const now = Math.floor(Date.now() / 1_000);
    const signingKey = fixture.genesis.signingKey;
    const deviceId = await deriveDeviceIdV2({
      subject: fixture.prepared.subject,
      signingKey,
    });
    const authorizationPayload = deviceAuthorizationPayloadV2Schema.parse({
      protocol: 'nexus.device-authorization.v2',
      subject: fixture.prepared.subject,
      genesisHash: fixture.prepared.genesisHash,
      deviceId,
      signingKey,
      authorizationNonce: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
      validFrom: now - 1,
      activationDeadline: now + 300,
      expiresAt: now + 3600,
    });
    const authorization = {
      payload: authorizationPayload,
      rootSignature: base64Url64Schema.parse(
        await signProtocolPayload(authorizationPayload, fixture.privateKey),
      ),
    };
    const activationPayload = deviceActivationPayloadV2Schema.parse({
      protocol: 'nexus.device-activation.v2',
      subject: fixture.prepared.subject,
      deviceId,
      authorizationId: await deriveDeviceAuthorizationIdV2(authorizationPayload),
      requestId: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
      iat: now,
      exp: now + 60,
    });
    const request = deviceActivationRequestV2Schema.parse({
      authorization,
      payload: activationPayload,
      deviceSignature: await signProtocolPayload(activationPayload, fixture.privateKey),
    });

    await expect(stub.activateDevice(request)).resolves.toMatchObject({
      ok: false,
      error: { code: 'BAD_REQUEST' },
    });
    const counts = await inspect(stub, (state) => ({
      devices: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM device_state')
        .one().count,
      operations: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM device_operations')
        .one().count,
    }));
    expect(counts).toEqual({ devices: 0, operations: 0 });
  });

  it('keeps device and root signing roles cryptographically separate', async () => {
    const fixture = await createIdentityFixture();
    const target = await createDeviceFixture(fixture);
    const sibling = await createDeviceFixture(fixture);
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);
    await stub.activateDevice(target.activation);

    const self = await createDeviceSelfRevocation(fixture, target);
    const siblingRevoke = deviceSelfRevokeRequestV2Schema.parse({
      ...self,
      deviceSignature: await signProtocolPayload(self.payload, sibling.privateKey),
    });
    await expect(stub.revokeDeviceSelf(siblingRevoke)).resolves.toMatchObject({
      ok: false,
      error: { code: 'INVALID_SIGNATURE' },
    });

    const root = await createDeviceRootRevocation(fixture, target.authorization.payload.deviceId);
    const deviceAsRoot = deviceRootRevokeRequestV2Schema.parse({
      ...root,
      rootSignature: await signProtocolPayload(root.payload, target.privateKey),
    });
    await expect(stub.revokeDeviceRoot(deviceAsRoot)).resolves.toMatchObject({
      ok: false,
      error: { code: 'INVALID_SIGNATURE' },
    });
    const authorizationId = await deriveDeviceAuthorizationIdV2(target.authorization.payload);
    await expect(
      stub.deviceStatus({ deviceId: target.authorization.payload.deviceId, authorizationId }),
    ).resolves.toMatchObject({ ok: true, value: { deviceState: 'active' } });
  });

  it('rejects a conflicting root authorization for an already-active device key', async () => {
    const fixture = await createIdentityFixture();
    const device = await createDeviceFixture(fixture);
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);
    await stub.activateDevice(device.activation);
    const now = Math.floor(Date.now() / 1_000);
    const conflicting = await createTimedActivation(fixture, device, {
      validFrom: now - 1,
      activationDeadline: now + 300,
      expiresAt: now + 3600,
    });

    await expect(stub.activateDevice(conflicting)).resolves.toMatchObject({
      ok: false,
      error: { code: 'DEVICE_AUTHORIZATION_CONFLICT' },
    });
    const state = await inspect(stub, (durableState) => ({
      ledger: durableState.storage.sql
        .exec<{ sequence: number }>('SELECT sequence FROM device_ledger WHERE singleton = 1')
        .one().sequence,
      operations: durableState.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM device_operations')
        .one().count,
    }));
    expect(state).toEqual({ ledger: 1, operations: 1 });
  });

  it('enforces authorization and activation request time boundaries', async () => {
    const fixture = await createIdentityFixture();
    const device = await createDeviceFixture(fixture);
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);
    const now = Math.floor(Date.now() / 1_000);
    const validTimes = { validFrom: now - 1, activationDeadline: now + 300, expiresAt: now + 3600 };
    const cases: DeviceActivationRequestV2[] = [
      await createTimedActivation(fixture, device, {
        validFrom: now + 61,
        activationDeadline: now + 300,
        expiresAt: now + 3600,
      }),
      await createTimedActivation(fixture, device, {
        validFrom: now - 3600,
        activationDeadline: now - 2,
        expiresAt: now - 1,
      }),
      await createTimedActivation(fixture, device, validTimes, {
        iat: now + 61,
        exp: now + 120,
      }),
      await createTimedActivation(fixture, device, validTimes, {
        iat: now - 120,
        exp: now - 61,
      }),
      await createTimedActivation(fixture, device, validTimes, {
        iat: now,
        exp: now + 301,
      }),
    ];
    const overlongAuthorization: DeviceActivationRequestV2 = {
      ...device.activation,
      authorization: {
        ...device.activation.authorization,
        payload: {
          ...device.activation.authorization.payload,
          validFrom: now,
          activationDeadline: now + 300,
          expiresAt: now + 366 * 24 * 60 * 60 + 1,
        },
      },
    };
    cases.push(overlongAuthorization);

    for (const request of cases) {
      await expect(stub.activateDevice(request)).resolves.toMatchObject({
        ok: false,
        error: { code: 'BAD_REQUEST' },
      });
    }
    const counts = await inspect(stub, (state) => ({
      devices: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM device_state')
        .one().count,
      operations: state.storage.sql
        .exec<{ count: number }>('SELECT COUNT(*) AS count FROM device_operations')
        .one().count,
    }));
    expect(counts).toEqual({ devices: 0, operations: 0 });
  });

  it('retries the independent device outbox with stable at-least-once event identity', async () => {
    const fixture = await createIdentityFixture();
    const device = await createDeviceFixture(fixture);
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);
    await new Promise((resolve) => setTimeout(resolve, 20));
    await env.TEST_QUEUE_CONTROL.reset(true);

    const activation = await stub.activateDevice(device.activation);
    expect(activation.ok).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 20));
    const failed = await inspect(stub, (state) =>
      state.storage.sql
        .exec<{ event_id: string; published_at: number | null; attempt_count: number }>(
          'SELECT event_id, published_at, attempt_count FROM device_outbox',
        )
        .one(),
    );
    expect(failed.event_id).toBe(activation.ok ? activation.value.eventId : '');
    expect(failed.published_at).toBeNull();
    expect(failed.attempt_count).toBeGreaterThanOrEqual(1);

    await env.TEST_QUEUE_CONTROL.setFailure(false);
    await expect(runDurableObjectAlarm(stub)).resolves.toBe(true);
    const recovered = await inspect(stub, (state) =>
      state.storage.sql
        .exec<{ published_at: number | null; attempt_count: number }>(
          'SELECT published_at, attempt_count FROM device_outbox',
        )
        .one(),
    );
    expect(recovered.published_at).toEqual(expect.any(Number));
    expect(recovered.attempt_count).toBeGreaterThanOrEqual(2);
    const attempts = (await env.TEST_QUEUE_CONTROL.getMessages()).filter(
      (event): event is DeviceRegistryEventV2 =>
        event.protocol === 'nexus.device-registry-event.v2',
    );
    expect(attempts.length).toBeGreaterThanOrEqual(2);
    expect(new Set(attempts.map((event) => event.eventId))).toEqual(
      new Set([activation.ok ? activation.value.eventId : '']),
    );
  });

  it('resolves activation racing root revocation to a permanent tombstone', async () => {
    const fixture = await createIdentityFixture();
    const device = await createDeviceFixture(fixture);
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);
    const root = await createDeviceRootRevocation(fixture, device.authorization.payload.deviceId);
    await Promise.all([stub.activateDevice(device.activation), stub.revokeDeviceRoot(root)]);
    const authorizationId = await deriveDeviceAuthorizationIdV2(device.authorization.payload);
    await expect(
      stub.deviceStatus({ deviceId: device.authorization.payload.deviceId, authorizationId }),
    ).resolves.toMatchObject({ ok: true, value: { deviceState: 'revoked' } });
    await expect(stub.activateDevice(device.activation)).resolves.toMatchObject({
      ok: false,
      error: { code: 'DEVICE_REVOKED' },
    });
  });

  it('returns stable exact replays for self and root device revocations', async () => {
    const selfIdentity = await createIdentityFixture();
    const selfDevice = await createDeviceFixture(selfIdentity);
    const selfStub = env.IDENTITY_STATE.getByName(selfIdentity.prepared.subject);
    await selfStub.register(selfIdentity.prepared);
    await selfStub.activateDevice(selfDevice.activation);
    const self = await createDeviceSelfRevocation(selfIdentity, selfDevice);
    const selfFirst = await selfStub.revokeDeviceSelf(self);
    const selfReplay = await selfStub.revokeDeviceSelf(self);
    expect(selfFirst.ok && selfReplay.ok).toBe(true);
    if (selfFirst.ok && selfReplay.ok) {
      expect(selfReplay.value.eventId).toBe(selfFirst.value.eventId);
      expect(selfReplay.value.operationId).toBe(selfFirst.value.operationId);
    }

    const rootIdentity = await createIdentityFixture();
    const rootDevice = await createDeviceFixture(rootIdentity);
    const rootStub = env.IDENTITY_STATE.getByName(rootIdentity.prepared.subject);
    await rootStub.register(rootIdentity.prepared);
    const root = await createDeviceRootRevocation(
      rootIdentity,
      rootDevice.authorization.payload.deviceId,
    );
    const rootFirst = await rootStub.revokeDeviceRoot(root);
    const rootReplay = await rootStub.revokeDeviceRoot(root);
    expect(rootFirst.ok && rootReplay.ok).toBe(true);
    if (rootFirst.ok && rootReplay.ok) {
      expect(rootReplay.value.eventId).toBe(rootFirst.value.eventId);
      expect(rootReplay.value.operationId).toBe(rootFirst.value.operationId);
    }
  });

  it('returns unknown for a wrong authorization query while the device remains active', async () => {
    const fixture = await createIdentityFixture();
    const device = await createDeviceFixture(fixture);
    const other = await createDeviceFixture(fixture);
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);
    await stub.activateDevice(device.activation);
    const wrongAuthorizationId = await deriveDeviceAuthorizationIdV2(other.authorization.payload);
    await expect(
      stub.deviceStatus({
        deviceId: device.authorization.payload.deviceId,
        authorizationId: wrongAuthorizationId,
      }),
    ).resolves.toMatchObject({
      ok: true,
      value: { identityState: 'active', deviceState: 'unknown' },
    });
  });

  it('makes identity revocation dominate races with both device revocation modes', async () => {
    for (const mode of ['self', 'root'] as const) {
      const fixture = await createIdentityFixture();
      const device = await createDeviceFixture(fixture);
      const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
      await stub.register(fixture.prepared);
      await stub.activateDevice(device.activation);
      if (mode === 'self') {
        const deviceRevocation = await createDeviceSelfRevocation(fixture, device);
        await Promise.all([
          stub.revokeBySecret(createSecretRevocation(fixture)),
          stub.revokeDeviceSelf(deviceRevocation),
        ]);
      } else {
        const deviceRevocation = await createDeviceRootRevocation(
          fixture,
          device.authorization.payload.deviceId,
        );
        await Promise.all([
          stub.revokeBySecret(createSecretRevocation(fixture)),
          stub.revokeDeviceRoot(deviceRevocation),
        ]);
      }
      const authorizationId = await deriveDeviceAuthorizationIdV2(device.authorization.payload);
      await expect(
        stub.deviceStatus({ deviceId: device.authorization.payload.deviceId, authorizationId }),
      ).resolves.toMatchObject({
        ok: true,
        value: { identityState: 'revoked', deviceState: 'revoked' },
      });
    }
  });

  it('enforces sibling isolation and clone-wide revocation through the real authoritative registry', async () => {
    const fixture = await createIdentityFixture();
    const deviceA = await createDeviceFixture(fixture);
    const deviceB = await createDeviceFixture(fixture);
    const stub = env.IDENTITY_STATE.getByName(fixture.prepared.subject);
    await stub.register(fixture.prepared);

    const installA1 = await stub.activateDevice(deviceA.activation);
    const installA2 = await stub.activateDevice(deviceA.activation);
    const activationB = await stub.activateDevice(deviceB.activation);
    expect(installA1.ok && installA2.ok && activationB.ok).toBe(true);
    if (installA1.ok && installA2.ok) {
      expect(installA2.value.eventId).toBe(installA1.value.eventId);
      expect(installA2.value.operationId).toBe(installA1.value.operationId);
    }

    const authorizationA = await deriveDeviceAuthorizationIdV2(deviceA.authorization.payload);
    const authorizationB = await deriveDeviceAuthorizationIdV2(deviceB.authorization.payload);
    await expect(
      stub.deviceStatus({
        deviceId: deviceA.authorization.payload.deviceId,
        authorizationId: authorizationA,
      }),
    ).resolves.toMatchObject({ ok: true, value: { deviceState: 'active' } });
    await expect(
      stub.deviceStatus({
        deviceId: deviceB.authorization.payload.deviceId,
        authorizationId: authorizationB,
      }),
    ).resolves.toMatchObject({ ok: true, value: { deviceState: 'active' } });

    const providers = authoritativeProviders(stub, fixture.prepared.subject);
    for (const logicalInstall of ['A1', 'A2'] as const) {
      const nonce = freshNonce();
      const expected = proofExpectation(nonce);
      const proof = await createOwnershipProof(fixture, deviceA, nonce);
      await expect(
        verifyRpOperationV2(
          proof,
          expected,
          challengeStore(expected),
          providers.lifecycle,
          providers.devices,
        ),
        logicalInstall,
      ).resolves.toMatchObject({
        subject: fixture.prepared.subject,
        deviceId: deviceA.authorization.payload.deviceId,
      });
    }

    const revokeA = await createDeviceRootRevocation(
      fixture,
      deviceA.authorization.payload.deviceId,
    );
    await expect(stub.revokeDeviceRoot(revokeA)).resolves.toMatchObject({
      ok: true,
      value: { deviceState: 'revoked' },
    });
    await expect(
      stub.deviceStatus({
        deviceId: deviceA.authorization.payload.deviceId,
        authorizationId: authorizationA,
      }),
    ).resolves.toMatchObject({ ok: true, value: { deviceState: 'revoked' } });
    await expect(
      stub.deviceStatus({
        deviceId: deviceB.authorization.payload.deviceId,
        authorizationId: authorizationB,
      }),
    ).resolves.toMatchObject({ ok: true, value: { deviceState: 'active' } });

    for (const logicalInstall of ['A1', 'A2'] as const) {
      const nonce = freshNonce();
      const expected = proofExpectation(nonce);
      const proof = await createOwnershipProof(fixture, deviceA, nonce);
      await expect(
        verifyRpOperationV2(
          proof,
          expected,
          challengeStore(expected),
          providers.lifecycle,
          providers.devices,
        ),
        logicalInstall,
      ).rejects.toMatchObject({
        code: 'IDENTITY_REVOKED',
        codeV2: 'DEVICE_REVOKED',
      });
    }

    const nonceB = freshNonce();
    const expectedB = proofExpectation(nonceB);
    const proofB = await createOwnershipProof(fixture, deviceB, nonceB);
    await expect(
      verifyRpOperationV2(
        proofB,
        expectedB,
        challengeStore(expectedB),
        providers.lifecycle,
        providers.devices,
      ),
    ).resolves.toMatchObject({
      subject: fixture.prepared.subject,
      deviceId: deviceB.authorization.payload.deviceId,
    });
  });
});
