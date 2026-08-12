import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { deriveDeviceRegistryEventIdV2, deriveRegistryEventId } from '@nexus/crypto';
import {
  deviceRegistryEventV2Schema,
  deviceRegistryEventWithoutEventIdV2Schema,
  registryEventV1Schema,
  registryEventWithoutEventIdV1Schema,
  type DeviceRegistryEventV2,
  type RegistryEventV1,
} from '@nexus/protocol';

import worker, { type Env, type TransparencyService, validateRegistryEvent } from '../src/index';

const GENESIS_HASH = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const REGISTER_ACTION_HASH = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE';
const REVOKE_ACTION_HASH = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI';
const DEVICE_ID = `nxd2_${GENESIS_HASH}` as const;
const SECOND_DEVICE_ID = `nxd2_${REGISTER_ACTION_HASH}` as const;
const AUTHORIZATION_ID = `nxa2_${GENESIS_HASH}` as const;
const DEVICE_OPERATION_ID = `nxo2_${GENESIS_HASH}` as const;
const SECOND_DEVICE_OPERATION_ID = `nxo2_${REGISTER_ACTION_HASH}` as const;

interface IdentityRow {
  state: 'active' | 'revoked';
  sequence: number;
  registered_at: number;
  revoked_at: number | null;
  updated_at: number;
}

interface DeviceRow {
  authorization_id: string | null;
  state: 'active' | 'revoked';
  event_sequence: number;
  authorization_expires_at: number | null;
  activated_at: number | null;
  revoked_at: number | null;
  revoked_by: 'root' | 'device' | null;
  updated_at: number;
}

async function event(
  eventType: RegistryEventV1['eventType'],
  acceptedAt: number,
): Promise<RegistryEventV1> {
  const eventWithoutId = registryEventWithoutEventIdV1Schema.parse({
    protocol: 'nexus.registry-event.v1',
    eventType,
    subject: `nx1_${GENESIS_HASH}`,
    genesisHash: GENESIS_HASH,
    sequence: eventType === 'registered' ? 0 : 1,
    state: eventType === 'registered' ? 'active' : 'revoked',
    acceptedAt,
    actionHash: eventType === 'registered' ? REGISTER_ACTION_HASH : REVOKE_ACTION_HASH,
  });
  const { eventId } = await deriveRegistryEventId(eventWithoutId);
  return registryEventV1Schema.parse({ ...eventWithoutId, eventId });
}

async function deviceEvent(
  eventType: DeviceRegistryEventV2['eventType'],
  deviceLedgerSequence: number,
  acceptedAt: number,
  overrides: Partial<Omit<DeviceRegistryEventV2, 'eventId'>> = {},
): Promise<DeviceRegistryEventV2> {
  const eventWithoutId = deviceRegistryEventWithoutEventIdV2Schema.parse({
    protocol: 'nexus.device-registry-event.v2',
    operationId: DEVICE_OPERATION_ID,
    eventType,
    subject: `nx1_${GENESIS_HASH}`,
    genesisHash: GENESIS_HASH,
    identitySequence: 0,
    identityState: 'active',
    deviceLedgerSequence,
    deviceId: DEVICE_ID,
    ...(eventType === 'activated'
      ? {
          authorizationId: AUTHORIZATION_ID,
          deviceState: 'active',
          authorizationExpiresAt: acceptedAt + 86_400,
        }
      : {
          deviceState: 'revoked',
          revokedBy: 'root',
        }),
    acceptedAt,
    actionHash: eventType === 'activated' ? REGISTER_ACTION_HASH : REVOKE_ACTION_HASH,
    ...overrides,
  });
  const { eventId } = await deriveDeviceRegistryEventIdV2(eventWithoutId);
  return deviceRegistryEventV2Schema.parse({ ...eventWithoutId, eventId });
}

function queueMessage(body: unknown, attempts = 1) {
  const ack = vi.fn();
  const retry = vi.fn();
  return {
    ack,
    retry,
    message: {
      body,
      attempts,
      ack,
      retry,
    } as unknown as Message<unknown>,
  };
}

function batch(...messages: Message<unknown>[]): MessageBatch<unknown> {
  return {
    queue: 'nexus-registry-events',
    messages,
    ackAll: vi.fn(),
    retryAll: vi.fn(),
  };
}

function deviceBatch(...messages: Message<unknown>[]): MessageBatch<unknown> {
  return {
    queue: 'nexus-registry-device-events',
    messages,
    ackAll: vi.fn(),
    retryAll: vi.fn(),
  };
}

function workerEnv(transparency: Partial<TransparencyService>): Env {
  return {
    INDEX_DB: env.INDEX_DB,
    TRANSPARENCY_SERVICE: {
      append: async () => undefined,
      appendDevice: async () => undefined,
      ...transparency,
    },
  };
}

async function count(table: string): Promise<number> {
  const row = await env.INDEX_DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<{
    count: number;
  }>();
  return row?.count ?? 0;
}

beforeEach(async () => {
  await env.INDEX_DB.batch([
    env.INDEX_DB.prepare('DELETE FROM device_projection_heads'),
    env.INDEX_DB.prepare('DELETE FROM device_states'),
    env.INDEX_DB.prepare('DELETE FROM device_registry_events'),
    env.INDEX_DB.prepare('DELETE FROM registry_events'),
    env.INDEX_DB.prepare('DELETE FROM pending_registry_events'),
    env.INDEX_DB.prepare('DELETE FROM identities'),
  ]);
});

describe('projector queue consumer', () => {
  it('accepts an event materialized through the producer contract unchanged', async () => {
    const produced = await event('registered', 1_788_799_990);

    await expect(validateRegistryEvent(produced)).resolves.toEqual(produced);
  });

  it('acks duplicates while storing one logical event', async () => {
    const registered = await event('registered', 1_788_800_000);
    const first = queueMessage(registered);
    const duplicate = queueMessage(registered);
    const append = vi.fn(async () => undefined);

    await worker.queue(batch(first.message, duplicate.message), workerEnv({ append }));

    expect(first.ack).toHaveBeenCalledOnce();
    expect(duplicate.ack).toHaveBeenCalledOnce();
    expect(first.retry).not.toHaveBeenCalled();
    expect(duplicate.retry).not.toHaveBeenCalled();
    expect(await count('identities')).toBe(1);
    expect(await count('registry_events')).toBe(1);
    // A duplicate may be the retry that recovers a prior transparency failure.
    expect(append).toHaveBeenCalledTimes(2);
  });

  it('holds an early revocation and drains it after registration', async () => {
    const revoked = await event('revoked', 1_788_800_020);
    const registered = await event('registered', 1_788_800_000);
    const append = vi.fn(async () => undefined);
    const earlyRevocation = queueMessage(revoked);

    await worker.queue(batch(earlyRevocation.message), workerEnv({ append }));

    expect(earlyRevocation.ack).toHaveBeenCalledOnce();
    expect(await count('identities')).toBe(0);
    expect(await count('registry_events')).toBe(0);
    expect(await count('pending_registry_events')).toBe(1);

    const laterRegistration = queueMessage(registered);
    await worker.queue(batch(laterRegistration.message), workerEnv({ append }));

    const identity = await env.INDEX_DB.prepare(
      `SELECT state, sequence, registered_at, revoked_at, updated_at
       FROM identities WHERE subject = ?`,
    )
      .bind(registered.subject)
      .first<IdentityRow>();

    expect(laterRegistration.ack).toHaveBeenCalledOnce();
    expect(identity).toEqual({
      state: 'revoked',
      sequence: 1,
      registered_at: registered.acceptedAt,
      revoked_at: revoked.acceptedAt,
      updated_at: revoked.acceptedAt,
    });
    expect(await count('registry_events')).toBe(2);
    expect(await count('pending_registry_events')).toBe(0);
  });

  it('does not roll a projection back for a stale sequence', async () => {
    const revoked = await event('revoked', 1_788_800_030);
    await env.INDEX_DB.prepare(
      `INSERT INTO identities (
         subject, genesis_hash, protocol, suite, state, sequence,
         registered_at, revoked_at, updated_at
       ) VALUES (?, ?, 'nexus.identity.v1', 'NX-25519-SHA256-JCS-v1',
                 'revoked', 2, 100, 200, 200)`,
    )
      .bind(revoked.subject, revoked.genesisHash)
      .run();
    const message = queueMessage(revoked);

    await worker.queue(batch(message.message), workerEnv({ append: vi.fn(async () => undefined) }));

    const identity = await env.INDEX_DB.prepare(
      `SELECT state, sequence, registered_at, revoked_at, updated_at
       FROM identities WHERE subject = ?`,
    )
      .bind(revoked.subject)
      .first<IdentityRow>();
    expect(message.ack).toHaveBeenCalledOnce();
    expect(identity).toEqual({
      state: 'revoked',
      sequence: 2,
      registered_at: 100,
      revoked_at: 200,
      updated_at: 200,
    });
  });

  it('retries transparency failure without duplicating D1 state', async () => {
    const registered = await event('registered', 1_788_800_040);
    const append = vi
      .fn<TransparencyService['append']>()
      .mockRejectedValueOnce(new Error('simulated transient failure'))
      .mockResolvedValueOnce(undefined);
    const firstAttempt = queueMessage(registered, 1);

    await worker.queue(batch(firstAttempt.message), workerEnv({ append }));

    expect(firstAttempt.retry).toHaveBeenCalledOnce();
    expect(firstAttempt.ack).not.toHaveBeenCalled();
    expect(await count('registry_events')).toBe(1);

    const secondAttempt = queueMessage(registered, 2);
    await worker.queue(batch(secondAttempt.message), workerEnv({ append }));

    expect(secondAttempt.ack).toHaveBeenCalledOnce();
    expect(secondAttempt.retry).not.toHaveBeenCalled();
    expect(await count('identities')).toBe(1);
    expect(await count('registry_events')).toBe(1);
    expect(append).toHaveBeenCalledTimes(2);
  });

  it('retries a message whose event id does not recompute', async () => {
    const registered = await event('registered', 1_788_800_050);
    const invalid = { ...registered, acceptedAt: registered.acceptedAt + 1 };
    const message = queueMessage(invalid);
    const append = vi.fn(async () => undefined);

    await worker.queue(batch(message.message), workerEnv({ append }));

    expect(message.retry).toHaveBeenCalledOnce();
    expect(message.ack).not.toHaveBeenCalled();
    expect(append).not.toHaveBeenCalled();
    expect(await count('identities')).toBe(0);
    expect(await count('registry_events')).toBe(0);
  });

  it('projects an activated device without changing v1 identity sequence', async () => {
    const registered = await event('registered', 1_788_801_000);
    await worker.queue(
      batch(queueMessage(registered).message),
      workerEnv({ append: vi.fn(async () => undefined) }),
    );
    const activated = await deviceEvent('activated', 1, 1_788_801_010);
    const message = queueMessage(activated);
    const appendDevice = vi.fn(async () => undefined);

    await worker.queue(deviceBatch(message.message), workerEnv({ appendDevice }));

    const device = await env.INDEX_DB.prepare(
      `SELECT authorization_id, state, event_sequence, authorization_expires_at,
              activated_at, revoked_at, revoked_by, updated_at
       FROM device_states WHERE subject = ? AND device_id = ?`,
    )
      .bind(activated.subject, activated.deviceId)
      .first<DeviceRow>();
    const identity = await env.INDEX_DB.prepare(
      'SELECT state, sequence, registered_at, revoked_at, updated_at FROM identities WHERE subject = ?',
    )
      .bind(activated.subject)
      .first<IdentityRow>();

    expect(message.ack).toHaveBeenCalledOnce();
    expect(message.retry).not.toHaveBeenCalled();
    expect(appendDevice).toHaveBeenCalledWith(activated);
    expect(device).toEqual({
      authorization_id: AUTHORIZATION_ID,
      state: 'active',
      event_sequence: 1,
      authorization_expires_at: activated.authorizationExpiresAt,
      activated_at: activated.acceptedAt,
      revoked_at: null,
      revoked_by: null,
      updated_at: activated.acceptedAt,
    });
    expect(identity?.state).toBe('active');
    expect(identity?.sequence).toBe(0);
  });

  it('deduplicates v2 Queue delivery by event ID and ledger sequence', async () => {
    const registered = await event('registered', 1_788_801_100);
    await worker.queue(batch(queueMessage(registered).message), workerEnv({}));
    const activated = await deviceEvent('activated', 1, 1_788_801_110);
    const first = queueMessage(activated);
    const duplicate = queueMessage(activated);
    const appendDevice = vi.fn(async () => undefined);

    await worker.queue(deviceBatch(first.message, duplicate.message), workerEnv({ appendDevice }));

    expect(first.ack).toHaveBeenCalledOnce();
    expect(duplicate.ack).toHaveBeenCalledOnce();
    expect(await count('device_registry_events')).toBe(1);
    expect(await count('device_states')).toBe(1);
    // A duplicate delivery may recover a prior transparency failure.
    expect(appendDevice).toHaveBeenCalledTimes(2);
  });

  it('stores an early device event and reconciles it after v1 registration', async () => {
    const activated = await deviceEvent('activated', 1, 1_788_801_210);
    const early = queueMessage(activated);

    await worker.queue(deviceBatch(early.message), workerEnv({}));

    expect(early.ack).toHaveBeenCalledOnce();
    expect(await count('device_registry_events')).toBe(1);
    expect(await count('device_states')).toBe(0);

    const registered = await event('registered', 1_788_801_200);
    await worker.queue(batch(queueMessage(registered).message), workerEnv({}));

    expect(await count('device_states')).toBe(1);
    const device = await env.INDEX_DB.prepare(
      `SELECT authorization_id, state, event_sequence, authorization_expires_at,
              activated_at, revoked_at, revoked_by, updated_at
       FROM device_states WHERE subject = ? AND device_id = ?`,
    )
      .bind(activated.subject, activated.deviceId)
      .first<DeviceRow>();
    expect(device?.state).toBe('active');
    expect(device?.event_sequence).toBe(1);
  });

  it('keeps root-created revoked tombstones terminal under stale activation', async () => {
    const registered = await event('registered', 1_788_801_300);
    await worker.queue(batch(queueMessage(registered).message), workerEnv({}));
    const revoked = await deviceEvent('revoked', 2, 1_788_801_320);
    const activated = await deviceEvent('activated', 1, 1_788_801_310, {
      operationId: SECOND_DEVICE_OPERATION_ID,
    });

    await worker.queue(deviceBatch(queueMessage(revoked).message), workerEnv({}));
    await worker.queue(deviceBatch(queueMessage(activated).message), workerEnv({}));

    const device = await env.INDEX_DB.prepare(
      `SELECT authorization_id, state, event_sequence, authorization_expires_at,
              activated_at, revoked_at, revoked_by, updated_at
       FROM device_states WHERE subject = ? AND device_id = ?`,
    )
      .bind(revoked.subject, revoked.deviceId)
      .first<DeviceRow>();
    expect(device).toEqual({
      authorization_id: null,
      state: 'revoked',
      event_sequence: 2,
      authorization_expires_at: null,
      activated_at: null,
      revoked_at: revoked.acceptedAt,
      revoked_by: 'root',
      updated_at: revoked.acceptedAt,
    });
    expect(await count('device_registry_events')).toBe(2);
  });

  it('does not persist private keys, device labels, RP scopes, or installation IDs', async () => {
    const registered = await event('registered', 1_788_801_400);
    await worker.queue(batch(queueMessage(registered).message), workerEnv({}));
    const activated = await deviceEvent('activated', 1, 1_788_801_410);
    const invalid = {
      ...activated,
      devicePrivateKey: 'must-not-be-stored',
      label: 'Alice laptop',
      rpScopes: ['https://rp.example'],
      installationId: 'browser-profile-1',
    };
    const message = queueMessage(invalid);
    const appendDevice = vi.fn(async () => undefined);

    await worker.queue(deviceBatch(message.message), workerEnv({ appendDevice }));

    expect(message.retry).toHaveBeenCalledOnce();
    expect(message.ack).not.toHaveBeenCalled();
    expect(appendDevice).not.toHaveBeenCalled();
    expect(await count('device_registry_events')).toBe(0);
    expect(await count('device_states')).toBe(0);
  });

  it('projects independent device keys for one stable v1 subject', async () => {
    const registered = await event('registered', 1_788_801_500);
    await worker.queue(batch(queueMessage(registered).message), workerEnv({}));
    const first = await deviceEvent('activated', 1, 1_788_801_510);
    const second = await deviceEvent('activated', 2, 1_788_801_520, {
      operationId: SECOND_DEVICE_OPERATION_ID,
      deviceId: SECOND_DEVICE_ID,
    });

    await worker.queue(
      deviceBatch(queueMessage(first).message, queueMessage(second).message),
      workerEnv({}),
    );

    expect(await count('device_states')).toBe(2);
    const head = await env.INDEX_DB.prepare(
      `SELECT max_device_ledger_sequence FROM device_projection_heads WHERE subject = ?`,
    )
      .bind(first.subject)
      .first<{ max_device_ledger_sequence: number }>();
    expect(head?.max_device_ledger_sequence).toBe(2);
  });
});
