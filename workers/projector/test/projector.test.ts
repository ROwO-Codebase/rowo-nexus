import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { deriveRegistryEventId } from '@nexus/crypto';
import {
  registryEventV1Schema,
  registryEventWithoutEventIdV1Schema,
  type RegistryEventV1,
} from '@nexus/protocol';

import worker, { type Env, type TransparencyService, validateRegistryEvent } from '../src/index';

const GENESIS_HASH = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const REGISTER_ACTION_HASH = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE';
const REVOKE_ACTION_HASH = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI';

interface IdentityRow {
  state: 'active' | 'revoked';
  sequence: number;
  registered_at: number;
  revoked_at: number | null;
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

function workerEnv(transparency: TransparencyService): Env {
  return {
    INDEX_DB: env.INDEX_DB,
    TRANSPARENCY_SERVICE: transparency,
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
});
