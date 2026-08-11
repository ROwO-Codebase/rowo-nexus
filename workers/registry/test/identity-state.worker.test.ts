import { env } from 'cloudflare:workers';
import { runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';

import type { IdentityState } from '../src/identity-state-do';
import { encodeBase64Url, revokeBySecretV1Schema } from '@nexus/protocol';
import type { RegistryEventV1 } from '@nexus/protocol';
import {
  createIdentityFixture,
  createSecretRevocation,
  createSignatureRevocation,
} from './fixtures';

interface QueueControl {
  setFailure(value: boolean): Promise<void>;
  reset(value?: boolean): Promise<void>;
  getMessages(): Promise<RegistryEventV1[]>;
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

describe('IdentityState SQLite Durable Object', () => {
  beforeEach(async () => {
    await env.TEST_QUEUE_CONTROL.reset(false);
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

  it('creates the exact spec lifecycle/action/outbox columns under schema_meta v1', async () => {
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

    expect(schema.version).toBe(1);
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
});
