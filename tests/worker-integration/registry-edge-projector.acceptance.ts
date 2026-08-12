import { env } from 'cloudflare:workers';
import { createExecutionContext } from 'cloudflare:test';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  decodeBase64UrlExact,
  encodeBase64Url,
  registryStatusV1Schema,
  transparencyInclusionProofV1Schema,
  type NexusSubject,
  type OwnershipProofV1,
  type VerificationExpectation,
} from '@nexus/protocol';
import {
  verifyOwnershipProof,
  verifyRpOperation,
  verifyTransparencyInclusionProof,
  type ChallengeRecord,
  type ChallengeStore,
} from '@nexus/verifier';

import projector from '../../workers/projector/src/index';
import {
  ACTION,
  RESOURCE,
  RP_ORIGIN,
  WALLET_ORIGIN,
  authoritativeStatusThroughEdge,
  createAcceptanceEdge,
  createAcceptanceDevice,
  createAcceptanceIdentity,
  nexusPost,
  ownershipProof,
  queuedEvents,
  queuedDeviceEvents,
  resetAcceptanceState,
  rootRevokeAcceptanceDevice,
  secretRevocation,
} from './helpers';
import { createAcceptanceTransparency } from './transparency-harness';

const NOW = Math.floor(Date.now() / 1_000);

class OneTimeChallenge implements ChallengeStore {
  readonly #record: ChallengeRecord;

  constructor(nonce: string) {
    this.#record = {
      nonce,
      action: ACTION,
      resource: RESOURCE,
      expiresAt: NOW + 60,
      consumed: false,
    };
  }

  get(nonce: string): Promise<ChallengeRecord | null> {
    return Promise.resolve(nonce === this.#record.nonce ? structuredClone(this.#record) : null);
  }

  consumeAtomically(nonce: string): Promise<boolean> {
    if (nonce !== this.#record.nonce || this.#record.consumed) return Promise.resolve(false);
    this.#record.consumed = true;
    return Promise.resolve(true);
  }
}

function expectation(nonce: OwnershipProofV1['payload']['nonce']): VerificationExpectation {
  return {
    audience: RP_ORIGIN,
    action: ACTION,
    resource: RESOURCE,
    nonce,
    now: NOW,
    maxClockSkewSeconds: 5,
  };
}

function queueMessage(body: unknown) {
  const ack = vi.fn();
  const retry = vi.fn();
  return {
    ack,
    retry,
    value: { body, attempts: 1, ack, retry } as unknown as Message<unknown>,
  };
}

function batch(...messages: Message<unknown>[]): MessageBatch<unknown> {
  return {
    queue: 'nexus-registry-events',
    messages,
    ackAll: vi.fn(),
    retryAll: vi.fn(),
  } as unknown as MessageBatch<unknown>;
}

function deviceBatch(...messages: Message<unknown>[]): MessageBatch<unknown> {
  return {
    queue: 'nexus-registry-device-events',
    messages,
    ackAll: vi.fn(),
    retryAll: vi.fn(),
  } as unknown as MessageBatch<unknown>;
}

type PublicBatchResult =
  { ok: true; status: unknown } | { ok: false; error: { code: string; message: string } };

function parsePublicBatchResults(value: unknown): PublicBatchResult[] {
  if (!Array.isArray(value)) throw new TypeError('Status batch results must be an array.');
  return value.map((item: unknown) => {
    if (typeof item !== 'object' || item === null) {
      throw new TypeError('Status batch item must be an object.');
    }
    const ok: unknown = Reflect.get(item, 'ok');
    if (ok === true) {
      const status: unknown = Reflect.get(item, 'status');
      return { ok, status };
    }
    if (ok !== false) throw new TypeError('Status batch item must declare its result state.');

    const error: unknown = Reflect.get(item, 'error');
    if (typeof error !== 'object' || error === null) {
      throw new TypeError('Status batch error must be an object.');
    }
    const code: unknown = Reflect.get(error, 'code');
    const message: unknown = Reflect.get(error, 'message');
    if (typeof code !== 'string' || typeof message !== 'string') {
      throw new TypeError('Status batch error fields must be strings.');
    }
    return { ok, error: { code, message } };
  });
}

async function count(table: string): Promise<number> {
  const row = await env.INDEX_DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<{
    count: number;
  }>();
  return row?.count ?? 0;
}

beforeEach(resetAcceptanceState);

describe('registry, edge, verifier, and projection acceptance', () => {
  it('rejects post-disposal control even when the old key still signs and D1 is stale active', async () => {
    const identity = await createAcceptanceIdentity();
    const { app, edgeEnv } = createAcceptanceEdge(NOW);
    const registration = await app.fetch(
      nexusPost(
        '/v1/identity/register',
        { subject: identity.subject, genesis: identity.genesis },
        WALLET_ORIGIN,
      ),
      edgeEnv,
    );
    expect(registration.status).toBe(200);

    await env.INDEX_DB.prepare(
      `INSERT INTO identities (
         subject, genesis_hash, protocol, suite, state, sequence,
         registered_at, revoked_at, updated_at
       ) VALUES (?, ?, 'nexus.identity.v1', 'NX-25519-SHA256-JCS-v1',
                 'active', 0, ?, NULL, ?)`,
    )
      .bind(identity.subject, identity.genesisHash, NOW, NOW)
      .run();

    const activeNonce = encodeBase64Url(crypto.getRandomValues(new Uint8Array(16)));
    const activeProof = await ownershipProof(identity, activeNonce, NOW);
    await expect(
      verifyRpOperation(
        activeProof,
        expectation(activeProof.payload.nonce),
        new OneTimeChallenge(activeProof.payload.nonce),
        {
          getAuthoritativeStatus: async (subject) =>
            await authoritativeStatusThroughEdge(subject, NOW),
        },
      ),
    ).resolves.toMatchObject({ subject: identity.subject });

    const revocation = await app.fetch(
      nexusPost(
        '/v1/identity/revoke',
        { mode: 'secret', payload: secretRevocation(identity) },
        WALLET_ORIGIN,
      ),
      edgeEnv,
    );
    expect(revocation.status).toBe(200);

    const staleProjection = await env.INDEX_DB.prepare(
      'SELECT state, sequence FROM identities WHERE subject = ?',
    )
      .bind(identity.subject)
      .first<{ state: string; sequence: number }>();
    expect(staleProjection).toEqual({ state: 'active', sequence: 0 });

    const postDisposalNonce = encodeBase64Url(crypto.getRandomValues(new Uint8Array(16)));
    const postDisposalProof = await ownershipProof(identity, postDisposalNonce, NOW);
    await expect(
      verifyOwnershipProof(postDisposalProof, expectation(postDisposalProof.payload.nonce)),
    ).resolves.toMatchObject({ subject: identity.subject });
    await expect(
      verifyRpOperation(
        postDisposalProof,
        expectation(postDisposalProof.payload.nonce),
        new OneTimeChallenge(postDisposalProof.payload.nonce),
        {
          getAuthoritativeStatus: async (subject) =>
            await authoritativeStatusThroughEdge(subject, NOW),
        },
      ),
    ).rejects.toMatchObject({ code: 'IDENTITY_REVOKED' });
  });

  it('deduplicates and orders real registry Queue events delivered revoke-first', async () => {
    const identity = await createAcceptanceIdentity();
    const { app, edgeEnv } = createAcceptanceEdge(NOW);
    expect(
      (
        await app.fetch(
          nexusPost(
            '/v1/identity/register',
            { subject: identity.subject, genesis: identity.genesis },
            WALLET_ORIGIN,
          ),
          edgeEnv,
        )
      ).status,
    ).toBe(200);
    expect(
      (
        await app.fetch(
          nexusPost(
            '/v1/identity/revoke',
            { mode: 'secret', payload: secretRevocation(identity) },
            WALLET_ORIGIN,
          ),
          edgeEnv,
        )
      ).status,
    ).toBe(200);

    const events = await queuedEvents(2);
    const registered = events.find((event) => event.eventType === 'registered');
    const revoked = events.find((event) => event.eventType === 'revoked');
    expect(registered).toBeDefined();
    expect(revoked).toBeDefined();
    if (registered === undefined || revoked === undefined)
      throw new Error('Missing event fixture.');

    const transparency = {
      append: vi.fn(() => Promise.resolve()),
      appendDevice: vi.fn(() => Promise.resolve()),
    };
    const early = queueMessage(revoked);
    const earlyDuplicate = queueMessage(revoked);
    await projector.queue(batch(early.value, earlyDuplicate.value), {
      INDEX_DB: env.INDEX_DB,
      TRANSPARENCY_SERVICE: transparency,
    });
    expect(early.ack).toHaveBeenCalledOnce();
    expect(earlyDuplicate.ack).toHaveBeenCalledOnce();
    expect(await count('identities')).toBe(0);
    expect(await count('pending_registry_events')).toBe(1);

    const later = queueMessage(registered);
    const laterDuplicate = queueMessage(registered);
    await projector.queue(batch(later.value, laterDuplicate.value), {
      INDEX_DB: env.INDEX_DB,
      TRANSPARENCY_SERVICE: transparency,
    });

    const projected = await env.INDEX_DB.prepare(
      'SELECT state, sequence, registered_at, revoked_at FROM identities WHERE subject = ?',
    )
      .bind(identity.subject)
      .first<{
        state: string;
        sequence: number;
        registered_at: number;
        revoked_at: number | null;
      }>();
    expect(projected).toEqual({
      state: 'revoked',
      sequence: 1,
      registered_at: registered.acceptedAt,
      revoked_at: revoked.acceptedAt,
    });
    expect(await count('registry_events')).toBe(2);
    expect(await count('pending_registry_events')).toBe(0);
    expect(later.ack).toHaveBeenCalledOnce();
    expect(laterDuplicate.ack).toHaveBeenCalledOnce();
    expect(transparency.append).toHaveBeenCalledTimes(4);
  });

  it('preserves status-batch order and maps an unknown identity to a per-item error', async () => {
    const first = await createAcceptanceIdentity();
    const missing = await createAcceptanceIdentity();
    const third = await createAcceptanceIdentity();
    const { app, edgeEnv } = createAcceptanceEdge(NOW);
    for (const identity of [first, third]) {
      const response = await app.fetch(
        nexusPost(
          '/v1/identity/register',
          { subject: identity.subject, genesis: identity.genesis },
          WALLET_ORIGIN,
        ),
        edgeEnv,
      );
      expect(response.status).toBe(200);
    }

    const requested: NexusSubject[] = [third.subject, missing.subject, first.subject];
    const response = await app.fetch(
      nexusPost('/v1/identity/status-batch', { subjects: requested }, RP_ORIGIN),
      edgeEnv,
    );
    expect(response.status).toBe(200);
    const rawPayload: unknown = await response.json();
    if (typeof rawPayload !== 'object' || rawPayload === null) {
      throw new TypeError('Status batch response must be an object.');
    }
    const payload = { results: parsePublicBatchResults(Reflect.get(rawPayload, 'results')) };
    expect(payload.results.map((result) => result.ok)).toEqual([true, false, true]);
    expect(payload.results[1]).toMatchObject({
      ok: false,
      error: { code: 'IDENTITY_NOT_FOUND' },
    });
    const successfulSubjects = payload.results.flatMap((result) =>
      result.ok ? [registryStatusV1Schema.parse(result.status).subject] : [],
    );
    expect(successfulSubjects).toEqual([third.subject, first.subject]);
    expect(JSON.stringify(payload.results[1])).not.toContain(missing.subject);
  });

  it('projects and transparently proves v2 activation and root revocation from the distinct Queue', async () => {
    const identity = await createAcceptanceIdentity();
    const device = await createAcceptanceDevice(identity, NOW);
    const { app, edgeEnv } = createAcceptanceEdge(NOW);

    const registration = await app.fetch(
      nexusPost(
        '/v1/identity/register',
        { subject: identity.subject, genesis: identity.genesis },
        WALLET_ORIGIN,
      ),
      edgeEnv,
    );
    expect(registration.status).toBe(200);

    const activation = await app.fetch(
      nexusPost('/v2/device/activate', device.activation, WALLET_ORIGIN),
      edgeEnv,
    );
    expect(activation.status).toBe(200);

    const rootRevocation = await rootRevokeAcceptanceDevice(
      identity,
      device.authorization.payload.deviceId,
      NOW,
    );
    const revocation = await app.fetch(
      nexusPost('/v2/device/revoke-root', rootRevocation, WALLET_ORIGIN),
      edgeEnv,
    );
    expect(revocation.status).toBe(200);

    const [v1Events, deviceEvents] = await Promise.all([queuedEvents(1), queuedDeviceEvents(2)]);
    expect(v1Events).toHaveLength(1);
    expect(deviceEvents.map((event) => event.eventType)).toEqual(['activated', 'revoked']);
    const activated = deviceEvents[0];
    const revoked = deviceEvents[1];
    if (activated === undefined || revoked === undefined) {
      throw new Error('The v2 registry Queue did not contain both device lifecycle events.');
    }

    const transparencyService = createAcceptanceTransparency(createExecutionContext());
    const appendDeviceResults: Awaited<ReturnType<typeof transparencyService.appendDevice>>[] = [];
    const transparency = {
      append: (event: (typeof v1Events)[number]) => transparencyService.append(event),
      appendDevice: async (event: (typeof deviceEvents)[number]) => {
        const result = await transparencyService.appendDevice(event);
        appendDeviceResults.push(result);
        return result;
      },
    };

    const rootMessage = queueMessage(v1Events[0]);
    await projector.queue(batch(rootMessage.value), {
      INDEX_DB: env.INDEX_DB,
      TRANSPARENCY_SERVICE: transparency,
    });
    expect(rootMessage.ack).toHaveBeenCalledOnce();

    const deviceMessages = [
      queueMessage(activated),
      queueMessage(activated),
      queueMessage(revoked),
      queueMessage(revoked),
    ];
    await projector.queue(deviceBatch(...deviceMessages.map((message) => message.value)), {
      INDEX_DB: env.INDEX_DB,
      TRANSPARENCY_SERVICE: transparency,
    });
    expect(deviceMessages.every((message) => message.ack.mock.calls.length === 1)).toBe(true);
    expect(deviceMessages.every((message) => message.retry.mock.calls.length === 0)).toBe(true);
    expect(appendDeviceResults.map((result) => result.duplicate)).toEqual([
      false,
      true,
      false,
      true,
    ]);

    const projectedIdentity = await env.INDEX_DB.prepare(
      `SELECT state, sequence FROM identities WHERE subject = ?`,
    )
      .bind(identity.subject)
      .first<{ state: string; sequence: number }>();
    expect(projectedIdentity).toEqual({ state: 'active', sequence: 0 });
    expect(await count('registry_events')).toBe(1);
    expect(await count('device_registry_events')).toBe(2);

    const projectedDevice = await env.INDEX_DB.prepare(
      `SELECT authorization_id, state, event_sequence, activated_at, revoked_at,
              revoked_by, latest_event_id
       FROM device_states WHERE subject = ? AND device_id = ?`,
    )
      .bind(identity.subject, device.authorization.payload.deviceId)
      .first<{
        authorization_id: string | null;
        state: string;
        event_sequence: number;
        activated_at: number | null;
        revoked_at: number | null;
        revoked_by: string | null;
        latest_event_id: string;
      }>();
    expect(projectedDevice).toEqual({
      authorization_id: activated.authorizationId,
      state: 'revoked',
      event_sequence: 2,
      activated_at: activated.acceptedAt,
      revoked_at: revoked.acceptedAt,
      revoked_by: 'root',
      latest_event_id: revoked.eventId,
    });
    const head = await env.INDEX_DB.prepare(
      `SELECT max_device_ledger_sequence FROM device_projection_heads WHERE subject = ?`,
    )
      .bind(identity.subject)
      .first<{ max_device_ledger_sequence: number }>();
    expect(head).toEqual({ max_device_ledger_sequence: 2 });

    const eventHash = decodeBase64UrlExact(revoked.eventId.slice('nxde2_'.length), 32);
    const eventHashBase64Url = encodeBase64Url(eventHash);
    const inclusionResponse = await transparencyService.fetch(
      new Request('https://transparency.test/v1/transparency/inclusion', {
        method: 'POST',
        headers: { 'content-type': 'application/nexus+json' },
        body: JSON.stringify({ eventHash: eventHashBase64Url }),
      }),
    );
    expect(inclusionResponse.status).toBe(200);
    const inclusion = transparencyInclusionProofV1Schema.parse(await inclusionResponse.json());
    expect(inclusion.eventHash).toBe(eventHashBase64Url);
    await expect(
      verifyTransparencyInclusionProof({
        eventHash,
        leafIndex: inclusion.leafIndex,
        treeSize: inclusion.treeSize,
        auditPath: inclusion.auditPath.map((hash) => decodeBase64UrlExact(hash, 32)),
        expectedRoot: decodeBase64UrlExact(inclusion.checkpoint.payload.rootHash, 32),
      }),
    ).resolves.toBe(true);
  });
});
