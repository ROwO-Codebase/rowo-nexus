import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';

import type { IdentityState } from '../../workers/registry/src/identity-state-do';
import {
  WALLET_ORIGIN,
  createAcceptanceEdge,
  createAcceptanceIdentity,
  nexusPost,
  resetAcceptanceState,
  secretRevocation,
  signatureRevocation,
} from '../worker-integration/helpers';

const NOW = Math.floor(Date.now() / 1_000);

async function inspectCounts(stub: DurableObjectStub<IdentityState>) {
  return await runInDurableObject(stub, (_instance, state) => ({
    identity: state.storage.sql
      .exec<{ count: number }>('SELECT COUNT(*) AS count FROM identity_state')
      .one().count,
    actions: state.storage.sql
      .exec<{ count: number }>('SELECT COUNT(*) AS count FROM actions')
      .one().count,
    revocations: state.storage.sql
      .exec<{ count: number }>("SELECT COUNT(*) AS count FROM actions WHERE action_type = 'revoke'")
      .one().count,
    outbox: state.storage.sql.exec<{ count: number }>('SELECT COUNT(*) AS count FROM outbox').one()
      .count,
    state: state.storage.sql
      .exec<{ state: string; sequence: number }>(
        'SELECT state, sequence FROM identity_state WHERE singleton = 1',
      )
      .one(),
  }));
}

beforeEach(resetAcceptanceState);

describe('registry concurrency through the edge contract', () => {
  it('collapses 50 simultaneous registration requests into one authoritative event', async () => {
    const identity = await createAcceptanceIdentity();
    const { app, edgeEnv } = createAcceptanceEdge(NOW);
    const responses = await Promise.all(
      Array.from(
        { length: 50 },
        async () =>
          await app.fetch(
            nexusPost(
              '/v1/identity/register',
              { subject: identity.subject, genesis: identity.genesis },
              WALLET_ORIGIN,
            ),
            edgeEnv,
          ),
      ),
    );

    expect(responses.every((response) => response.status === 200)).toBe(true);
    const bodies = await Promise.all(responses.map(async (response) => await response.json()));
    const eventIds = bodies.map(
      (body) => (body as { receipt: { payload: { eventId: string } } }).receipt.payload.eventId,
    );
    expect(new Set(eventIds).size).toBe(1);

    const stub = env.IDENTITY_STATE.getByName(identity.subject);
    expect(await inspectCounts(stub)).toEqual({
      identity: 1,
      actions: 1,
      revocations: 0,
      outbox: 1,
      state: { state: 'active', sequence: 0 },
    });
  });

  it('serializes signing-key and secret revocation requests into one terminal transition', async () => {
    const identity = await createAcceptanceIdentity();
    const { app, edgeEnv } = createAcceptanceEdge(NOW);
    const registered = await app.fetch(
      nexusPost(
        '/v1/identity/register',
        { subject: identity.subject, genesis: identity.genesis },
        WALLET_ORIGIN,
      ),
      edgeEnv,
    );
    expect(registered.status).toBe(200);

    const signed = await signatureRevocation(identity, NOW);
    const secret = secretRevocation(identity);
    const [signatureResponse, secretResponse] = await Promise.all([
      app.fetch(
        nexusPost('/v1/identity/revoke', { mode: 'signature', ...signed }, WALLET_ORIGIN),
        edgeEnv,
      ),
      app.fetch(
        nexusPost('/v1/identity/revoke', { mode: 'secret', payload: secret }, WALLET_ORIGIN),
        edgeEnv,
      ),
    ]);

    expect([signatureResponse.status, secretResponse.status]).toEqual([200, 200]);
    const results = await Promise.all([signatureResponse.json(), secretResponse.json()]);
    const terminalIds = results.map(
      (body) => (body as { receipt: { payload: { eventId: string } } }).receipt.payload.eventId,
    );
    expect(new Set(terminalIds).size).toBe(1);

    const stub = env.IDENTITY_STATE.getByName(identity.subject);
    expect(await inspectCounts(stub)).toEqual({
      identity: 1,
      actions: 2,
      revocations: 1,
      outbox: 2,
      state: { state: 'revoked', sequence: 1 },
    });
  });
});
