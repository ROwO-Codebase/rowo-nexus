import { env } from 'cloudflare:workers';
import {
  abortAllDurableObjects,
  evictDurableObject,
  runInDurableObject,
  SELF,
} from 'cloudflare:test';

import {
  computeRevocationCommitment,
  deriveSubject,
  signProtocolPayload,
  WebCryptoProvider,
} from '@nexus/crypto';
import {
  ED25519_ALGORITHM,
  IDENTITY_PROTOCOL_V1,
  NEXUS_SUITE_V1,
  OWNERSHIP_PROOF_PROTOCOL_V1,
  encodeBase64Url,
} from '@nexus/protocol';
import type {
  Base64Url32,
  Base64Url64,
  IdentityGenesisV1,
  NexusSubject,
  OwnershipProofV1,
} from '@nexus/protocol';
import { beforeEach, describe, expect, it } from 'vitest';

import type {
  IssueChallengeInput,
  IssuedChallenge,
  OperationResult,
} from '../src/shared/contracts';
import type { ReferenceRpState } from './reference-rp-state';

const AUDIENCE = 'https://notes.example.test';
const provider = new WebCryptoProvider();

interface TestIdentity {
  readonly subject: NexusSubject;
  readonly genesis: IdentityGenesisV1;
  readonly privateKey: CryptoKey;
}

interface TestRateLimiter {
  setMode(value: 'allow' | 'deny' | 'fail'): Promise<void>;
  reset(): Promise<void>;
  getKeys(): Promise<string[]>;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace -- Cloudflare Vitest supplies bindings through this ambient namespace.
  namespace Cloudflare {
    interface Env {
      RP_STATE: DurableObjectNamespace<ReferenceRpState>;
      RP_API_RATE_LIMITER: TestRateLimiter;
      TEST_LIFECYCLE: Fetcher;
    }
  }
}

describe('deployed reference RP Worker', () => {
  beforeEach(async () => {
    await env.TEST_LIFECYCLE.fetch('https://lifecycle.test/__test/reset', { method: 'POST' });
    await env.RP_API_RATE_LIMITER.reset();
    await runInDurableObject(env.RP_STATE.getByName('reference-rp-primary'), (_instance, state) => {
      state.storage.sql.exec('DELETE FROM challenges; DELETE FROM sessions; DELETE FROM receipts;');
    });
  });

  it('fails closed on rate-limit denial or outage without inserting a challenge', async () => {
    const stub = env.RP_STATE.getByName('reference-rp-primary');
    const countChallenges = async (): Promise<number> =>
      await runInDurableObject(
        stub,
        (_instance, state) =>
          state.storage.sql
            .exec<{ count: number }>('SELECT COUNT(*) AS count FROM challenges')
            .one().count,
      );
    const before = await countChallenges();
    const operation: IssueChallengeInput = {
      action: 'note.create',
      draft: { title: 'Rate limited', body: 'This challenge must never reach durable storage.' },
    };

    await env.RP_API_RATE_LIMITER.setMode('deny');
    const denied = await SELF.fetch(`${AUDIENCE}/api/challenges`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CF-Connecting-IP': '203.0.113.42',
      },
      body: JSON.stringify(operation),
    });
    expect(denied.status).toBe(429);
    expect(denied.headers.get('Retry-After')).toBe('60');
    expect(await countChallenges()).toBe(before);
    const keys = await env.RP_API_RATE_LIMITER.getKeys();
    expect(keys).toHaveLength(1);
    expect(keys[0]).not.toContain('203.0.113.42');

    await env.RP_API_RATE_LIMITER.setMode('fail');
    const unavailable = await postJson('/api/challenges', operation);
    expect(unavailable.status).toBe(503);
    expect(await countChallenges()).toBe(before);
  });

  it('cleans expired challenges and enforces outstanding and total SQLite quotas', async () => {
    const stub = env.RP_STATE.getByName('reference-rp-primary');
    const now = Math.floor(Date.now() / 1_000);
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec('DELETE FROM challenges');
      state.storage.sql.exec(
        `INSERT INTO challenges
          (challenge_id, nonce_hash, action, resource, context_hash, expires_at, consumed_at)
         VALUES ('expired', 'expired-hash', 'note.create', 'note:nt_expired', 'expired-context', ?, NULL)`,
        now - 1,
      );
    });
    const cleanup = await issueChallenge({
      action: 'note.create',
      draft: { title: 'Cleanup', body: 'Expired rows are removed before insertion.' },
    });
    const afterCleanup = await runInDurableObject(stub, (_instance, state) => ({
      expired: state.storage.sql
        .exec<{ count: number }>(
          "SELECT COUNT(*) AS count FROM challenges WHERE challenge_id = 'expired'",
        )
        .one().count,
      inserted: state.storage.sql
        .exec<{ count: number }>(
          'SELECT COUNT(*) AS count FROM challenges WHERE challenge_id = ?',
          cleanup.challengeId,
        )
        .one().count,
    }));
    expect(afterCleanup).toEqual({ expired: 0, inserted: 1 });

    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec('DELETE FROM challenges');
      state.storage.transactionSync(() => {
        for (let index = 0; index < 512; index += 1) {
          state.storage.sql.exec(
            `INSERT INTO challenges
              (challenge_id, nonce_hash, action, resource, context_hash, expires_at, consumed_at)
             VALUES (?, ?, 'note.create', 'note:nt_quota', 'quota-context', ?, NULL)`,
            `outstanding-${String(index)}`,
            `outstanding-hash-${String(index)}`,
            now + 600,
          );
        }
      });
    });
    const outstandingDenied = await postJson('/api/challenges', {
      action: 'note.create',
      draft: { title: 'Outstanding quota', body: 'This must be rejected.' },
    });
    expect(outstandingDenied.status).toBe(429);

    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec('DELETE FROM challenges');
      state.storage.transactionSync(() => {
        for (let index = 0; index < 2_048; index += 1) {
          state.storage.sql.exec(
            `INSERT INTO challenges
              (challenge_id, nonce_hash, action, resource, context_hash, expires_at, consumed_at)
             VALUES (?, ?, 'note.create', 'note:nt_quota', 'quota-context', ?, ?)`,
            `total-${String(index)}`,
            `total-hash-${String(index)}`,
            now + 600,
            now,
          );
        }
      });
    });
    const totalDenied = await postJson('/api/challenges', {
      action: 'note.create',
      draft: { title: 'Total quota', body: 'This must also be rejected.' },
    });
    expect(totalDenied.status).toBe(429);
  });

  it('allows exactly one mutation for a challenge and stores no raw nonce, token, or proof', async () => {
    const identity = await createRegisteredIdentity();
    const operation: IssueChallengeInput = {
      action: 'note.create',
      draft: { title: `Replay ${crypto.randomUUID()}`, body: 'Only one request may win.' },
    };
    const challenge = await issueChallenge(operation);
    const proof = await createProof(identity, challenge);
    const input = { challengeId: challenge.challengeId, operation, proof };

    const attempts = await Promise.all([
      postJson('/api/operations', input),
      postJson('/api/operations', input),
    ]);
    expect(
      attempts.map((response) => response.status).sort(),
      (await Promise.all(attempts.map(async (response) => await response.clone().text()))).join(
        '\n',
      ),
    ).toEqual([200, 409]);
    const accepted = attempts.find((response) => response.status === 200);
    if (accepted === undefined) throw new Error('Expected one accepted operation.');
    const result: OperationResult = await accepted.json();

    const stub = env.RP_STATE.getByName('reference-rp-primary');
    const snapshot = await runInDurableObject(stub, (_instance, state) => ({
      challenge: state.storage.sql
        .exec<{ nonce_hash: string; consumed_at: number | null }>(
          'SELECT nonce_hash, consumed_at FROM challenges WHERE challenge_id = ?',
          challenge.challengeId,
        )
        .one(),
      session: state.storage.sql
        .exec<{ token_hash: string }>(
          'SELECT token_hash FROM sessions WHERE subject = ?',
          identity.subject,
        )
        .toArray()[0],
      receiptCount: state.storage.sql
        .exec<{ count: number }>(
          'SELECT COUNT(*) AS count FROM receipts WHERE subject = ?',
          identity.subject,
        )
        .one().count,
    }));
    expect(snapshot.challenge.nonce_hash).not.toBe(challenge.nonce);
    expect(snapshot.challenge.consumed_at).toEqual(expect.any(Number));
    expect(snapshot.session?.token_hash).not.toBe(result.session.token);
    expect(snapshot.receiptCount).toBe(1);
    expect(JSON.stringify(snapshot)).not.toContain(proof.signature);
  });

  it('persists create, edit, session status, and delete across the public API', async () => {
    const identity = await createRegisteredIdentity();
    const create: IssueChallengeInput = {
      action: 'note.create',
      draft: { title: `Lifecycle ${crypto.randomUUID()}`, body: 'First version.' },
    };
    const created = await authorize(identity, create);
    expect(created.note).toMatchObject({ authorSubject: identity.subject, version: 1 });
    if (created.note === null) throw new Error('Expected a created note.');

    const sessionResponse = await SELF.fetch(`${AUDIENCE}/api/session`, {
      headers: { Authorization: `NexusSession ${created.session.token}` },
    });
    expect(sessionResponse.status).toBe(200);
    await expect(sessionResponse.json()).resolves.toMatchObject({
      session: { subject: identity.subject, state: 'active' },
    });

    const edit: IssueChallengeInput = {
      action: 'note.edit',
      noteId: created.note.id,
      expectedVersion: created.note.version,
      draft: { title: created.note.title, body: 'Second version.' },
    };
    const edited = await authorize(identity, edit);
    expect(edited.note).toMatchObject({
      authorSubject: identity.subject,
      version: 2,
      body: 'Second version.',
    });
    if (edited.note === null) throw new Error('Expected an edited note.');

    const remove: IssueChallengeInput = {
      action: 'note.delete',
      noteId: edited.note.id,
      expectedVersion: edited.note.version,
    };
    const deleted = await authorize(identity, remove);
    expect(deleted.note).toBeNull();
    expect((await SELF.fetch(`${AUDIENCE}/api/notes/${edited.note.id}`)).status).toBe(404);
  });

  it('denies create, edit, and delete after authoritative revocation', async () => {
    const identity = await createRegisteredIdentity();
    const initial = await authorize(identity, {
      action: 'note.create',
      draft: { title: `Before revoke ${crypto.randomUUID()}`, body: 'Still active.' },
    });
    if (initial.note === null) throw new Error('Expected a created note.');
    await lifecycleControl('/__test/revoke', identity);

    const operations: IssueChallengeInput[] = [
      {
        action: 'note.create',
        draft: { title: `Denied ${crypto.randomUUID()}`, body: 'Must not be created.' },
      },
      {
        action: 'note.edit',
        noteId: initial.note.id,
        expectedVersion: initial.note.version,
        draft: { title: initial.note.title, body: 'Must not be changed.' },
      },
      {
        action: 'note.delete',
        noteId: initial.note.id,
        expectedVersion: initial.note.version,
      },
    ];
    for (const operation of operations) {
      const challenge = await issueChallenge(operation);
      const response = await postJson('/api/operations', {
        challengeId: challenge.challengeId,
        operation,
        proof: await createProof(identity, challenge),
      });
      expect(response.status).toBe(403);
      await expect(response.json()).resolves.toMatchObject({ error: { code: 'IDENTITY_REVOKED' } });
    }

    const unchanged = await SELF.fetch(`${AUDIENCE}/api/notes/${initial.note.id}`);
    await expect(unchanged.json()).resolves.toMatchObject({
      note: { version: 1, body: 'Still active.', authorSubject: identity.subject },
    });
  });

  it('survives Durable Object eviction and enforces immutable author_subject in SQLite', async () => {
    // Pool 0.21 gracefully waits on in-flight runInDurableObject facets during
    // eviction. Clear facets retained by earlier tests, then exercise an actual
    // graceful eviction of the clean instance created below.
    await abortAllDurableObjects();
    const identity = await createRegisteredIdentity();
    const result = await authorize(identity, {
      action: 'note.create',
      draft: { title: `Durable ${crypto.randomUUID()}`, body: 'Persist this note.' },
    });
    if (result.note === null) throw new Error('Expected a created note.');

    const stub = env.RP_STATE.getByName('reference-rp-primary');
    await evictDurableObject(stub);
    const persisted = await SELF.fetch(`${AUDIENCE}/api/notes/${result.note.id}`);
    await expect(persisted.json()).resolves.toMatchObject({
      note: { id: result.note.id, authorSubject: identity.subject, body: 'Persist this note.' },
    });

    await expect(
      runInDurableObject(stub, (_instance, state) => {
        state.storage.sql.exec(
          'UPDATE notes SET author_subject = ? WHERE id = ?',
          `nx1_${'Z'.repeat(43)}`,
          result.note?.id ?? '',
        );
      }),
    ).rejects.toThrow();
    const afterAttempt = await SELF.fetch(`${AUDIENCE}/api/notes/${result.note.id}`);
    await expect(afterAttempt.json()).resolves.toMatchObject({
      note: { authorSubject: identity.subject },
    });
  });
});

async function createRegisteredIdentity(): Promise<TestIdentity> {
  const pair = await provider.generateEd25519KeyPair();
  const publicKey = await provider.exportEd25519PublicKey(pair.publicKey);
  const commitment = await computeRevocationCommitment(provider.randomBytes(32), provider);
  const genesis: IdentityGenesisV1 = {
    protocol: IDENTITY_PROTOCOL_V1,
    suite: NEXUS_SUITE_V1,
    signingKey: {
      alg: ED25519_ALGORITHM,
      publicKey: encodeBase64Url(publicKey) as Base64Url32,
    },
    revocationCommitment: encodeBase64Url(commitment) as Base64Url32,
  };
  const identity = {
    genesis,
    subject: await deriveSubject(genesis, provider),
    privateKey: pair.privateKey,
  };
  await lifecycleControl('/__test/register', identity);
  return identity;
}

async function lifecycleControl(
  path: string,
  identity: Pick<TestIdentity, 'subject' | 'genesis'>,
): Promise<void> {
  const response = await env.TEST_LIFECYCLE.fetch(`https://lifecycle.test${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject: identity.subject, genesis: identity.genesis }),
  });
  expect(response.ok).toBe(true);
}

async function issueChallenge(operation: IssueChallengeInput): Promise<IssuedChallenge> {
  const response = await postJson('/api/challenges', operation);
  expect(response.status).toBe(201);
  const body: { challenge: IssuedChallenge } = await response.json();
  return body.challenge;
}

async function authorize(
  identity: TestIdentity,
  operation: IssueChallengeInput,
): Promise<OperationResult> {
  const challenge = await issueChallenge(operation);
  const response = await postJson('/api/operations', {
    challengeId: challenge.challengeId,
    operation,
    proof: await createProof(identity, challenge),
  });
  expect(response.status, await response.clone().text()).toBe(200);
  return await response.json();
}

async function createProof(
  identity: TestIdentity,
  challenge: IssuedChallenge,
): Promise<OwnershipProofV1> {
  const now = Math.floor(Date.now() / 1_000);
  const payload: OwnershipProofV1['payload'] = {
    protocol: OWNERSHIP_PROOF_PROTOCOL_V1,
    subject: identity.subject,
    genesis: identity.genesis,
    aud: AUDIENCE,
    act: challenge.action,
    resource: challenge.resource,
    nonce: challenge.nonce,
    iat: now,
    exp: challenge.expiresAt,
    ...(challenge.contextHash === undefined ? {} : { contextHash: challenge.contextHash }),
  };
  return {
    payload,
    signature: (await signProtocolPayload(payload, identity.privateKey, provider)) as Base64Url64,
  };
}

function postJson(path: string, value: unknown): Promise<Response> {
  return SELF.fetch(`${AUDIENCE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(value),
  });
}
