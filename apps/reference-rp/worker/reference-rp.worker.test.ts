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
  IssuedChallenge,
  NoteView,
  SessionOperationInput,
  SessionOperationResult,
  SessionStartResult,
} from '../src/shared/contracts';
import type { ReferenceRpState } from './reference-rp-state';

const AUDIENCE = 'https://notes.example.test';
const SESSION_RESOURCE = 'urn:rowo:nexus-notes:session';
const provider = new WebCryptoProvider();

interface TestIdentity {
  readonly subject: NexusSubject;
  readonly genesis: IdentityGenesisV1;
  readonly privateKey: CryptoKey;
}

interface LoggedInIdentity {
  readonly identity: TestIdentity;
  readonly cookie: string;
  readonly result: SessionStartResult;
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
      state.storage.sql.exec(`
        DELETE FROM note_likes;
        DELETE FROM replies;
        DELETE FROM notes;
        DELETE FROM challenges;
        DELETE FROM sessions;
        DELETE FROM receipts;
      `);
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

    await env.RP_API_RATE_LIMITER.setMode('deny');
    const denied = await SELF.fetch(`${AUDIENCE}/api/challenges`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CF-Connecting-IP': '203.0.113.42',
      },
      body: JSON.stringify({ action: 'session.start' }),
    });
    expect(denied.status).toBe(429);
    expect(denied.headers.get('Retry-After')).toBe('60');
    expect(await countChallenges()).toBe(before);
    const keys = await env.RP_API_RATE_LIMITER.getKeys();
    expect(keys).toHaveLength(1);
    expect(keys[0]).not.toContain('203.0.113.42');

    await env.RP_API_RATE_LIMITER.setMode('fail');
    const unavailable = await postJson('/api/challenges', { action: 'session.start' });
    expect(unavailable.status).toBe(503);
    expect(await countChallenges()).toBe(before);
  });

  it('cleans expired challenges and enforces bounded outstanding challenge storage', async () => {
    const stub = env.RP_STATE.getByName('reference-rp-primary');
    const now = Math.floor(Date.now() / 1_000);
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec(
        `INSERT INTO challenges
          (challenge_id, nonce_hash, action, resource, context_hash, expires_at, consumed_at)
         VALUES ('expired', 'expired-hash', 'session.start', ?, 'expired-context', ?, NULL)`,
        SESSION_RESOURCE,
        now - 1,
      );
    });
    const challenge = await issueChallenge();
    const afterCleanup = await runInDurableObject(stub, (_instance, state) => ({
      expired: state.storage.sql
        .exec<{ count: number }>(
          "SELECT COUNT(*) AS count FROM challenges WHERE challenge_id = 'expired'",
        )
        .one().count,
      inserted: state.storage.sql
        .exec<{ count: number }>(
          'SELECT COUNT(*) AS count FROM challenges WHERE challenge_id = ?',
          challenge.challengeId,
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
             VALUES (?, ?, 'session.start', ?, 'quota-context', ?, NULL)`,
            `outstanding-${String(index)}`,
            `outstanding-hash-${String(index)}`,
            SESSION_RESOURCE,
            now + 600,
          );
        }
      });
    });
    const denied = await postJson('/api/challenges', { action: 'session.start' });
    expect(denied.status).toBe(429);
  });

  it('starts one hash-only five-minute session and rejects proof replay', async () => {
    const identity = await createRegisteredIdentity();
    const challenge = await issueChallenge();
    const input = {
      challengeId: challenge.challengeId,
      operation: { action: 'session.start' as const },
      proof: await createProof(identity, challenge),
    };

    const attempts = await Promise.all([
      postJson('/api/operations', input),
      postJson('/api/operations', input),
    ]);
    expect(attempts.map((response) => response.status).sort()).toEqual([200, 409]);
    const accepted = attempts.find((response) => response.status === 200);
    if (accepted === undefined) throw new Error('Expected one accepted session.');
    const result: SessionStartResult = await accepted.clone().json();
    const setCookie = accepted.headers.get('Set-Cookie');
    expect(setCookie).toContain('__Host-nexus_notes_session=');
    expect(setCookie).toContain('Max-Age=300');
    expect(setCookie).toContain('Secure');
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('SameSite=Strict');
    const cookie = cookiePair(setCookie);

    const snapshot = await runInDurableObject(
      env.RP_STATE.getByName('reference-rp-primary'),
      (_instance, state) => ({
        challenge: state.storage.sql
          .exec<{ nonce_hash: string; consumed_at: number | null }>(
            'SELECT nonce_hash, consumed_at FROM challenges WHERE challenge_id = ?',
            challenge.challengeId,
          )
          .one(),
        session: state.storage.sql
          .exec<{ token_hash: string; proof_hash: string; expires_at: number }>(
            'SELECT token_hash, proof_hash, expires_at FROM sessions WHERE subject = ?',
            identity.subject,
          )
          .one(),
      }),
    );
    expect(snapshot.challenge.nonce_hash).not.toBe(challenge.nonce);
    expect(snapshot.challenge.consumed_at).toEqual(expect.any(Number));
    expect(snapshot.session.token_hash).not.toBe(cookie.split('=')[1]);
    expect(snapshot.session.proof_hash).toBe(result.receipt.proofHash);
    expect(snapshot.session.expires_at - result.receipt.acceptedAt).toBe(300);
    expect(JSON.stringify(snapshot)).not.toContain(input.proof.signature);

    const current = await fetchWithCookie('/api/session', cookie);
    expect(current.status).toBe(200);
    await expect(current.json()).resolves.toMatchObject({
      session: { subject: identity.subject, state: 'active' },
    });
  });

  it('keeps private notes creator-only and exposes edit/delete authority only through that session', async () => {
    const owner = await login(await createRegisteredIdentity());
    const other = await login(await createRegisteredIdentity());
    const privateNote = await createNote(owner.cookie, 'private');

    await expect(fetchNotes()).resolves.toEqual([]);
    await expect(fetchNotes(other.cookie)).resolves.toEqual([]);
    expect((await fetchWithCookie(`/api/notes/${privateNote.id}`, other.cookie)).status).toBe(404);
    await expect(fetchNote(privateNote.id, owner.cookie)).resolves.toMatchObject({
      id: privateNote.id,
      authorSubject: owner.identity.subject,
      visibility: 'private',
    });

    const denied = await sessionOperation(other.cookie, {
      action: 'note.edit',
      noteId: privateNote.id,
      expectedVersion: privateNote.version,
      draft: { title: 'Takeover', body: 'This must fail.', visibility: 'public' },
    });
    expect(denied.status).toBe(403);

    const publicNote = await createNote(owner.cookie, 'public');
    await expect(fetchNotes()).resolves.toEqual([
      expect.objectContaining({ id: publicNote.id, visibility: 'public' }),
    ]);
  });

  it('supports replies and enforces reply-author or note-author removal', async () => {
    const owner = await login(await createRegisteredIdentity());
    const visitor = await login(await createRegisteredIdentity());
    const stranger = await login(await createRegisteredIdentity());
    const note = await createNote(owner.cookie, 'public');

    const replied = await expectSessionSuccess(
      await sessionOperation(visitor.cookie, {
        action: 'reply.create',
        noteId: note.id,
        body: 'A visitor reply.',
      }),
    );
    const reply = replied.note?.replies[0];
    if (reply === undefined) throw new Error('Expected a reply.');

    expect(
      (
        await sessionOperation(stranger.cookie, {
          action: 'reply.delete',
          noteId: note.id,
          replyId: reply.id,
        })
      ).status,
    ).toBe(403);
    const removed = await expectSessionSuccess(
      await sessionOperation(owner.cookie, {
        action: 'reply.delete',
        noteId: note.id,
        replyId: reply.id,
      }),
    );
    expect(removed.note?.replies).toEqual([]);

    const privateNote = await createNote(owner.cookie, 'private');
    expect(
      (
        await sessionOperation(visitor.cookie, {
          action: 'reply.create',
          noteId: privateNote.id,
          body: 'Invisible reply.',
        })
      ).status,
    ).toBe(404);
    expect(
      (
        await expectSessionSuccess(
          await sessionOperation(owner.cookie, {
            action: 'reply.create',
            noteId: privateNote.id,
            body: 'Owner self-reply.',
          }),
        )
      ).note?.replies,
    ).toHaveLength(1);
  });

  it('counts one like per subject, supports unlike, and never likes a private note', async () => {
    const owner = await login(await createRegisteredIdentity());
    const visitor = await login(await createRegisteredIdentity());
    const note = await createNote(owner.cookie, 'public');

    await expectSessionSuccess(
      await sessionOperation(visitor.cookie, { action: 'note.like', noteId: note.id }),
    );
    const duplicate = await expectSessionSuccess(
      await sessionOperation(visitor.cookie, { action: 'note.like', noteId: note.id }),
    );
    expect(duplicate.note).toMatchObject({ likeCount: 1, likedByViewer: true });
    const unliked = await expectSessionSuccess(
      await sessionOperation(visitor.cookie, { action: 'note.unlike', noteId: note.id }),
    );
    expect(unliked.note).toMatchObject({ likeCount: 0, likedByViewer: false });

    const privateNote = await createNote(owner.cookie, 'private');
    expect(
      (await sessionOperation(owner.cookie, { action: 'note.like', noteId: privateNote.id }))
        .status,
    ).toBe(403);
  });

  it('rejects every session mutation after revocation and survives Durable Object eviction', async () => {
    await abortAllDurableObjects();
    const owner = await login(await createRegisteredIdentity());
    const note = await createNote(owner.cookie, 'public');
    const stub = env.RP_STATE.getByName('reference-rp-primary');
    await evictDurableObject(stub);
    await expect(fetchNote(note.id)).resolves.toMatchObject({
      id: note.id,
      authorSubject: owner.identity.subject,
    });

    await lifecycleControl('/__test/revoke', owner.identity);
    const denied = await sessionOperation(owner.cookie, {
      action: 'note.delete',
      noteId: note.id,
      expectedVersion: note.version,
    });
    expect(denied.status).toBe(401);
    await expect(denied.json()).resolves.toMatchObject({ error: { code: 'SESSION_INVALID' } });

    await expect(
      runInDurableObject(stub, (_instance, state) => {
        state.storage.sql.exec(
          'UPDATE notes SET author_subject = ? WHERE id = ?',
          `nx1_${'Z'.repeat(43)}`,
          note.id,
        );
      }),
    ).rejects.toThrow();
    const schema = await runInDurableObject(stub, (_instance, state) => ({
      version: state.storage.sql
        .exec<{ version: number }>('SELECT version FROM schema_meta WHERE singleton = 1')
        .one().version,
      replyTable: state.storage.sql
        .exec<{ count: number }>(
          "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'replies'",
        )
        .one().count,
      likesTable: state.storage.sql
        .exec<{ count: number }>(
          "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'note_likes'",
        )
        .one().count,
    }));
    expect(schema).toEqual({ version: 2, replyTable: 1, likesTable: 1 });
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

async function issueChallenge(): Promise<IssuedChallenge> {
  const response = await postJson('/api/challenges', { action: 'session.start' });
  expect(response.status, await response.clone().text()).toBe(201);
  const body: { challenge: IssuedChallenge } = await response.json();
  return body.challenge;
}

async function login(identity: TestIdentity): Promise<LoggedInIdentity> {
  const challenge = await issueChallenge();
  const response = await postJson('/api/operations', {
    challengeId: challenge.challengeId,
    operation: { action: 'session.start' },
    proof: await createProof(identity, challenge),
  });
  expect(response.status, await response.clone().text()).toBe(200);
  return {
    identity,
    cookie: cookiePair(response.headers.get('Set-Cookie')),
    result: await response.json(),
  };
}

async function createNote(cookie: string, visibility: 'public' | 'private'): Promise<NoteView> {
  const result = await expectSessionSuccess(
    await sessionOperation(cookie, {
      action: 'note.create',
      draft: { title: `${visibility} note`, body: 'A note body.', visibility },
    }),
  );
  if (result.note === null) throw new Error('Expected a note.');
  return result.note;
}

async function sessionOperation(
  cookie: string,
  operation: SessionOperationInput,
): Promise<Response> {
  return await SELF.fetch(`${AUDIENCE}/api/session-operations`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: cookie,
      'X-Nexus-Notes-Session': '1',
    },
    body: JSON.stringify(operation),
  });
}

async function expectSessionSuccess(response: Response): Promise<SessionOperationResult> {
  expect(response.status, await response.clone().text()).toBe(200);
  return await response.json();
}

async function fetchNotes(cookie?: string): Promise<NoteView[]> {
  const response = await fetchWithCookie('/api/notes', cookie);
  expect(response.status, await response.clone().text()).toBe(200);
  const body: { notes: NoteView[] } = await response.json();
  return body.notes;
}

async function fetchNote(id: string, cookie?: string): Promise<NoteView> {
  const response = await fetchWithCookie(`/api/notes/${id}`, cookie);
  expect(response.status, await response.clone().text()).toBe(200);
  const body: { note: NoteView } = await response.json();
  return body.note;
}

function fetchWithCookie(path: string, cookie?: string): Promise<Response> {
  return SELF.fetch(`${AUDIENCE}${path}`, {
    headers: cookie === undefined ? {} : { Cookie: cookie },
  });
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

function cookiePair(setCookie: string | null): string {
  if (setCookie === null) throw new Error('Expected the session cookie.');
  const pair = setCookie.split(';', 1)[0];
  if (pair === undefined || !pair.startsWith('__Host-nexus_notes_session=')) {
    throw new Error('The session cookie is malformed.');
  }
  return pair;
}

function postJson(path: string, value: unknown): Promise<Response> {
  return SELF.fetch(`${AUDIENCE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(value),
  });
}
