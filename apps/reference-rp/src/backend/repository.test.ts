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
import { describe, expect, it } from 'vitest';

import type { IssuedChallenge } from '../shared/contracts.js';
import { LocalLifecycleAuthority } from './lifecycle.js';
import { ReferenceRpRepository } from './repository.js';

const AUDIENCE = 'https://notes.example.test';
const NOW = 1_800_000_000;
const provider = new WebCryptoProvider();

interface TestIdentity {
  subject: NexusSubject;
  genesis: IdentityGenesisV1;
  privateKey: CryptoKey;
}

describe('ReferenceRpRepository', () => {
  it('starts one hash-only session and rejects replay of its exact proof', async () => {
    const repository = createRepository();
    const identity = await createIdentity();
    const challenge = repository.issueChallenge({ action: 'session.start' });
    const input = {
      challengeId: challenge.challengeId,
      operation: { action: 'session.start' as const },
      proof: await createProof(identity, challenge),
    };

    const before = repository.debugSnapshot();
    expect(before.challenges[0]?.nonceHash).not.toBe(challenge.nonce);
    expect(JSON.stringify(before)).not.toContain(challenge.nonce);

    const attempts = await Promise.allSettled([
      repository.startSession(input),
      repository.startSession(input),
    ]);
    const successful = attempts.find((attempt) => attempt.status === 'fulfilled');
    expect(attempts.filter((attempt) => attempt.status === 'fulfilled')).toHaveLength(1);
    expect(attempts.filter((attempt) => attempt.status === 'rejected')).toHaveLength(1);
    if (successful?.status !== 'fulfilled') throw new Error('Expected one session.');

    const after = repository.debugSnapshot();
    expect(successful.value.result.session.subject).toBe(identity.subject);
    expect(successful.value.result.receipt).toMatchObject({
      operation: 'session.start',
      authorization: 'wallet-proof',
    });
    expect(JSON.stringify(after)).not.toContain(input.proof.signature);
    expect(JSON.stringify(after)).not.toContain(successful.value.token);
    expect(after.sessions[0]?.tokenHash).not.toBe(successful.value.token);
    expect(Object.keys(after)).toEqual([
      'notes',
      'replies',
      'likes',
      'receipts',
      'sessions',
      'profiles',
      'challenges',
    ]);
  });

  it('denies restricted subjects and permanently invalidates an existing local session', async () => {
    const restricted = new Set<NexusSubject>();
    const repository = createRepository(
      undefined,
      () => NOW,
      (subject) => restricted.has(subject),
    );
    const identity = await createIdentity();
    restricted.add(identity.subject);

    await expect(login(repository, identity)).rejects.toMatchObject({
      code: 'SUBJECT_RESTRICTED',
    });
    expect(repository.debugSnapshot().sessions).toEqual([]);
    expect(repository.debugSnapshot().receipts).toEqual([]);

    restricted.delete(identity.subject);
    const started = await login(repository, identity);
    restricted.add(identity.subject);
    await expect(repository.getSession(started.token)).rejects.toMatchObject({
      code: 'SESSION_INVALID',
    });

    restricted.delete(identity.subject);
    await expect(repository.getSession(started.token)).rejects.toMatchObject({
      code: 'SESSION_INVALID',
    });
  });

  it('publishes one unique friendly name across existing notes and replies', async () => {
    const repository = createRepository();
    const owner = await login(repository, await createIdentity());
    const visitor = await login(repository, await createIdentity());
    const note = await createNote(repository, owner.token, 'public');
    await repository.executeSessionOperation(
      { action: 'reply.create', noteId: note.id, body: 'An owner reply.' },
      owner.token,
    );

    const named = await repository.executeSessionOperation(
      { action: 'profile.set-name', friendlyName: 'friendly_name' },
      owner.token,
    );
    expect(named.session?.friendlyName).toBe('friendly_name');
    const publicView = await repository.getNote(note.id);
    expect(publicView.authorFriendlyName).toBe('friendly_name');
    expect(publicView.replies[0]?.authorFriendlyName).toBe('friendly_name');

    await expect(
      repository.executeSessionOperation(
        { action: 'profile.set-name', friendlyName: 'FRIENDLY_NAME' },
        visitor.token,
      ),
    ).rejects.toMatchObject({ code: 'NAME_TAKEN' });

    await repository.executeSessionOperation(
      { action: 'profile.set-name', friendlyName: 'renamed_writer' },
      owner.token,
    );
    expect((await repository.getNote(note.id)).authorFriendlyName).toBe('renamed_writer');
  });

  it('returns private notes only to their active creator session', async () => {
    const repository = createRepository();
    const owner = await login(repository, await createIdentity());
    const other = await login(repository, await createIdentity());

    const created = await repository.executeSessionOperation(
      {
        action: 'note.create',
        draft: {
          title: 'Private field notes',
          body: 'Only the creator can read this.',
          visibility: 'private',
        },
      },
      owner.token,
    );
    if (created.note === null) throw new Error('Expected private note.');

    expect(await repository.listNotes()).toEqual([]);
    expect(await repository.listNotes(other.token)).toEqual([]);
    await expect(repository.getNote(created.note.id, other.token)).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    expect(await repository.getNote(created.note.id, owner.token)).toMatchObject({
      visibility: 'private',
      authorSubject: owner.identity.subject,
    });

    await repository.executeSessionOperation(
      {
        action: 'note.create',
        draft: {
          title: 'Public field notes',
          body: 'Everyone can read this.',
          visibility: 'public',
        },
      },
      owner.token,
    );
    expect((await repository.listNotes()).map((note) => note.title)).toEqual([
      'Public field notes',
    ]);
  });

  it('allows replies on visible notes and enforces reply-or-note-author removal', async () => {
    const repository = createRepository();
    const owner = await login(repository, await createIdentity());
    const visitor = await login(repository, await createIdentity());
    const stranger = await login(repository, await createIdentity());
    const created = await createNote(repository, owner.token, 'public');

    let updated = await repository.executeSessionOperation(
      { action: 'reply.create', noteId: created.id, body: 'A visitor reply.' },
      visitor.token,
    );
    expect(updated.note?.replies).toHaveLength(1);
    const visitorReply = updated.note?.replies[0];
    if (visitorReply === undefined) throw new Error('Expected reply.');

    await expect(
      repository.executeSessionOperation(
        { action: 'reply.delete', noteId: created.id, replyId: visitorReply.id },
        stranger.token,
      ),
    ).rejects.toMatchObject({ code: 'AUTHOR_MISMATCH' });

    updated = await repository.executeSessionOperation(
      { action: 'reply.delete', noteId: created.id, replyId: visitorReply.id },
      owner.token,
    );
    expect(updated.note?.replies).toEqual([]);

    const privateNote = await createNote(repository, owner.token, 'private');
    expect(
      (
        await repository.executeSessionOperation(
          { action: 'reply.create', noteId: privateNote.id, body: 'A private self-reply.' },
          owner.token,
        )
      ).note?.replies,
    ).toHaveLength(1);
    await expect(
      repository.executeSessionOperation(
        { action: 'reply.create', noteId: privateNote.id, body: 'This must not be visible.' },
        visitor.token,
      ),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('counts one like per subject, supports unlike, and rejects private-note likes', async () => {
    const repository = createRepository();
    const owner = await login(repository, await createIdentity());
    const visitor = await login(repository, await createIdentity());
    const publicNote = await createNote(repository, owner.token, 'public');

    await repository.executeSessionOperation(
      { action: 'note.like', noteId: publicNote.id },
      visitor.token,
    );
    const liked = await repository.executeSessionOperation(
      { action: 'note.like', noteId: publicNote.id },
      visitor.token,
    );
    expect(liked.note).toMatchObject({ likeCount: 1, likedByViewer: true });

    const unliked = await repository.executeSessionOperation(
      { action: 'note.unlike', noteId: publicNote.id },
      visitor.token,
    );
    expect(unliked.note).toMatchObject({ likeCount: 0, likedByViewer: false });

    const privateNote = await createNote(repository, owner.token, 'private');
    await expect(
      repository.executeSessionOperation(
        { action: 'note.like', noteId: privateNote.id },
        owner.token,
      ),
    ).rejects.toMatchObject({ code: 'OPERATION_NOT_ALLOWED' });
  });

  it('gates edit and delete by active immutable-author session and lifecycle', async () => {
    const lifecycle = new LocalLifecycleAuthority(() => NOW);
    const repository = createRepository(lifecycle);
    const ownerIdentity = await createIdentity();
    const owner = await login(repository, ownerIdentity);
    const other = await login(repository, await createIdentity());
    const note = await createNote(repository, owner.token, 'public');

    await expect(
      repository.executeSessionOperation(
        {
          action: 'note.edit',
          noteId: note.id,
          expectedVersion: note.version,
          draft: { title: 'Takeover', body: 'Rejected.', visibility: 'public' },
        },
        other.token,
      ),
    ).rejects.toMatchObject({ code: 'AUTHOR_MISMATCH' });

    const edited = await repository.executeSessionOperation(
      {
        action: 'note.edit',
        noteId: note.id,
        expectedVersion: note.version,
        draft: { title: 'Updated', body: 'Accepted.', visibility: 'private' },
      },
      owner.token,
    );
    expect(edited.note).toMatchObject({
      title: 'Updated',
      visibility: 'private',
      authorSubject: ownerIdentity.subject,
      authorization: 'rp-session',
    });

    lifecycle.revoke(ownerIdentity.subject);
    await expect(
      repository.executeSessionOperation(
        {
          action: 'note.delete',
          noteId: note.id,
          expectedVersion: edited.note?.version ?? 2,
        },
        owner.token,
      ),
    ).rejects.toMatchObject({ code: 'SESSION_INVALID' });
  });

  it('expires sessions absolutely after five minutes', async () => {
    const clock = { now: NOW };
    const lifecycle = new LocalLifecycleAuthority(() => clock.now);
    const repository = createRepository(lifecycle, () => clock.now);
    const started = await login(repository, await createIdentity());
    clock.now += 301;

    await expect(repository.getSession(started.token)).rejects.toMatchObject({
      code: 'SESSION_INVALID',
    });
    await expect(
      repository.executeSessionOperation(
        {
          action: 'note.create',
          draft: { title: 'Too late', body: 'The session expired.', visibility: 'public' },
        },
        started.token,
      ),
    ).rejects.toMatchObject({ code: 'SESSION_INVALID' });
  });
});

function createRepository(
  lifecycle?: LocalLifecycleAuthority,
  now: () => number = () => NOW,
  isSubjectRestricted?: (subject: NexusSubject, now: number) => boolean,
): ReferenceRpRepository {
  return new ReferenceRpRepository({
    audience: AUDIENCE,
    lifecycle: lifecycle ?? new LocalLifecycleAuthority(now),
    now,
    seed: false,
    ...(isSubjectRestricted === undefined ? {} : { isSubjectRestricted }),
  });
}

async function login(repository: ReferenceRpRepository, identity: TestIdentity) {
  const challenge = repository.issueChallenge({ action: 'session.start' });
  const started = await repository.startSession({
    challengeId: challenge.challengeId,
    operation: { action: 'session.start' },
    proof: await createProof(identity, challenge),
  });
  return { ...started, identity };
}

async function createNote(
  repository: ReferenceRpRepository,
  token: string,
  visibility: 'public' | 'private',
) {
  const created = await repository.executeSessionOperation(
    {
      action: 'note.create',
      draft: { title: `${visibility} note`, body: 'A note body.', visibility },
    },
    token,
  );
  if (created.note === null) throw new Error('Expected note.');
  return created.note;
}

async function createIdentity(): Promise<TestIdentity> {
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
  return {
    genesis,
    subject: await deriveSubject(genesis, provider),
    privateKey: pair.privateKey,
  };
}

async function createProof(
  identity: TestIdentity,
  challenge: IssuedChallenge,
  audience = AUDIENCE,
): Promise<OwnershipProofV1> {
  const payload: OwnershipProofV1['payload'] = {
    protocol: OWNERSHIP_PROOF_PROTOCOL_V1,
    subject: identity.subject,
    genesis: identity.genesis,
    aud: audience,
    act: challenge.action,
    resource: challenge.resource,
    nonce: challenge.nonce,
    iat: NOW,
    exp: challenge.expiresAt,
    ...(challenge.contextHash === undefined ? {} : { contextHash: challenge.contextHash }),
  };
  return {
    payload,
    signature: (await signProtocolPayload(payload, identity.privateKey, provider)) as Base64Url64,
  };
}
