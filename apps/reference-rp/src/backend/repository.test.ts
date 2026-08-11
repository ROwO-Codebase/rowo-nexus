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

import type { IssueChallengeInput, IssuedChallenge } from '../shared/contracts.js';
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
  it('stores hash-only challenges and proof receipts without an account/controller record', async () => {
    const repository = createRepository();
    const identity = await createIdentity();
    const operation: IssueChallengeInput = {
      action: 'note.create',
      draft: {
        title: 'Hash-only record',
        body: 'The raw proof should leave no database-shaped trace.',
      },
    };
    const challenge = repository.issueChallenge(operation);
    const proof = await createProof(identity, challenge);

    const before = repository.debugSnapshot();
    expect(before.challenges).toHaveLength(1);
    expect(before.challenges[0]?.nonceHash).not.toBe(challenge.nonce);
    expect(JSON.stringify(before)).not.toContain(challenge.nonce);

    const result = await repository.submitOperation({
      challengeId: challenge.challengeId,
      operation,
      proof,
    });
    const after = repository.debugSnapshot();

    expect(result.note?.authorSubject).toBe(identity.subject);
    expect(result.receipt.proofHash).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(JSON.stringify(after)).not.toContain(proof.signature);
    expect(JSON.stringify(after)).not.toContain(result.session.token);
    expect(after.sessions[0]?.tokenHash).not.toBe(result.session.token);
    expect(Object.keys(after)).toEqual(['notes', 'receipts', 'sessions', 'challenges']);
    expect(JSON.stringify(after)).not.toMatch(/controller|realUser|userId|rawProof/iu);
  });

  it('rejects a replay and allows only one winner under concurrent submission', async () => {
    const repository = createRepository();
    const identity = await createIdentity();
    const operation: IssueChallengeInput = {
      action: 'note.create',
      draft: {
        title: 'Only once',
        body: 'A single nonce must produce a single accepted mutation.',
      },
    };
    const challenge = repository.issueChallenge(operation);
    const input = {
      challengeId: challenge.challengeId,
      operation,
      proof: await createProof(identity, challenge),
    };

    const attempts = await Promise.allSettled([
      repository.submitOperation(input),
      repository.submitOperation(input),
    ]);
    expect(attempts.filter((attempt) => attempt.status === 'fulfilled')).toHaveLength(1);
    expect(attempts.filter((attempt) => attempt.status === 'rejected')).toHaveLength(1);
    expect(repository.listNotes().filter((note) => note.title === 'Only once')).toHaveLength(1);

    await expect(repository.submitOperation(input)).rejects.toMatchObject({
      code: 'CHALLENGE_EXPIRED',
    });
  });

  it('binds the challenge to exact content, version, action, resource, and audience', async () => {
    const repository = createRepository();
    const identity = await createIdentity();
    const original: IssueChallengeInput = {
      action: 'note.create',
      draft: { title: 'Original title', body: 'Original content.' },
    };
    const challenge = repository.issueChallenge(original);
    const proof = await createProof(identity, challenge);
    const changed: IssueChallengeInput = {
      action: 'note.create',
      draft: { title: 'Changed title', body: 'Original content.' },
    };

    await expect(
      repository.submitOperation({ challengeId: challenge.challengeId, operation: changed, proof }),
    ).rejects.toMatchObject({ code: 'CHALLENGE_MISMATCH' });

    const wrongAudienceChallenge = repository.issueChallenge(original);
    const wrongAudienceProof = await createProof(identity, wrongAudienceChallenge, {
      audience: 'https://other.example.test',
    });
    await expect(
      repository.submitOperation({
        challengeId: wrongAudienceChallenge.challengeId,
        operation: original,
        proof: wrongAudienceProof,
      }),
    ).rejects.toMatchObject({ code: 'WRONG_AUDIENCE' });
  });

  it('keeps author_subject immutable across edit and rejects a different identity', async () => {
    const repository = createRepository();
    const author = await createIdentity();
    const intruder = await createIdentity();
    const create: IssueChallengeInput = {
      action: 'note.create',
      draft: { title: 'Authored once', body: 'The subject cannot be replaced later.' },
    };
    const createChallenge = repository.issueChallenge(create);
    const created = await repository.submitOperation({
      challengeId: createChallenge.challengeId,
      operation: create,
      proof: await createProof(author, createChallenge),
    });
    const note = created.note;
    expect(note).not.toBeNull();
    if (note === null) throw new Error('Expected created note.');

    const attemptedEdit: IssueChallengeInput = {
      action: 'note.edit',
      noteId: note.id,
      expectedVersion: note.version,
      draft: { title: 'Attempted takeover', body: 'This must not change ownership.' },
    };
    const editChallenge = repository.issueChallenge(attemptedEdit);
    await expect(
      repository.submitOperation({
        challengeId: editChallenge.challengeId,
        operation: attemptedEdit,
        proof: await createProof(intruder, editChallenge),
      }),
    ).rejects.toMatchObject({ code: 'AUTHOR_MISMATCH' });

    const unchanged = repository.getNote(note.id);
    expect(unchanged.authorSubject).toBe(author.subject);
    expect(unchanged.title).toBe('Authored once');
  });

  it('blocks create, edit, and delete when authoritative lifecycle is revoked', async () => {
    const lifecycle = new LocalLifecycleAuthority(() => NOW);
    const repository = createRepository(lifecycle);
    const identity = await createIdentity();
    const initial: IssueChallengeInput = {
      action: 'note.create',
      draft: {
        title: 'Before disposal',
        body: 'This note was accepted while the subject was active.',
      },
    };
    const initialChallenge = repository.issueChallenge(initial);
    const created = await repository.submitOperation({
      challengeId: initialChallenge.challengeId,
      operation: initial,
      proof: await createProof(identity, initialChallenge),
    });
    if (created.note === null) throw new Error('Expected created note.');
    lifecycle.revoke(identity.subject);

    const operations: IssueChallengeInput[] = [
      {
        action: 'note.create',
        draft: { title: 'After disposal', body: 'A revoked identity cannot create another note.' },
      },
      {
        action: 'note.edit',
        noteId: created.note.id,
        expectedVersion: created.note.version,
        draft: { title: 'Changed after disposal', body: 'This mutation must be rejected.' },
      },
      {
        action: 'note.delete',
        noteId: created.note.id,
        expectedVersion: created.note.version,
      },
    ];
    for (const operation of operations) {
      const challenge = repository.issueChallenge(operation);
      await expect(
        repository.submitOperation({
          challengeId: challenge.challengeId,
          operation,
          proof: await createProof(identity, challenge),
        }),
      ).rejects.toMatchObject({ code: 'IDENTITY_REVOKED' });
    }

    expect(repository.listNotes().some((note) => note.title === 'After disposal')).toBe(false);
    expect(repository.getNote(created.note.id)).toMatchObject({
      title: 'Before disposal',
      version: 1,
      authorSubject: identity.subject,
    });
  });

  it('supports create, edit, session status, and delete with the same subject', async () => {
    const repository = createRepository();
    const identity = await createIdentity();
    const create: IssueChallengeInput = {
      action: 'note.create',
      draft: { title: 'A complete lifecycle', body: 'First version.' },
    };
    const createChallenge = repository.issueChallenge(create);
    const created = await repository.submitOperation({
      challengeId: createChallenge.challengeId,
      operation: create,
      proof: await createProof(identity, createChallenge),
    });
    if (created.note === null) throw new Error('Expected created note.');
    const session = await repository.getSession(created.session.token);
    expect(session).toMatchObject({ subject: identity.subject, state: 'active' });

    const edit: IssueChallengeInput = {
      action: 'note.edit',
      noteId: created.note.id,
      expectedVersion: created.note.version,
      draft: { title: 'A complete lifecycle', body: 'Second version.' },
    };
    const editChallenge = repository.issueChallenge(edit);
    const edited = await repository.submitOperation({
      challengeId: editChallenge.challengeId,
      operation: edit,
      proof: await createProof(identity, editChallenge),
    });
    expect(edited.note).toMatchObject({
      version: 2,
      authorSubject: identity.subject,
      body: 'Second version.',
    });

    if (edited.note === null) throw new Error('Expected edited note.');
    const remove: IssueChallengeInput = {
      action: 'note.delete',
      noteId: edited.note.id,
      expectedVersion: edited.note.version,
    };
    const deleteChallenge = repository.issueChallenge(remove);
    const deleted = await repository.submitOperation({
      challengeId: deleteChallenge.challengeId,
      operation: remove,
      proof: await createProof(identity, deleteChallenge),
    });
    expect(deleted.note).toBeNull();
    expect(() => repository.getNote(edited.note?.id ?? '')).toThrowError(
      'The requested note does not exist.',
    );
  });
});

function createRepository(lifecycle?: LocalLifecycleAuthority): ReferenceRpRepository {
  return new ReferenceRpRepository({
    audience: AUDIENCE,
    lifecycle: lifecycle ?? new LocalLifecycleAuthority(() => NOW),
    now: () => NOW,
    seed: false,
  });
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
  overrides: { audience?: string } = {},
): Promise<OwnershipProofV1> {
  const payload: OwnershipProofV1['payload'] = {
    protocol: OWNERSHIP_PROOF_PROTOCOL_V1,
    subject: identity.subject,
    genesis: identity.genesis,
    aud: overrides.audience ?? AUDIENCE,
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
