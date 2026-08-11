import {
  CONTINUITY_LINK_PROTOCOL_V1,
  IDENTITY_PROTOCOL_V1,
  NEXUS_SUITE_V1,
  OWNERSHIP_PROOF_PROTOCOL_V1,
  REGISTRY_RECEIPT_PROTOCOL_V1,
  REVOKE_PROTOCOL_V1,
  REVOKE_SECRET_PROTOCOL_V1,
  STATUS_STATEMENT_PROTOCOL_V1,
  encodeBase64Url,
} from '@nexus/protocol';
import type {
  Base64Url32,
  Base64Url64,
  Base64UrlAtLeast16,
  ContinuityLinkPayloadV1,
  IdentityGenesisV1,
  NexusSubject,
  OwnershipProofPayloadV1,
  OwnershipProofV1,
  RegistryReceiptPayloadV1,
  RevokeBySignaturePayloadV1,
  ServiceKeySet,
  StatusStatementPayloadV1,
  VerificationExpectation,
} from '@nexus/protocol';
import {
  computeRevocationCommitment,
  deriveSubject,
  getDefaultCryptoProvider,
  signProtocolPayload,
} from '@nexus/crypto';
import { describe, expect, it } from 'vitest';

import {
  NexusVerificationError,
  verifyContinuityLink,
  verifyOwnershipProof,
  verifyRegistryReceipt,
  verifyRevocationSecret,
  verifyRevokeBySignature,
  verifyRpOperation,
  verifyStatusStatement,
  verifySubject,
} from './index.js';
import type { ChallengeStore, LifecycleProvider, NexusVerificationErrorCode } from './index.js';

const NOW = 1_800_000_000;

function encoded32(bytes: Uint8Array): Base64Url32 {
  return encodeBase64Url(bytes) as Base64Url32;
}

function encoded64(value: string): Base64Url64 {
  return value as Base64Url64;
}

function encodedNonce(bytes: Uint8Array): Base64UrlAtLeast16 {
  return encodeBase64Url(bytes) as Base64UrlAtLeast16;
}

const NONCE = encodedNonce(new Uint8Array(16).fill(7));

interface TestIdentity {
  readonly genesis: IdentityGenesisV1;
  readonly subject: NexusSubject;
  readonly privateKey: CryptoKey;
  readonly revocationSecret: Uint8Array;
}

async function makeIdentity(seed: number): Promise<TestIdentity> {
  const provider = getDefaultCryptoProvider();
  const keyPair = await provider.generateEd25519KeyPair({
    privateKeyExtractable: true,
  });
  const publicKey = await provider.exportEd25519PublicKey(keyPair.publicKey);
  const revocationSecret = new Uint8Array(32).fill(seed);
  const commitment = await computeRevocationCommitment(revocationSecret);
  const genesis: IdentityGenesisV1 = {
    protocol: IDENTITY_PROTOCOL_V1,
    suite: NEXUS_SUITE_V1,
    signingKey: {
      alg: 'Ed25519',
      publicKey: encoded32(publicKey),
    },
    revocationCommitment: encoded32(commitment),
  };

  return {
    genesis,
    subject: await deriveSubject(genesis),
    privateKey: keyPair.privateKey,
    revocationSecret,
  };
}

function expectation(overrides: Partial<VerificationExpectation> = {}): VerificationExpectation {
  return {
    audience: 'https://rp.example',
    action: 'post.edit',
    resource: 'post:01ABC',
    nonce: NONCE,
    now: NOW,
    maxClockSkewSeconds: 5,
    ...overrides,
  };
}

async function makeProof(
  identity: TestIdentity,
  overrides: Partial<OwnershipProofPayloadV1> = {},
): Promise<OwnershipProofV1> {
  const payload: OwnershipProofPayloadV1 = {
    protocol: OWNERSHIP_PROOF_PROTOCOL_V1,
    subject: identity.subject,
    genesis: identity.genesis,
    aud: 'https://rp.example',
    act: 'post.edit',
    resource: 'post:01ABC',
    nonce: NONCE,
    iat: NOW - 10,
    exp: NOW + 50,
    ...overrides,
  };
  return {
    payload,
    signature: encoded64(await signProtocolPayload(payload, identity.privateKey)),
  };
}

async function expectCode(
  operation: Promise<unknown>,
  code: NexusVerificationErrorCode,
): Promise<void> {
  await expect(operation).rejects.toMatchObject({
    name: 'NexusVerificationError',
    code,
  });
}

async function makeServiceKey(seed: number) {
  const provider = getDefaultCryptoProvider();
  const pair = await provider.generateEd25519KeyPair({
    privateKeyExtractable: true,
  });
  const raw = await provider.exportEd25519PublicKey(pair.publicKey);
  const kid = `registry-${seed}`;
  const keyset: ServiceKeySet = {
    keys: [
      {
        kty: 'OKP',
        crv: 'Ed25519',
        alg: 'EdDSA',
        kid,
        x: encoded32(raw),
        use: 'sig',
      },
    ],
  };
  return { pair, kid, keyset };
}

describe('verifySubject', () => {
  it('recomputes the subject and returns decoded public key material', async () => {
    const identity = await makeIdentity(1);
    const verified = await verifySubject(identity.genesis, identity.subject);
    expect(verified.subject).toBe(identity.subject);
    expect(verified.signingPublicKey).toHaveLength(32);
  });

  it('rejects an altered genesis or public key under the original subject', async () => {
    const [identity, other] = await Promise.all([makeIdentity(2), makeIdentity(3)]);
    const alteredCommitment = {
      ...identity.genesis,
      revocationCommitment: other.genesis.revocationCommitment,
    };
    const alteredKey = {
      ...identity.genesis,
      signingKey: other.genesis.signingKey,
    };

    await expectCode(verifySubject(alteredCommitment, identity.subject), 'INVALID_SUBJECT');
    await expectCode(verifySubject(alteredKey, identity.subject), 'INVALID_SUBJECT');
  });
});

describe('verifyOwnershipProof', () => {
  it('verifies a bound proof without consulting nonce or lifecycle state', async () => {
    const identity = await makeIdentity(4);
    const proof = await makeProof(identity);
    await expect(verifyOwnershipProof(proof, expectation())).resolves.toMatchObject({
      subject: identity.subject,
    });
  });

  it.each([
    ['audience', { audience: 'https://other.example' }, 'WRONG_AUDIENCE'],
    ['action', { action: 'post.delete' }, 'WRONG_ACTION'],
    ['resource', { resource: 'post:OTHER' }, 'WRONG_RESOURCE'],
    ['nonce', { nonce: encodedNonce(new Uint8Array(16).fill(8)) }, 'WRONG_NONCE'],
  ] as const)('rejects the wrong %s', async (_label, overrides, code) => {
    const identity = await makeIdentity(5);
    await expectCode(verifyOwnershipProof(await makeProof(identity), expectation(overrides)), code);
  });

  it('enforces expiry, future skew, ordering, and the 120 second maximum', async () => {
    const identity = await makeIdentity(6);
    await expectCode(
      verifyOwnershipProof(
        await makeProof(identity, { iat: NOW - 200, exp: NOW - 6 }),
        expectation(),
      ),
      'PROOF_LIFETIME_EXCEEDED',
    );
    await expectCode(
      verifyOwnershipProof(
        await makeProof(identity, { iat: NOW - 60, exp: NOW - 6 }),
        expectation(),
      ),
      'PROOF_EXPIRED',
    );
    await expectCode(
      verifyOwnershipProof(
        await makeProof(identity, { iat: NOW + 6, exp: NOW + 60 }),
        expectation(),
      ),
      'PROOF_NOT_YET_VALID',
    );
    await expectCode(
      verifyOwnershipProof(await makeProof(identity, { iat: NOW, exp: NOW + 121 }), expectation()),
      'PROOF_LIFETIME_EXCEEDED',
    );
    await expectCode(
      verifyOwnershipProof(
        {
          ...(await makeProof(identity)),
          payload: {
            ...(await makeProof(identity)).payload,
            iat: NOW + 1,
            exp: NOW,
          },
        },
        expectation(),
      ),
      'BAD_REQUEST',
    );
  });

  it('rejects tampering, malformed signatures, and padded base64url', async () => {
    const identity = await makeIdentity(7);
    const proof = await makeProof(identity);
    const altered = {
      ...proof,
      payload: { ...proof.payload, act: 'post.delete' },
    };
    await expectCode(
      verifyOwnershipProof(altered, expectation({ action: 'post.delete' })),
      'INVALID_SIGNATURE',
    );
    await expectCode(
      verifyOwnershipProof({ ...proof, signature: '***' }, expectation()),
      'BAD_REQUEST',
    );
    await expectCode(
      verifyOwnershipProof({ ...proof, signature: `${proof.signature}=` }, expectation()),
      'BAD_REQUEST',
    );
  });

  it('fails closed on unknown protocol and suite versions', async () => {
    const identity = await makeIdentity(8);
    const proof = await makeProof(identity);
    await expectCode(
      verifyOwnershipProof(
        {
          ...proof,
          payload: { ...proof.payload, protocol: 'nexus.ownership-proof.v2' },
        },
        expectation(),
      ),
      'UNSUPPORTED_PROTOCOL',
    );
    await expectCode(
      verifyOwnershipProof(
        {
          ...proof,
          payload: {
            ...proof.payload,
            genesis: { ...proof.payload.genesis, suite: 'NX-unknown' },
          },
        },
        expectation(),
      ),
      'UNSUPPORTED_SUITE',
    );
  });

  it('orchestrates challenge consumption and authoritative lifecycle checks', async () => {
    const identity = await makeIdentity(9);
    const proof = await makeProof(identity);
    let consumed = false;
    const store: ChallengeStore = {
      get() {
        return Promise.resolve({
          nonce: NONCE,
          action: 'post.edit',
          resource: 'post:01ABC',
          expiresAt: NOW + 60,
          consumed,
        });
      },
      consumeAtomically() {
        if (consumed) return Promise.resolve(false);
        consumed = true;
        return Promise.resolve(true);
      },
    };
    const active: LifecycleProvider = {
      getAuthoritativeStatus() {
        return Promise.resolve({ state: 'active', sequence: 0, registeredAt: NOW - 100 });
      },
    };

    await expect(verifyRpOperation(proof, expectation(), store, active)).resolves.toMatchObject({
      subject: identity.subject,
    });
    await expectCode(
      verifyRpOperation(proof, expectation(), store, active),
      'NONCE_REPLAY_OR_EXPIRED',
    );

    consumed = false;
    const revoked: LifecycleProvider = {
      getAuthoritativeStatus() {
        return Promise.resolve({
          state: 'revoked',
          sequence: 1,
          registeredAt: NOW - 100,
          revokedAt: NOW - 1,
        });
      },
    };
    await expectCode(verifyRpOperation(proof, expectation(), store, revoked), 'IDENTITY_REVOKED');
    expect(consumed).toBe(false);
  });
});

describe('revocation verification', () => {
  it('verifies signing-key revocation with exact subject, sequence, nonce, and time', async () => {
    const identity = await makeIdentity(10);
    const payload: RevokeBySignaturePayloadV1 = {
      protocol: REVOKE_PROTOCOL_V1,
      subject: identity.subject,
      expectedSequence: 0,
      nonce: NONCE,
      iat: NOW - 10,
      reasonCode: 'dispose',
    };
    const request = {
      mode: 'signature' as const,
      payload,
      signature: await signProtocolPayload(payload, identity.privateKey),
    };
    const expected = {
      subject: identity.subject,
      expectedSequence: 0,
      nonce: NONCE,
      now: NOW,
      maxClockSkewSeconds: 5,
    };

    await expect(
      verifyRevokeBySignature(request, identity.genesis, expected),
    ).resolves.toMatchObject({ subject: identity.subject });
    await expectCode(
      verifyRevokeBySignature(request, identity.genesis, {
        ...expected,
        nonce: encodedNonce(new Uint8Array(16).fill(9)),
      }),
      'WRONG_NONCE',
    );
    await expectCode(
      verifyRevokeBySignature(request, identity.genesis, {
        ...expected,
        expectedSequence: 1,
      }),
      'SEQUENCE_CONFLICT',
    );
  });

  it('rejects stale/future revocation signatures, tampering, and the wrong key', async () => {
    const [identity, other] = await Promise.all([makeIdentity(11), makeIdentity(12)]);
    const base: RevokeBySignaturePayloadV1 = {
      protocol: REVOKE_PROTOCOL_V1,
      subject: identity.subject,
      expectedSequence: 0,
      nonce: NONCE,
      iat: NOW - 121,
    };
    const expected = {
      subject: identity.subject,
      expectedSequence: 0,
      nonce: NONCE,
      now: NOW,
      maxClockSkewSeconds: 0,
    };
    await expectCode(
      verifyRevokeBySignature(
        {
          mode: 'signature',
          payload: base,
          signature: await signProtocolPayload(base, identity.privateKey),
        },
        identity.genesis,
        expected,
      ),
      'PROOF_EXPIRED',
    );
    const future = { ...base, iat: NOW + 1 };
    await expectCode(
      verifyRevokeBySignature(
        {
          mode: 'signature',
          payload: future,
          signature: await signProtocolPayload(future, identity.privateKey),
        },
        identity.genesis,
        expected,
      ),
      'PROOF_NOT_YET_VALID',
    );
    const current = { ...base, iat: NOW };
    await expectCode(
      verifyRevokeBySignature(
        {
          mode: 'signature',
          payload: current,
          signature: await signProtocolPayload(current, other.privateKey),
        },
        identity.genesis,
        expected,
      ),
      'INVALID_SIGNATURE',
    );
  });

  it('verifies the committed recovery secret and rejects a wrong secret', async () => {
    const identity = await makeIdentity(13);
    const request = {
      mode: 'secret' as const,
      payload: {
        protocol: REVOKE_SECRET_PROTOCOL_V1,
        subject: identity.subject,
        expectedSequence: 0,
        revocationSecret: encoded32(identity.revocationSecret),
      },
    };
    await expect(
      verifyRevocationSecret(request, identity.genesis, {
        subject: identity.subject,
        expectedSequence: 0,
      }),
    ).resolves.toMatchObject({ subject: identity.subject });

    await expectCode(
      verifyRevocationSecret(
        {
          ...request,
          payload: {
            ...request.payload,
            revocationSecret: encoded32(new Uint8Array(32).fill(99)),
          },
        },
        identity.genesis,
        { subject: identity.subject, expectedSequence: 0 },
      ),
      'INVALID_REVOCATION_SECRET',
    );
  });
});

describe('service-signed statements', () => {
  it('verifies registry receipts and rejects tampering, unknown keys, and wrong-purpose keys', async () => {
    const identity = await makeIdentity(14);
    const [service, unknownService] = await Promise.all([makeServiceKey(1), makeServiceKey(99)]);
    const payload: RegistryReceiptPayloadV1 = {
      protocol: REGISTRY_RECEIPT_PROTOCOL_V1,
      eventId: `nxe1_${encoded32(new Uint8Array(32).fill(1))}`,
      subject: identity.subject,
      genesisHash: encoded32(new Uint8Array(32).fill(2)),
      eventType: 'registered',
      sequence: 0,
      state: 'active',
      acceptedAt: NOW,
      signerKid: service.kid,
    };
    const receipt = {
      payload,
      signature: await signProtocolPayload(payload, service.pair.privateKey),
    };
    await expect(
      verifyRegistryReceipt(receipt, service.keyset, {
        subject: identity.subject,
        eventType: 'registered',
        sequence: 0,
        state: 'active',
      }),
    ).resolves.toEqual(receipt);

    await expectCode(
      verifyRegistryReceipt(
        { ...receipt, payload: { ...payload, acceptedAt: NOW + 1 } },
        service.keyset,
      ),
      'INVALID_SIGNATURE',
    );
    await expectCode(verifyRegistryReceipt(receipt, unknownService.keyset), 'KEY_NOT_FOUND');
    await expectCode(
      verifyRegistryReceipt(receipt, {
        keys: service.keyset.keys.map((key) => ({ ...key, use: 'enc' })),
      }),
      'KEY_PURPOSE_MISMATCH',
    );

    await expect(
      verifyRegistryReceipt(receipt, {
        keys: service.keyset.keys.map((key) => ({
          kty: key.kty,
          crv: key.crv,
          alg: key.alg,
          kid: key.kid,
          x: key.x,
        })),
      }),
    ).resolves.toEqual(receipt);
  });

  it('enforces status exp itself and rejects future statements and the wrong key', async () => {
    const identity = await makeIdentity(15);
    const [service, wrongService] = await Promise.all([makeServiceKey(2), makeServiceKey(3)]);
    const payload: StatusStatementPayloadV1 = {
      protocol: STATUS_STATEMENT_PROTOCOL_V1,
      subject: identity.subject,
      state: 'active',
      sequence: 0,
      registeredAt: NOW - 100,
      iat: NOW,
      exp: NOW + 60,
      signerKid: service.kid,
    };
    const statement = {
      payload,
      signature: await signProtocolPayload(payload, service.pair.privateKey),
    };
    await expect(
      verifyStatusStatement(statement, service.keyset, NOW, {
        subject: identity.subject,
      }),
    ).resolves.toEqual(statement);
    await expectCode(verifyStatusStatement(statement, service.keyset, NOW + 61), 'PROOF_EXPIRED');

    const futurePayload = { ...payload, iat: NOW + 6, exp: NOW + 66 };
    const future = {
      payload: futurePayload,
      signature: await signProtocolPayload(futurePayload, service.pair.privateKey),
    };
    await expectCode(
      verifyStatusStatement(future, service.keyset, NOW, {
        maxClockSkewSeconds: 5,
      }),
      'PROOF_NOT_YET_VALID',
    );
    await expectCode(
      verifyStatusStatement(
        statement,
        {
          keys: wrongService.keyset.keys.map((key) => ({
            ...key,
            kid: service.kid,
          })),
        },
        NOW,
      ),
      'INVALID_SIGNATURE',
    );
  });
});

describe('verifyContinuityLink', () => {
  it('requires exact expectations and valid signatures from both identities', async () => {
    const [identityA, identityB] = await Promise.all([makeIdentity(16), makeIdentity(17)]);
    const payload: ContinuityLinkPayloadV1 = {
      protocol: CONTINUITY_LINK_PROTOCOL_V1,
      subjectA: identityA.subject,
      genesisA: identityA.genesis,
      subjectB: identityB.subject,
      genesisB: identityB.genesis,
      scope: 'account:migration',
      iat: NOW,
      exp: NOW + 120,
      nonce: NONCE,
    };
    const link = {
      payload,
      signatureA: await signProtocolPayload(payload, identityA.privateKey),
      signatureB: await signProtocolPayload(payload, identityB.privateKey),
    };
    const expected = {
      nonce: NONCE,
      now: NOW,
      maxClockSkewSeconds: 0,
      subjectA: identityA.subject,
      subjectB: identityB.subject,
      scope: 'account:migration',
    };
    await expect(verifyContinuityLink(link, expected)).resolves.toEqual(link);

    await expectCode(
      verifyContinuityLink({ ...link, signatureA: link.signatureB }, expected),
      'INVALID_SIGNATURE',
    );
    await expectCode(
      verifyContinuityLink({ ...link, signatureB: link.signatureA }, expected),
      'INVALID_SIGNATURE',
    );
    await expectCode(
      verifyContinuityLink(link, {
        ...expected,
        nonce: encodedNonce(new Uint8Array(16).fill(18)),
      }),
      'WRONG_NONCE',
    );
    await expectCode(
      verifyContinuityLink(link, { ...expected, scope: 'account:other' }),
      'WRONG_SCOPE',
    );
  });

  it('rejects continuity payload tampering and invalid time windows', async () => {
    const [identityA, identityB] = await Promise.all([makeIdentity(18), makeIdentity(19)]);
    const payload: ContinuityLinkPayloadV1 = {
      protocol: CONTINUITY_LINK_PROTOCOL_V1,
      subjectA: identityA.subject,
      genesisA: identityA.genesis,
      subjectB: identityB.subject,
      genesisB: identityB.genesis,
      iat: NOW,
      exp: NOW + 121,
      nonce: NONCE,
    };
    const link = {
      payload,
      signatureA: await signProtocolPayload(payload, identityA.privateKey),
      signatureB: await signProtocolPayload(payload, identityB.privateKey),
    };
    await expectCode(
      verifyContinuityLink(link, {
        nonce: NONCE,
        now: NOW,
        maxClockSkewSeconds: 0,
      }),
      'PROOF_LIFETIME_EXCEEDED',
    );

    const validPayload = { ...payload, exp: NOW + 120 };
    const valid = {
      payload: validPayload,
      signatureA: await signProtocolPayload(validPayload, identityA.privateKey),
      signatureB: await signProtocolPayload(validPayload, identityB.privateKey),
    };
    await expectCode(
      verifyContinuityLink(
        {
          ...valid,
          payload: { ...valid.payload, nonce: encodedNonce(new Uint8Array(16).fill(20)) },
        },
        {
          nonce: encodedNonce(new Uint8Array(16).fill(20)),
          now: NOW,
          maxClockSkewSeconds: 0,
        },
      ),
      'INVALID_SIGNATURE',
    );
  });
});

describe('typed verifier errors', () => {
  it('exposes stable codes without leaking verification input', () => {
    const error = new NexusVerificationError('INVALID_REVOCATION_SECRET');
    expect(error).toBeInstanceOf(Error);
    expect(error.code).toBe('INVALID_REVOCATION_SECRET');
    expect(error.message).not.toContain('secret');
  });
});
