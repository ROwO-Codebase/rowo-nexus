import {
  DEVICE_AUTHORIZATION_PROTOCOL_V2,
  DEVICE_REGISTRY_RECEIPT_PROTOCOL_V2,
  DEVICE_STATUS_STATEMENT_PROTOCOL_V2,
  IDENTITY_PROTOCOL_V1,
  NEXUS_SUITE_V1,
  OWNERSHIP_PROOF_PROTOCOL_V1,
  OWNERSHIP_PROOF_PROTOCOL_V2,
  encodeBase64Url,
} from '@nexus/protocol';
import type {
  Base64Url32,
  Base64Url64,
  Base64UrlAtLeast16,
  DeviceAuthorizationPayloadV2,
  DeviceAuthorizationV2,
  DeviceStatusStatementPayloadV2,
  DeviceRegistryReceiptPayloadV2,
  IdentityGenesisV1,
  NexusSubject,
  OwnershipProofPayloadV2,
  OwnershipProofPayloadV1,
  OwnershipProofV1,
  OwnershipProofV2,
  ServiceKeySet,
  VerificationExpectationV2,
} from '@nexus/protocol';
import {
  computeRevocationCommitment,
  deriveDeviceAuthorizationIdV2,
  deriveDeviceIdV2,
  deriveGenesisHash,
  deriveSubject,
  getDefaultCryptoProvider,
  signProtocolPayload,
} from '@nexus/crypto';
import { describe, expect, it } from 'vitest';

import {
  NexusVerificationError,
  NexusVerificationErrorV2,
  verifyDeviceStatusStatement,
  verifyDeviceRegistryReceipt,
  verifyOwnershipProof,
  verifyOwnershipProofAny,
  verifyOwnershipProofV2,
  verifyRpOperationV2,
} from './index.js';
import type {
  ChallengeStore,
  DeviceLifecycleProvider,
  LifecycleProvider,
  NexusVerificationErrorCodeV2,
} from './index.js';

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

const NONCE = encodedNonce(new Uint8Array(16).fill(27));

interface TestV2Identity {
  genesis: IdentityGenesisV1;
  subject: NexusSubject;
  rootPrivateKey: CryptoKey;
  devicePrivateKey: CryptoKey;
  authorization: DeviceAuthorizationV2;
  authorizationId: Awaited<ReturnType<typeof deriveDeviceAuthorizationIdV2>>;
}

async function makeV2Identity(seed: number): Promise<TestV2Identity> {
  const provider = getDefaultCryptoProvider();
  const [root, device] = await Promise.all([
    provider.generateEd25519KeyPair({ privateKeyExtractable: true }),
    provider.generateEd25519KeyPair({ privateKeyExtractable: true }),
  ]);
  const [rootPublic, devicePublic] = await Promise.all([
    provider.exportEd25519PublicKey(root.publicKey),
    provider.exportEd25519PublicKey(device.publicKey),
  ]);
  const commitment = await computeRevocationCommitment(new Uint8Array(32).fill(seed));
  const genesis: IdentityGenesisV1 = {
    protocol: IDENTITY_PROTOCOL_V1,
    suite: NEXUS_SUITE_V1,
    signingKey: { alg: 'Ed25519', publicKey: encoded32(rootPublic) },
    revocationCommitment: encoded32(commitment),
  };
  const subject = await deriveSubject(genesis);
  const signingKey = { alg: 'Ed25519' as const, publicKey: encoded32(devicePublic) };
  const payload: DeviceAuthorizationPayloadV2 = {
    protocol: DEVICE_AUTHORIZATION_PROTOCOL_V2,
    subject,
    genesisHash: encoded32(await deriveGenesisHash(genesis)),
    deviceId: await deriveDeviceIdV2({ subject, signingKey }),
    signingKey,
    authorizationNonce: encoded32(new Uint8Array(32).fill(seed + 1)),
    validFrom: NOW - 1_000,
    activationDeadline: NOW + 1_000,
    expiresAt: NOW + 10_000,
  };
  const authorization: DeviceAuthorizationV2 = {
    payload,
    rootSignature: encoded64(await signProtocolPayload(payload, root.privateKey)),
  };
  return {
    genesis,
    subject,
    rootPrivateKey: root.privateKey,
    devicePrivateKey: device.privateKey,
    authorization,
    authorizationId: await deriveDeviceAuthorizationIdV2(payload),
  };
}

const CONTEXT_HASH = encoded32(new Uint8Array(32).fill(28));

function expectation(
  overrides: Partial<VerificationExpectationV2> = {},
): VerificationExpectationV2 {
  return {
    audience: 'https://rp.example',
    action: 'post.edit',
    resource: 'post:01ABC',
    nonce: NONCE,
    now: NOW,
    maxClockSkewSeconds: 5,
    contextHash: null,
    ...overrides,
  };
}

async function makeProof(
  identity: TestV2Identity,
  overrides: Partial<OwnershipProofPayloadV2> = {},
): Promise<OwnershipProofV2> {
  const payload: OwnershipProofPayloadV2 = {
    protocol: OWNERSHIP_PROOF_PROTOCOL_V2,
    subject: identity.subject,
    genesis: identity.genesis,
    deviceId: identity.authorization.payload.deviceId,
    authorizationId: identity.authorizationId,
    authorization: identity.authorization,
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
    deviceSignature: encoded64(await signProtocolPayload(payload, identity.devicePrivateKey)),
  };
}

async function makeV1Proof(
  identity: TestV2Identity,
  contextHash?: Base64Url32,
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
    ...(contextHash === undefined ? {} : { contextHash }),
  };
  return {
    payload,
    signature: encoded64(await signProtocolPayload(payload, identity.rootPrivateKey)),
  };
}

async function expectCode(
  operation: Promise<unknown>,
  code: NexusVerificationErrorCodeV2,
): Promise<void> {
  try {
    await operation;
    throw new Error('Expected verification to fail.');
  } catch (error) {
    expect(error).toBeInstanceOf(NexusVerificationError);
    if (error instanceof NexusVerificationErrorV2) {
      expect(error.codeV2).toBe(code);
      return;
    }
    if (error instanceof NexusVerificationError) {
      expect(error.code).toBe(code);
      return;
    }
    throw error;
  }
}

describe('v2 ownership verification', () => {
  it('verifies the root authorization and device proof chain', async () => {
    const identity = await makeV2Identity(31);
    const verified = await verifyOwnershipProofV2(await makeProof(identity), expectation());
    expect(verified).toMatchObject({
      protocol: OWNERSHIP_PROOF_PROTOCOL_V2,
      subject: identity.subject,
      deviceId: identity.authorization.payload.deviceId,
      authorizationId: identity.authorizationId,
    });
    expect(verified.rootSigningPublicKey).toBeInstanceOf(Uint8Array);
    expect(verified.deviceSigningPublicKey).toBeInstanceOf(Uint8Array);
  });

  it('keeps the legacy entry point v1-only and dispatches only explicitly accepted versions', async () => {
    const identity = await makeV2Identity(32);
    const proof = await makeProof(identity);
    await expectCode(verifyOwnershipProof(proof, expectation()), 'UNSUPPORTED_PROTOCOL');
    await expectCode(
      verifyOwnershipProofAny(proof, expectation(), {
        acceptedProtocols: [OWNERSHIP_PROOF_PROTOCOL_V1],
      }),
      'UNSUPPORTED_PROTOCOL',
    );
    await expect(
      verifyOwnershipProofAny(proof, expectation(), {
        acceptedProtocols: [OWNERSHIP_PROOF_PROTOCOL_V2],
      }),
    ).resolves.toMatchObject({ subject: identity.subject });
    await expectCode(
      verifyOwnershipProofAny(proof, expectation(), {
        acceptedProtocols: [OWNERSHIP_PROOF_PROTOCOL_V2, OWNERSHIP_PROOF_PROTOCOL_V2],
      }),
      'BAD_REQUEST',
    );
  });

  it('rejects root-certificate tampering and device-signature tampering independently', async () => {
    const identity = await makeV2Identity(33);
    const proof = await makeProof(identity);
    await expectCode(
      verifyOwnershipProofV2(
        {
          ...proof,
          payload: {
            ...proof.payload,
            authorization: {
              ...proof.payload.authorization,
              rootSignature: proof.deviceSignature,
            },
          },
        },
        expectation(),
      ),
      'INVALID_SIGNATURE',
    );
    await expectCode(
      verifyOwnershipProofV2(
        { ...proof, deviceSignature: proof.payload.authorization.rootSignature },
        expectation(),
      ),
      'INVALID_SIGNATURE',
    );
  });

  it('requires exact derived device and authorization identifiers', async () => {
    const identity = await makeV2Identity(34);
    const proof = await makeProof(identity);
    const wrongDevice = `nxd2_${encoded32(new Uint8Array(32).fill(99))}`;
    await expectCode(
      verifyOwnershipProofV2(
        {
          ...proof,
          payload: {
            ...proof.payload,
            deviceId: wrongDevice,
            authorization: {
              ...proof.payload.authorization,
              payload: { ...proof.payload.authorization.payload, deviceId: wrongDevice },
            },
          },
        },
        expectation(),
      ),
      'WRONG_DEVICE',
    );
    const wrongAuthorization = `nxa2_${encoded32(new Uint8Array(32).fill(98))}`;
    await expectCode(
      verifyOwnershipProofV2(
        { ...proof, payload: { ...proof.payload, authorizationId: wrongAuthorization } },
        expectation(),
      ),
      'WRONG_AUTHORIZATION',
    );
  });

  it('rejects an authorization that reuses the root signing key as its device key', async () => {
    const identity = await makeV2Identity(38);
    const signingKey = identity.genesis.signingKey;
    const payload: DeviceAuthorizationPayloadV2 = {
      ...identity.authorization.payload,
      signingKey,
      deviceId: await deriveDeviceIdV2({ subject: identity.subject, signingKey }),
    };
    const authorization: DeviceAuthorizationV2 = {
      payload,
      rootSignature: encoded64(await signProtocolPayload(payload, identity.rootPrivateKey)),
    };
    const authorizationId = await deriveDeviceAuthorizationIdV2(payload);
    const proof = await makeProof(identity, {
      deviceId: payload.deviceId,
      authorizationId,
      authorization,
    });
    const rootSignedProof = {
      ...proof,
      deviceSignature: encoded64(await signProtocolPayload(proof.payload, identity.rootPrivateKey)),
    };
    await expectCode(verifyOwnershipProofV2(rootSignedProof, expectation()), 'INVALID_KEY');
  });

  it('enforces explicit absent or exact context binding', async () => {
    const identity = await makeV2Identity(39);
    const unbound = await makeProof(identity);
    await expect(verifyOwnershipProofV2(unbound, expectation())).resolves.toMatchObject({
      subject: identity.subject,
    });
    await expectCode(
      verifyOwnershipProofV2(unbound, expectation({ contextHash: CONTEXT_HASH })),
      'WRONG_CONTEXT',
    );
    await expect(
      verifyOwnershipProofV2(unbound, expectation({ contextHash: CONTEXT_HASH })),
    ).rejects.toMatchObject({
      name: 'NexusVerificationErrorV2',
      code: 'WRONG_NONCE',
      codeV2: 'WRONG_CONTEXT',
    });

    const bound = await makeProof(identity, { contextHash: CONTEXT_HASH });
    await expect(
      verifyOwnershipProofV2(bound, expectation({ contextHash: CONTEXT_HASH })),
    ).resolves.toMatchObject({ subject: identity.subject });
    await expectCode(verifyOwnershipProofV2(bound, expectation()), 'WRONG_CONTEXT');
    await expectCode(
      verifyOwnershipProofV2(bound, {
        audience: 'https://rp.example',
        action: 'post.edit',
        resource: 'post:01ABC',
        nonce: NONCE,
        now: NOW,
        maxClockSkewSeconds: 5,
      } as VerificationExpectationV2),
      'BAD_REQUEST',
    );
  });

  it('enforces v2 context policy on v1 fallback to prevent downgrade bypass', async () => {
    const identity = await makeV2Identity(41);
    const unbound = await makeV1Proof(identity);
    const options = {
      acceptedProtocols: [OWNERSHIP_PROOF_PROTOCOL_V2, OWNERSHIP_PROOF_PROTOCOL_V1],
    } as const;
    await expect(verifyOwnershipProofAny(unbound, expectation(), options)).resolves.toMatchObject({
      subject: identity.subject,
    });
    await expectCode(
      verifyOwnershipProofAny(unbound, expectation({ contextHash: CONTEXT_HASH }), options),
      'WRONG_CONTEXT',
    );

    const bound = await makeV1Proof(identity, CONTEXT_HASH);
    await expect(
      verifyOwnershipProofAny(bound, expectation({ contextHash: CONTEXT_HASH }), options),
    ).resolves.toMatchObject({ subject: identity.subject });
    await expectCode(verifyOwnershipProofAny(bound, expectation(), options), 'WRONG_CONTEXT');

    // The direct legacy API remains deliberately context-agnostic.
    const expectedV2 = expectation();
    const legacyExpectation = {
      audience: expectedV2.audience,
      action: expectedV2.action,
      resource: expectedV2.resource,
      nonce: expectedV2.nonce,
      now: expectedV2.now,
      maxClockSkewSeconds: expectedV2.maxClockSkewSeconds,
    };
    await expect(verifyOwnershipProof(bound, legacyExpectation)).resolves.toMatchObject({
      subject: identity.subject,
    });
  });

  it('treats device authorization expiry as an exclusive boundary', async () => {
    const identity = await makeV2Identity(40);
    const payload: DeviceAuthorizationPayloadV2 = {
      ...identity.authorization.payload,
      activationDeadline: NOW,
      expiresAt: NOW,
    };
    const authorization: DeviceAuthorizationV2 = {
      payload,
      rootSignature: encoded64(await signProtocolPayload(payload, identity.rootPrivateKey)),
    };
    const authorizationId = await deriveDeviceAuthorizationIdV2(payload);
    const proof = await makeProof(identity, {
      authorization,
      authorizationId,
      iat: NOW - 10,
      exp: NOW,
    });
    await expectCode(verifyOwnershipProofV2(proof, expectation()), 'DEVICE_EXPIRED');
  });
});

describe('v2 RP orchestration', () => {
  it('requires exact active identity and device state before consuming the nonce', async () => {
    const identity = await makeV2Identity(35);
    const proof = await makeProof(identity);
    let consumed = false;
    const store: ChallengeStore = {
      get: () =>
        Promise.resolve({
          nonce: NONCE,
          action: 'post.edit',
          resource: 'post:01ABC',
          expiresAt: NOW + 60,
          consumed,
        }),
      consumeAtomically: () => {
        if (consumed) return Promise.resolve(false);
        consumed = true;
        return Promise.resolve(true);
      },
    };
    const lifecycle: LifecycleProvider = {
      getAuthoritativeStatus: () =>
        Promise.resolve({ state: 'active', sequence: 0, registeredAt: NOW - 100 }),
    };
    const activeDevice: DeviceLifecycleProvider = {
      getAuthoritativeDeviceStatus: () =>
        Promise.resolve({
          state: 'active',
          identityState: 'active',
          identitySequence: 0,
          deviceId: identity.authorization.payload.deviceId,
          authorizationId: identity.authorizationId,
          deviceLedgerSequence: 1,
          activatedAt: NOW - 100,
          authorizationExpiresAt: NOW + 10_000,
        }),
    };
    await expect(
      verifyRpOperationV2(proof, expectation(), store, lifecycle, activeDevice),
    ).resolves.toMatchObject({ subject: identity.subject });
    expect(consumed).toBe(true);

    consumed = false;
    const revokedDevice: DeviceLifecycleProvider = {
      getAuthoritativeDeviceStatus: () =>
        Promise.resolve({
          state: 'revoked',
          identityState: 'active',
          identitySequence: 0,
          deviceId: identity.authorization.payload.deviceId,
          authorizationId: identity.authorizationId,
          deviceLedgerSequence: 2,
          revokedAt: NOW - 1,
        }),
    };
    await expectCode(
      verifyRpOperationV2(proof, expectation(), store, lifecycle, revokedDevice),
      'DEVICE_REVOKED',
    );
    expect(consumed).toBe(false);

    const expiredAtBoundary: DeviceLifecycleProvider = {
      getAuthoritativeDeviceStatus: () =>
        Promise.resolve({
          state: 'active',
          identityState: 'active',
          identitySequence: 0,
          deviceId: identity.authorization.payload.deviceId,
          authorizationId: identity.authorizationId,
          deviceLedgerSequence: 2,
          activatedAt: NOW - 100,
          authorizationExpiresAt: NOW,
        }),
    };
    await expectCode(
      verifyRpOperationV2(proof, expectation(), store, lifecycle, expiredAtBoundary),
      'DEVICE_EXPIRED',
    );
    expect(consumed).toBe(false);
  });
});

describe('v2 signed device status', () => {
  it('verifies freshness, signature, and exact device bindings', async () => {
    const identity = await makeV2Identity(36);
    const provider = getDefaultCryptoProvider();
    const service = await provider.generateEd25519KeyPair({ privateKeyExtractable: true });
    const servicePublic = await provider.exportEd25519PublicKey(service.publicKey);
    const keyset: ServiceKeySet = {
      keys: [
        {
          kty: 'OKP',
          crv: 'Ed25519',
          alg: 'EdDSA',
          kid: 'device-registry-1',
          x: encoded32(servicePublic),
          use: 'sig',
        },
      ],
    };
    const payload: DeviceStatusStatementPayloadV2 = {
      protocol: DEVICE_STATUS_STATEMENT_PROTOCOL_V2,
      subject: identity.subject,
      genesisHash: identity.authorization.payload.genesisHash,
      identityState: 'active',
      identitySequence: 0,
      deviceLedgerSequence: 1,
      deviceId: identity.authorization.payload.deviceId,
      authorizationId: identity.authorizationId,
      deviceState: 'active',
      activatedAt: NOW - 100,
      authorizationExpiresAt: identity.authorization.payload.expiresAt,
      iat: NOW,
      exp: NOW + 30,
      signerKid: 'device-registry-1',
    };
    const statement = {
      payload,
      signature: encoded64(await signProtocolPayload(payload, service.privateKey)),
    };
    await expect(
      verifyDeviceStatusStatement(statement, keyset, NOW, {
        subject: identity.subject,
        genesisHash: identity.authorization.payload.genesisHash,
        deviceId: identity.authorization.payload.deviceId,
        authorizationId: identity.authorizationId,
        identityState: 'active',
        identitySequence: 0,
        deviceLedgerSequence: 1,
        deviceState: 'active',
        authorizationExpiresAt: identity.authorization.payload.expiresAt,
      }),
    ).resolves.toEqual(statement);
    await expectCode(verifyDeviceStatusStatement(statement, keyset, NOW + 31), 'PROOF_EXPIRED');

    const boundaryPayload: DeviceStatusStatementPayloadV2 = {
      ...payload,
      authorizationExpiresAt: NOW,
    };
    const boundary = {
      payload: boundaryPayload,
      signature: encoded64(await signProtocolPayload(boundaryPayload, service.privateKey)),
    };
    await expectCode(verifyDeviceStatusStatement(boundary, keyset, NOW), 'DEVICE_EXPIRED');
  });

  it('verifies device registry receipts and their exact expected transition', async () => {
    const identity = await makeV2Identity(37);
    const provider = getDefaultCryptoProvider();
    const service = await provider.generateEd25519KeyPair({ privateKeyExtractable: true });
    const servicePublic = await provider.exportEd25519PublicKey(service.publicKey);
    const keyset: ServiceKeySet = {
      keys: [
        {
          kty: 'OKP',
          crv: 'Ed25519',
          alg: 'EdDSA',
          kid: 'device-registry-2',
          x: encoded32(servicePublic),
          use: 'sig',
        },
      ],
    };
    const payload: DeviceRegistryReceiptPayloadV2 = {
      protocol: DEVICE_REGISTRY_RECEIPT_PROTOCOL_V2,
      eventId: `nxde2_${encoded32(new Uint8Array(32).fill(3))}`,
      operationId: `nxo2_${encoded32(new Uint8Array(32).fill(4))}`,
      eventType: 'activated',
      subject: identity.subject,
      genesisHash: identity.authorization.payload.genesisHash,
      identitySequence: 0,
      identityState: 'active',
      deviceLedgerSequence: 1,
      deviceId: identity.authorization.payload.deviceId,
      authorizationId: identity.authorizationId,
      deviceState: 'active',
      authorizationExpiresAt: identity.authorization.payload.expiresAt,
      acceptedAt: NOW,
      signerKid: 'device-registry-2',
    };
    const receipt = {
      payload,
      signature: encoded64(await signProtocolPayload(payload, service.privateKey)),
    };
    await expect(
      verifyDeviceRegistryReceipt(receipt, keyset, {
        operationId: payload.operationId,
        subject: identity.subject,
        genesisHash: identity.authorization.payload.genesisHash,
        eventType: 'activated',
        identityState: 'active',
        identitySequence: 0,
        deviceLedgerSequence: 1,
        deviceId: identity.authorization.payload.deviceId,
        authorizationId: identity.authorizationId,
        deviceState: 'active',
      }),
    ).resolves.toEqual(receipt);
    await expectCode(
      verifyDeviceRegistryReceipt(receipt, keyset, { eventType: 'revoked' }),
      'WRONG_EVENT_TYPE',
    );
    await expectCode(
      verifyDeviceRegistryReceipt(
        { ...receipt, payload: { ...receipt.payload, acceptedAt: NOW + 1 } },
        keyset,
      ),
      'INVALID_SIGNATURE',
    );
  });
});
