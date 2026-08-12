import { mkdir, writeFile } from 'node:fs/promises';

import {
  concatBytes,
  computeRevocationCommitment,
  createGenesisHashPreimage,
  createProtocolSignaturePreimage,
  createRegistryEventHashPreimage,
  createRevocationCommitmentPreimage,
  deriveDeviceAuthorizationIdV2,
  deriveDeviceIdV2,
  deriveDeviceOperationIdV2,
  deriveDeviceRegistryEventIdV2,
  deriveGenesisHash,
  deriveRegistryEventId,
  deriveSubject,
  getDefaultCryptoProvider,
  signProtocolPayload,
  utf8Encode,
} from '@nexus/crypto';
import {
  CONTINUITY_LINK_PROTOCOL_V1,
  DEVICE_ACTIVATION_PROTOCOL_V2,
  DEVICE_AUTHORIZATION_PROTOCOL_V2,
  DEVICE_REGISTRY_EVENT_PROTOCOL_V2,
  DEVICE_REGISTRY_RECEIPT_PROTOCOL_V2,
  DEVICE_STATUS_STATEMENT_PROTOCOL_V2,
  ED25519_ALGORITHM,
  EDDSA_JWK_ALGORITHM,
  IDENTITY_PROTOCOL_V1,
  NEXUS_SUITE_V1,
  OWNERSHIP_PROOF_PROTOCOL_V1,
  OWNERSHIP_PROOF_PROTOCOL_V2,
  REGISTRY_EVENT_PROTOCOL_V1,
  REGISTRY_RECEIPT_PROTOCOL_V1,
  REVOKE_PROTOCOL_V1,
  STATUS_STATEMENT_PROTOCOL_V1,
  TRANSPARENCY_CHECKPOINT_PROTOCOL_V1,
  TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1,
  TRANSPARENCY_INCLUSION_PROOF_PROTOCOL_V1,
  X25519_ALGORITHM,
  canonicalize,
  createDeviceAuthorizationHashPreimageV2,
  createDeviceIdHashPreimageV2,
  createDeviceOperationHashPreimageV2,
  createDeviceRegistryEventHashPreimageV2,
  createGlobalTransparencyCheckpointSignaturePreimage,
  createTransparencyCheckpointSignaturePreimage,
  encodeBase64Url,
  deviceActivationPayloadV2Schema,
  deviceAuthorizationPayloadV2Schema,
  deviceAuthorizationV2Schema,
  deviceIdInputV2Schema,
  deviceRegistryEventWithoutEventIdV2Schema,
  deviceRegistryReceiptPayloadV2Schema,
  deviceStatusStatementPayloadV2Schema,
  identityGenesisV1Schema,
  ownershipProofPayloadV2Schema,
  registryEventWithoutEventIdV1Schema,
  signedGlobalTransparencyCheckpointV1Schema,
  signedTransparencyCheckpointV1Schema,
} from '@nexus/protocol';
import type {
  ContinuityLinkPayloadV1,
  DeviceRegistryEventV2,
  DeviceRegistryReceiptPayloadV2,
  DeviceStatusStatementPayloadV2,
  Ed25519PublicJwk,
  GlobalCheckpointShardV1,
  GlobalTransparencyCheckpointPayloadV1,
  IdentityGenesisV1,
  OwnershipProofPayloadV1,
  OwnershipProofPayloadV2,
  RegistryReceiptPayloadV1,
  RevokeBySignaturePayloadV1,
  StatusStatementPayloadV1,
  TransparencyCheckpointPayloadV1,
  TransparencyInclusionProofV1,
} from '@nexus/protocol';
import { format } from 'prettier';

import { bytesFromHex, bytesToHex } from './encoding.js';
import {
  ED25519_FIXTURES,
  FIXTURE_WARNING,
  REVOCATION_SECRET_A_HEX,
  REVOCATION_SECRET_B_HEX,
  VECTOR_TIMES,
  X25519_PUBLIC_KEY_A_HEX,
  X25519_PUBLIC_KEY_B_HEX,
} from './fixtures.js';

const VECTOR_SCHEMA = 'nexus.test-vectors.v1';
const VECTOR_SCHEMA_V2 = 'nexus.test-vectors.v2';
const SERVICE_KEY_ID = 'registry-fixture-2026-01';
const TRANSPARENCY_KEY_ID = 'transparency-fixture-2026-01';

async function importFixturePrivateKey(pkcs8Hex: string): Promise<CryptoKey> {
  return getDefaultCryptoProvider().importEd25519PrivateKey(bytesFromHex(pkcs8Hex));
}

async function hashTransparencyLeaf(eventHash: Uint8Array): Promise<Uint8Array> {
  return getDefaultCryptoProvider().sha256(concatBytes(Uint8Array.of(0x00), eventHash));
}

async function hashTransparencyNode(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return getDefaultCryptoProvider().sha256(concatBytes(Uint8Array.of(0x01), left, right));
}

function signedPayloadFields<T extends { readonly protocol: string }>(
  payload: T,
  signatureBase64Url: string,
): Readonly<Record<string, unknown>> {
  return {
    canonicalPayloadJcs: canonicalize(payload),
    signaturePreimageHex: bytesToHex(createProtocolSignaturePreimage(payload)),
    signatureBase64Url,
  };
}

async function buildIdentity(
  publicKeyHex: string,
  agreementKeyHex: string,
  revocationSecretHex: string,
): Promise<{
  readonly genesis: IdentityGenesisV1;
  readonly genesisHash: Uint8Array;
  readonly subject: string;
  readonly commitment: Uint8Array;
}> {
  const commitment = await computeRevocationCommitment(bytesFromHex(revocationSecretHex));
  const genesis = identityGenesisV1Schema.parse({
    protocol: IDENTITY_PROTOCOL_V1,
    suite: NEXUS_SUITE_V1,
    signingKey: {
      alg: ED25519_ALGORITHM,
      publicKey: encodeBase64Url(bytesFromHex(publicKeyHex)),
    },
    agreementKey: {
      alg: X25519_ALGORITHM,
      publicKey: encodeBase64Url(bytesFromHex(agreementKeyHex)),
    },
    revocationCommitment: encodeBase64Url(commitment),
  });
  const genesisHash = await deriveGenesisHash(genesis);
  return {
    genesis,
    genesisHash,
    subject: await deriveSubject(genesis),
    commitment,
  };
}

export async function buildTestVectorFiles(): Promise<ReadonlyMap<string, string>> {
  const [
    privateKeyA,
    privateKeyB,
    servicePrivateKey,
    transparencyPrivateKey,
    identityA,
    identityB,
  ] = await Promise.all([
    importFixturePrivateKey(ED25519_FIXTURES.identityA.pkcs8Hex),
    importFixturePrivateKey(ED25519_FIXTURES.identityB.pkcs8Hex),
    importFixturePrivateKey(ED25519_FIXTURES.serviceRegistry.pkcs8Hex),
    importFixturePrivateKey(ED25519_FIXTURES.serviceTransparency.pkcs8Hex),
    buildIdentity(
      ED25519_FIXTURES.identityA.publicKeyHex,
      X25519_PUBLIC_KEY_A_HEX,
      REVOCATION_SECRET_A_HEX,
    ),
    buildIdentity(
      ED25519_FIXTURES.identityB.publicKeyHex,
      X25519_PUBLIC_KEY_B_HEX,
      REVOCATION_SECRET_B_HEX,
    ),
  ]);

  const servicePublicKeyBase64Url = encodeBase64Url(
    bytesFromHex(ED25519_FIXTURES.serviceRegistry.publicKeyHex),
  );
  const serviceJwk: Ed25519PublicJwk = {
    kty: 'OKP',
    crv: ED25519_ALGORITHM,
    alg: EDDSA_JWK_ALGORITHM,
    kid: SERVICE_KEY_ID,
    x: servicePublicKeyBase64Url as Ed25519PublicJwk['x'],
    use: 'sig',
  };
  const transparencyJwk: Ed25519PublicJwk = {
    kty: 'OKP',
    crv: ED25519_ALGORITHM,
    alg: EDDSA_JWK_ALGORITHM,
    kid: TRANSPARENCY_KEY_ID,
    x: encodeBase64Url(
      bytesFromHex(ED25519_FIXTURES.serviceTransparency.publicKeyHex),
    ) as Ed25519PublicJwk['x'],
    use: 'sig',
  };

  const ownershipPayload: OwnershipProofPayloadV1 = {
    protocol: OWNERSHIP_PROOF_PROTOCOL_V1,
    subject: identityA.subject as OwnershipProofPayloadV1['subject'],
    genesis: identityA.genesis,
    aud: 'https://rp.example',
    act: 'resource.create',
    resource: 'urn:example:resource:alpha',
    nonce: encodeBase64Url(
      bytesFromHex('101112131415161718191a1b1c1d1e1f'),
    ) as OwnershipProofPayloadV1['nonce'],
    iat: VECTOR_TIMES.issuedAt,
    exp: VECTOR_TIMES.issuedAt + 60,
    contextHash: encodeBase64Url(
      await getDefaultCryptoProvider().sha256(utf8Encode('fixture-context')),
    ) as OwnershipProofPayloadV1['contextHash'],
  };
  const ownershipSignature = await signProtocolPayload(ownershipPayload, privateKeyA);

  // v2 is an additive delegation layer anchored to the unchanged v1 genesis.
  // The RFC 8032 TEST 2 key is used only as the deterministic device key.
  const deviceSigningKey = {
    alg: ED25519_ALGORITHM,
    publicKey: encodeBase64Url(bytesFromHex(ED25519_FIXTURES.identityB.publicKeyHex)),
  } as const;
  const deviceIdInput = deviceIdInputV2Schema.parse({
    subject: identityA.subject,
    signingKey: deviceSigningKey,
  });
  const deviceId = await deriveDeviceIdV2(deviceIdInput);
  const deviceAuthorizationPayload = deviceAuthorizationPayloadV2Schema.parse({
    protocol: DEVICE_AUTHORIZATION_PROTOCOL_V2,
    ...deviceIdInput,
    genesisHash: encodeBase64Url(identityA.genesisHash),
    deviceId,
    authorizationNonce: encodeBase64Url(
      bytesFromHex('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),
    ),
    validFrom: VECTOR_TIMES.issuedAt,
    activationDeadline: VECTOR_TIMES.issuedAt + 3_600,
    expiresAt: VECTOR_TIMES.issuedAt + 86_400,
  });
  const deviceRootSignature = await signProtocolPayload(deviceAuthorizationPayload, privateKeyA);
  const deviceAuthorization = deviceAuthorizationV2Schema.parse({
    payload: deviceAuthorizationPayload,
    rootSignature: deviceRootSignature,
  });
  const deviceAuthorizationId = await deriveDeviceAuthorizationIdV2(deviceAuthorizationPayload);

  const deviceActivationPayload = deviceActivationPayloadV2Schema.parse({
    protocol: DEVICE_ACTIVATION_PROTOCOL_V2,
    subject: identityA.subject,
    deviceId,
    authorizationId: deviceAuthorizationId,
    requestId: encodeBase64Url(
      bytesFromHex('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'),
    ),
    iat: VECTOR_TIMES.issuedAt + 10,
    exp: VECTOR_TIMES.issuedAt + 70,
  });
  const deviceActivationSignature = await signProtocolPayload(deviceActivationPayload, privateKeyB);
  const deviceOperationId = await deriveDeviceOperationIdV2(deviceActivationPayload);
  const deviceActionHash = await getDefaultCryptoProvider().sha256(
    createProtocolSignaturePreimage(deviceActivationPayload),
  );
  const deviceRegistryEventWithoutEventId = deviceRegistryEventWithoutEventIdV2Schema.parse({
    protocol: DEVICE_REGISTRY_EVENT_PROTOCOL_V2,
    operationId: deviceOperationId,
    eventType: 'activated',
    subject: identityA.subject,
    genesisHash: encodeBase64Url(identityA.genesisHash),
    identitySequence: 0,
    identityState: 'active',
    deviceLedgerSequence: 1,
    deviceId,
    authorizationId: deviceAuthorizationId,
    deviceState: 'active',
    authorizationExpiresAt: deviceAuthorizationPayload.expiresAt,
    acceptedAt: VECTOR_TIMES.registeredAt + 10,
    actionHash: encodeBase64Url(deviceActionHash),
  });
  const deviceRegistryEventIdentity = await deriveDeviceRegistryEventIdV2(
    deviceRegistryEventWithoutEventId,
  );
  const deviceRegistryEvent: DeviceRegistryEventV2 = {
    ...deviceRegistryEventWithoutEventId,
    eventId: deviceRegistryEventIdentity.eventId,
  };

  const deviceRegistryReceiptPayload: DeviceRegistryReceiptPayloadV2 =
    deviceRegistryReceiptPayloadV2Schema.parse({
      protocol: DEVICE_REGISTRY_RECEIPT_PROTOCOL_V2,
      eventId: deviceRegistryEventIdentity.eventId,
      operationId: deviceOperationId,
      eventType: deviceRegistryEvent.eventType,
      subject: deviceRegistryEvent.subject,
      genesisHash: deviceRegistryEvent.genesisHash,
      identitySequence: deviceRegistryEvent.identitySequence,
      identityState: deviceRegistryEvent.identityState,
      deviceLedgerSequence: deviceRegistryEvent.deviceLedgerSequence,
      deviceId,
      authorizationId: deviceAuthorizationId,
      deviceState: deviceRegistryEvent.deviceState,
      authorizationExpiresAt: deviceAuthorizationPayload.expiresAt,
      acceptedAt: deviceRegistryEvent.acceptedAt,
      signerKid: SERVICE_KEY_ID,
    });
  const deviceRegistryReceiptSignature = await signProtocolPayload(
    deviceRegistryReceiptPayload,
    servicePrivateKey,
  );

  const deviceStatusStatementPayload: DeviceStatusStatementPayloadV2 =
    deviceStatusStatementPayloadV2Schema.parse({
      protocol: DEVICE_STATUS_STATEMENT_PROTOCOL_V2,
      subject: identityA.subject,
      genesisHash: encodeBase64Url(identityA.genesisHash),
      identityState: 'active',
      identitySequence: 0,
      deviceLedgerSequence: 1,
      deviceId,
      authorizationId: deviceAuthorizationId,
      deviceState: 'active',
      activatedAt: deviceRegistryEvent.acceptedAt,
      authorizationExpiresAt: deviceAuthorizationPayload.expiresAt,
      iat: deviceRegistryEvent.acceptedAt + 1,
      exp: deviceRegistryEvent.acceptedAt + 61,
      signerKid: SERVICE_KEY_ID,
    });
  const deviceStatusStatementSignature = await signProtocolPayload(
    deviceStatusStatementPayload,
    servicePrivateKey,
  );

  const ownershipPayloadV2: OwnershipProofPayloadV2 = ownershipProofPayloadV2Schema.parse({
    protocol: OWNERSHIP_PROOF_PROTOCOL_V2,
    subject: identityA.subject,
    genesis: identityA.genesis,
    deviceId,
    authorizationId: deviceAuthorizationId,
    authorization: deviceAuthorization,
    aud: 'https://rp.example',
    act: 'resource.create',
    resource: 'urn:example:resource:alpha',
    nonce: encodeBase64Url(bytesFromHex('808182838485868788898a8b8c8d8e8f')),
    iat: VECTOR_TIMES.issuedAt + 20,
    exp: VECTOR_TIMES.issuedAt + 80,
    contextHash: encodeBase64Url(
      await getDefaultCryptoProvider().sha256(utf8Encode('fixture-context-v2')),
    ),
  });
  const ownershipSignatureV2 = await signProtocolPayload(ownershipPayloadV2, privateKeyB);

  const registrationActionHash = await getDefaultCryptoProvider().sha256(
    utf8Encode('nexus-test-vector:registration-action'),
  );
  const registryEventWithoutEventId = registryEventWithoutEventIdV1Schema.parse({
    protocol: REGISTRY_EVENT_PROTOCOL_V1,
    eventType: 'registered',
    subject: identityA.subject,
    genesisHash: encodeBase64Url(identityA.genesisHash),
    sequence: 0,
    state: 'active',
    acceptedAt: VECTOR_TIMES.registeredAt,
    actionHash: encodeBase64Url(registrationActionHash),
  });
  const registryEventIdentity = await deriveRegistryEventId(registryEventWithoutEventId);

  const [firstEventHash, thirdEventHash, emptyTransparencyRoot] = await Promise.all([
    getDefaultCryptoProvider().sha256(utf8Encode('nexus-test-vector:transparency-event-0')),
    getDefaultCryptoProvider().sha256(utf8Encode('nexus-test-vector:transparency-event-2')),
    getDefaultCryptoProvider().sha256(new Uint8Array()),
  ]);
  const [firstLeafHash, targetLeafHash, thirdLeafHash] = await Promise.all([
    hashTransparencyLeaf(firstEventHash),
    hashTransparencyLeaf(registryEventIdentity.eventHash),
    hashTransparencyLeaf(thirdEventHash),
  ]);
  const leftTransparencyRoot = await hashTransparencyNode(firstLeafHash, targetLeafHash);
  const transparencyRoot = await hashTransparencyNode(leftTransparencyRoot, thirdLeafHash);
  const transparencyShardId = bytesToHex(registryEventIdentity.eventHash).slice(0, 2);
  const transparencyCheckpointPayload: TransparencyCheckpointPayloadV1 = {
    protocol: TRANSPARENCY_CHECKPOINT_PROTOCOL_V1,
    shardId: transparencyShardId,
    treeSize: 3,
    rootHash: encodeBase64Url(transparencyRoot) as TransparencyCheckpointPayloadV1['rootHash'],
    checkpointedAt: VECTOR_TIMES.registeredAt + 20,
    signerKid: TRANSPARENCY_KEY_ID,
  };
  const transparencyCheckpointSignature = await signProtocolPayload(
    transparencyCheckpointPayload,
    transparencyPrivateKey,
  );
  const signedTransparencyCheckpoint = signedTransparencyCheckpointV1Schema.parse({
    payload: transparencyCheckpointPayload,
    signature: transparencyCheckpointSignature,
  });
  const globalShards: GlobalCheckpointShardV1[] = Array.from({ length: 256 }, (_, index) => {
    const shardId = index.toString(16).padStart(2, '0');
    return shardId === transparencyShardId
      ? {
          shardId,
          treeSize: transparencyCheckpointPayload.treeSize,
          rootHash: transparencyCheckpointPayload.rootHash,
        }
      : {
          shardId,
          treeSize: 0,
          rootHash: encodeBase64Url(emptyTransparencyRoot) as GlobalCheckpointShardV1['rootHash'],
        };
  });
  const globalTransparencyPayload: GlobalTransparencyCheckpointPayloadV1 = {
    protocol: TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1,
    checkpointedAt: transparencyCheckpointPayload.checkpointedAt + 1,
    shards: globalShards,
    signerKid: TRANSPARENCY_KEY_ID,
  };
  const globalTransparencySignature = await signProtocolPayload(
    globalTransparencyPayload,
    transparencyPrivateKey,
  );
  const signedGlobalTransparencyCheckpoint = signedGlobalTransparencyCheckpointV1Schema.parse({
    payload: globalTransparencyPayload,
    signature: globalTransparencySignature,
  });
  const transparencyInclusionProof: TransparencyInclusionProofV1 = {
    protocol: TRANSPARENCY_INCLUSION_PROOF_PROTOCOL_V1,
    eventHash: encodeBase64Url(
      registryEventIdentity.eventHash,
    ) as TransparencyInclusionProofV1['eventHash'],
    shardId: transparencyShardId,
    leafIndex: 1,
    treeSize: 3,
    auditPath: [firstLeafHash, thirdLeafHash].map(
      (hash) => encodeBase64Url(hash) as TransparencyInclusionProofV1['auditPath'][number],
    ),
    checkpoint: signedTransparencyCheckpoint,
  };

  const registryReceiptPayload: RegistryReceiptPayloadV1 = {
    protocol: REGISTRY_RECEIPT_PROTOCOL_V1,
    eventId: registryEventIdentity.eventId,
    subject: registryEventWithoutEventId.subject,
    genesisHash: registryEventWithoutEventId.genesisHash,
    eventType: registryEventWithoutEventId.eventType,
    sequence: registryEventWithoutEventId.sequence,
    state: registryEventWithoutEventId.state,
    acceptedAt: registryEventWithoutEventId.acceptedAt,
    signerKid: SERVICE_KEY_ID,
  };
  const registryReceiptSignature = await signProtocolPayload(
    registryReceiptPayload,
    servicePrivateKey,
  );

  const statusStatementPayload: StatusStatementPayloadV1 = {
    protocol: STATUS_STATEMENT_PROTOCOL_V1,
    subject: registryEventWithoutEventId.subject,
    state: 'active',
    sequence: 0,
    registeredAt: VECTOR_TIMES.registeredAt,
    iat: VECTOR_TIMES.registeredAt + 1,
    exp: VECTOR_TIMES.registeredAt + 61,
    signerKid: SERVICE_KEY_ID,
  };
  const statusStatementSignature = await signProtocolPayload(
    statusStatementPayload,
    servicePrivateKey,
  );

  const signingKeyRevokePayload: RevokeBySignaturePayloadV1 = {
    protocol: REVOKE_PROTOCOL_V1,
    subject: registryEventWithoutEventId.subject,
    expectedSequence: 0,
    nonce: encodeBase64Url(
      bytesFromHex('202122232425262728292a2b2c2d2e2f'),
    ) as RevokeBySignaturePayloadV1['nonce'],
    iat: VECTOR_TIMES.revokeIssuedAt,
    reasonCode: 'dispose',
  };
  const signingKeyRevokeSignature = await signProtocolPayload(signingKeyRevokePayload, privateKeyA);

  const continuityLinkPayload: ContinuityLinkPayloadV1 = {
    protocol: CONTINUITY_LINK_PROTOCOL_V1,
    subjectA: identityA.subject as ContinuityLinkPayloadV1['subjectA'],
    genesisA: identityA.genesis,
    subjectB: identityB.subject as ContinuityLinkPayloadV1['subjectB'],
    genesisB: identityB.genesis,
    scope: 'rp.example:portfolio',
    iat: VECTOR_TIMES.continuityIssuedAt,
    exp: VECTOR_TIMES.continuityIssuedAt + 60,
    nonce: encodeBase64Url(
      bytesFromHex('303132333435363738393a3b3c3d3e3f4041424344454647'),
    ) as ContinuityLinkPayloadV1['nonce'],
  };
  const [continuitySignatureA, continuitySignatureB] = await Promise.all([
    signProtocolPayload(continuityLinkPayload, privateKeyA),
    signProtocolPayload(continuityLinkPayload, privateKeyB),
  ]);

  const keys = {
    schema: VECTOR_SCHEMA,
    warning: FIXTURE_WARNING,
    fixtures: Object.values(ED25519_FIXTURES).map((fixture) => ({
      id: fixture.id,
      source: fixture.rfc8032Section,
      seedHex: fixture.seedHex,
      privateKeyPkcs8Hex: fixture.pkcs8Hex,
      privateKeyPkcs8Base64Url: encodeBase64Url(bytesFromHex(fixture.pkcs8Hex)),
      publicKeyHex: fixture.publicKeyHex,
      publicKeyBase64Url: encodeBase64Url(bytesFromHex(fixture.publicKeyHex)),
    })),
  };

  const revocationCommitment = {
    schema: VECTOR_SCHEMA,
    warning: FIXTURE_WARNING,
    secretHex: REVOCATION_SECRET_A_HEX,
    commitmentPreimageHex: bytesToHex(
      createRevocationCommitmentPreimage(bytesFromHex(REVOCATION_SECRET_A_HEX)),
    ),
    commitmentHex: bytesToHex(identityA.commitment),
    commitmentBase64Url: encodeBase64Url(identityA.commitment),
  };

  const identity = {
    schema: VECTOR_SCHEMA,
    genesis: identityA.genesis,
    genesisJcs: canonicalize(identityA.genesis),
    genesisJcsUtf8Hex: bytesToHex(utf8Encode(canonicalize(identityA.genesis))),
    genesisHashPreimageHex: bytesToHex(createGenesisHashPreimage(identityA.genesis)),
    genesisHashHex: bytesToHex(identityA.genesisHash),
    genesisHashBase64Url: encodeBase64Url(identityA.genesisHash),
    subject: identityA.subject,
  };

  const ownershipProof = {
    schema: VECTOR_SCHEMA,
    signingKeyId: ED25519_FIXTURES.identityA.id,
    signingPublicKeyBase64Url: encodeBase64Url(
      bytesFromHex(ED25519_FIXTURES.identityA.publicKeyHex),
    ),
    payload: ownershipPayload,
    ...signedPayloadFields(ownershipPayload, ownershipSignature),
    proof: { payload: ownershipPayload, signature: ownershipSignature },
  };

  const deviceAuthorizationVector = {
    schema: VECTOR_SCHEMA_V2,
    warning: FIXTURE_WARNING,
    rootSigningKeyId: ED25519_FIXTURES.identityA.id,
    deviceSigningKeyId: ED25519_FIXTURES.identityB.id,
    identityGenesisProtocol: identityA.genesis.protocol,
    genesis: identityA.genesis,
    genesisHashBase64Url: encodeBase64Url(identityA.genesisHash),
    deviceIdInput,
    canonicalDeviceIdInputJcs: canonicalize(deviceIdInput),
    deviceIdHashPreimageHex: bytesToHex(createDeviceIdHashPreimageV2(deviceIdInput)),
    deviceId,
    payload: deviceAuthorizationPayload,
    authorizationIdHashPreimageHex: bytesToHex(
      createDeviceAuthorizationHashPreimageV2(deviceAuthorizationPayload),
    ),
    authorizationId: deviceAuthorizationId,
    ...signedPayloadFields(deviceAuthorizationPayload, deviceRootSignature),
    authorization: deviceAuthorization,
  };

  const deviceActivationVector = {
    schema: VECTOR_SCHEMA_V2,
    warning: FIXTURE_WARNING,
    deviceSigningKeyId: ED25519_FIXTURES.identityB.id,
    authorizationId: deviceAuthorizationId,
    payload: deviceActivationPayload,
    operationIdHashPreimageHex: bytesToHex(
      createDeviceOperationHashPreimageV2(deviceActivationPayload),
    ),
    operationId: deviceOperationId,
    ...signedPayloadFields(deviceActivationPayload, deviceActivationSignature),
    request: {
      authorization: deviceAuthorization,
      payload: deviceActivationPayload,
      deviceSignature: deviceActivationSignature,
    },
  };

  const ownershipProofV2 = {
    schema: VECTOR_SCHEMA_V2,
    warning: FIXTURE_WARNING,
    rootSigningKeyId: ED25519_FIXTURES.identityA.id,
    deviceSigningKeyId: ED25519_FIXTURES.identityB.id,
    payload: ownershipPayloadV2,
    ...signedPayloadFields(ownershipPayloadV2, ownershipSignatureV2),
    proof: {
      payload: ownershipPayloadV2,
      deviceSignature: ownershipSignatureV2,
    },
    verification: {
      audience: ownershipPayloadV2.aud,
      action: ownershipPayloadV2.act,
      resource: ownershipPayloadV2.resource,
      nonce: ownershipPayloadV2.nonce,
      now: ownershipPayloadV2.iat,
      maxClockSkewSeconds: 0,
    },
  };

  const deviceRegistryEventVector = {
    schema: VECTOR_SCHEMA_V2,
    warning: FIXTURE_WARNING,
    operationPayload: deviceActivationPayload,
    operationIdHashPreimageHex: bytesToHex(
      createDeviceOperationHashPreimageV2(deviceActivationPayload),
    ),
    operationId: deviceOperationId,
    eventWithoutEventId: deviceRegistryEventWithoutEventId,
    canonicalEventJcs: canonicalize(deviceRegistryEventWithoutEventId),
    eventHashPreimageHex: bytesToHex(
      createDeviceRegistryEventHashPreimageV2(deviceRegistryEventWithoutEventId),
    ),
    eventHashHex: bytesToHex(deviceRegistryEventIdentity.eventHash),
    eventHashBase64Url: encodeBase64Url(deviceRegistryEventIdentity.eventHash),
    eventId: deviceRegistryEventIdentity.eventId,
    event: deviceRegistryEvent,
  };

  const deviceRegistryReceipt = {
    schema: VECTOR_SCHEMA_V2,
    warning: FIXTURE_WARNING,
    signingKeyId: ED25519_FIXTURES.serviceRegistry.id,
    keyset: { keys: [serviceJwk] },
    payload: deviceRegistryReceiptPayload,
    ...signedPayloadFields(deviceRegistryReceiptPayload, deviceRegistryReceiptSignature),
    receipt: {
      payload: deviceRegistryReceiptPayload,
      signature: deviceRegistryReceiptSignature,
    },
    verification: {
      eventId: deviceRegistryReceiptPayload.eventId,
      operationId: deviceRegistryReceiptPayload.operationId,
      subject: deviceRegistryReceiptPayload.subject,
      genesisHash: deviceRegistryReceiptPayload.genesisHash,
      eventType: deviceRegistryReceiptPayload.eventType,
      identityState: deviceRegistryReceiptPayload.identityState,
      identitySequence: deviceRegistryReceiptPayload.identitySequence,
      deviceLedgerSequence: deviceRegistryReceiptPayload.deviceLedgerSequence,
      deviceId: deviceRegistryReceiptPayload.deviceId,
      authorizationId: deviceRegistryReceiptPayload.authorizationId,
      deviceState: deviceRegistryReceiptPayload.deviceState,
      authorizationExpiresAt: deviceRegistryReceiptPayload.authorizationExpiresAt,
      acceptedAt: deviceRegistryReceiptPayload.acceptedAt,
    },
  };

  const deviceStatusStatement = {
    schema: VECTOR_SCHEMA_V2,
    warning: FIXTURE_WARNING,
    signingKeyId: ED25519_FIXTURES.serviceRegistry.id,
    keyset: { keys: [serviceJwk] },
    verificationTime: deviceStatusStatementPayload.iat + 30,
    payload: deviceStatusStatementPayload,
    ...signedPayloadFields(deviceStatusStatementPayload, deviceStatusStatementSignature),
    statement: {
      payload: deviceStatusStatementPayload,
      signature: deviceStatusStatementSignature,
    },
    verification: {
      subject: deviceStatusStatementPayload.subject,
      genesisHash: deviceStatusStatementPayload.genesisHash,
      deviceId: deviceStatusStatementPayload.deviceId,
      authorizationId: deviceStatusStatementPayload.authorizationId,
      identityState: deviceStatusStatementPayload.identityState,
      identitySequence: deviceStatusStatementPayload.identitySequence,
      deviceLedgerSequence: deviceStatusStatementPayload.deviceLedgerSequence,
      deviceState: deviceStatusStatementPayload.deviceState,
      authorizationExpiresAt: deviceStatusStatementPayload.authorizationExpiresAt,
      maxClockSkewSeconds: 0,
    },
  };

  const registryEvent = {
    schema: VECTOR_SCHEMA,
    eventWithoutEventId: registryEventWithoutEventId,
    canonicalEventJcs: canonicalize(registryEventWithoutEventId),
    eventHashPreimageHex: bytesToHex(createRegistryEventHashPreimage(registryEventWithoutEventId)),
    eventHashHex: bytesToHex(registryEventIdentity.eventHash),
    eventHashBase64Url: encodeBase64Url(registryEventIdentity.eventHash),
    eventId: registryEventIdentity.eventId,
    event: {
      ...registryEventWithoutEventId,
      eventId: registryEventIdentity.eventId,
    },
  };

  const globalTargetShard = globalShards.find((shard) => shard.shardId === transparencyShardId);
  if (globalTargetShard === undefined) {
    throw new Error('The transparency target shard is missing from the global manifest.');
  }
  const transparency = {
    schema: VECTOR_SCHEMA,
    warning: FIXTURE_WARNING,
    signingKeyId: ED25519_FIXTURES.serviceTransparency.id,
    keyset: { keys: [transparencyJwk] },
    merkle: {
      algorithm: 'RFC6962-SHA256',
      leafDomainHex: '00',
      nodeDomainHex: '01',
      eventHashesHex: [
        bytesToHex(firstEventHash),
        bytesToHex(registryEventIdentity.eventHash),
        bytesToHex(thirdEventHash),
      ],
      leafHashesHex: [
        bytesToHex(firstLeafHash),
        bytesToHex(targetLeafHash),
        bytesToHex(thirdLeafHash),
      ],
      targetLeafIndex: transparencyInclusionProof.leafIndex,
      auditPathHex: [bytesToHex(firstLeafHash), bytesToHex(thirdLeafHash)],
      rootHashHex: bytesToHex(transparencyRoot),
      rootHashBase64Url: transparencyCheckpointPayload.rootHash,
    },
    checkpoint: {
      payload: transparencyCheckpointPayload,
      canonicalPayloadJcs: canonicalize(transparencyCheckpointPayload),
      signaturePreimageHex: bytesToHex(
        createTransparencyCheckpointSignaturePreimage(transparencyCheckpointPayload),
      ),
      signatureBase64Url: transparencyCheckpointSignature,
      signed: signedTransparencyCheckpoint,
    },
    globalCheckpoint: {
      payload: globalTransparencyPayload,
      canonicalPayloadJcs: canonicalize(globalTransparencyPayload),
      signaturePreimageHex: bytesToHex(
        createGlobalTransparencyCheckpointSignaturePreimage(globalTransparencyPayload),
      ),
      signatureBase64Url: globalTransparencySignature,
      signed: signedGlobalTransparencyCheckpoint,
    },
    inclusionProof: transparencyInclusionProof,
    composition: {
      targetShard: globalTargetShard,
      checkpointMatchesGlobalShard: true,
      inclusionCheckpointMatchesShardCheckpoint: true,
    },
    verification: {
      checkpoint: {
        now: transparencyCheckpointPayload.checkpointedAt,
        maxAgeSeconds: 60,
        maxClockSkewSeconds: 0,
        signerKid: TRANSPARENCY_KEY_ID,
        shardId: transparencyShardId,
        treeSize: transparencyCheckpointPayload.treeSize,
        rootHash: transparencyCheckpointPayload.rootHash,
      },
      globalCheckpoint: {
        now: globalTransparencyPayload.checkpointedAt,
        maxAgeSeconds: 60,
        maxClockSkewSeconds: 0,
        signerKid: TRANSPARENCY_KEY_ID,
      },
      inclusion: {
        now: transparencyCheckpointPayload.checkpointedAt,
        maxAgeSeconds: 60,
        maxClockSkewSeconds: 0,
        signerKid: TRANSPARENCY_KEY_ID,
        eventHash: transparencyInclusionProof.eventHash,
        shardId: transparencyShardId,
        treeSize: transparencyCheckpointPayload.treeSize,
        rootHash: transparencyCheckpointPayload.rootHash,
      },
    },
  };

  const registryReceipt = {
    schema: VECTOR_SCHEMA,
    signingKeyId: ED25519_FIXTURES.serviceRegistry.id,
    keyset: { keys: [serviceJwk] },
    payload: registryReceiptPayload,
    ...signedPayloadFields(registryReceiptPayload, registryReceiptSignature),
    receipt: {
      payload: registryReceiptPayload,
      signature: registryReceiptSignature,
    },
  };

  const statusStatement = {
    schema: VECTOR_SCHEMA,
    signingKeyId: ED25519_FIXTURES.serviceRegistry.id,
    keyset: { keys: [serviceJwk] },
    verificationTime: VECTOR_TIMES.registeredAt + 30,
    payload: statusStatementPayload,
    ...signedPayloadFields(statusStatementPayload, statusStatementSignature),
    statement: {
      payload: statusStatementPayload,
      signature: statusStatementSignature,
    },
  };

  const signingKeyRevoke = {
    schema: VECTOR_SCHEMA,
    signingKeyId: ED25519_FIXTURES.identityA.id,
    genesis: identityA.genesis,
    verification: {
      subject: identityA.subject,
      expectedSequence: 0,
      nonce: signingKeyRevokePayload.nonce,
      now: VECTOR_TIMES.revokeIssuedAt,
      maxClockSkewSeconds: 0,
    },
    payload: signingKeyRevokePayload,
    ...signedPayloadFields(signingKeyRevokePayload, signingKeyRevokeSignature),
    request: {
      mode: 'signature',
      payload: signingKeyRevokePayload,
      signature: signingKeyRevokeSignature,
    },
  };

  const continuityLink = {
    schema: VECTOR_SCHEMA,
    signingKeyIds: [ED25519_FIXTURES.identityA.id, ED25519_FIXTURES.identityB.id],
    verification: {
      subjectA: identityA.subject,
      subjectB: identityB.subject,
      scope: continuityLinkPayload.scope,
      nonce: continuityLinkPayload.nonce,
      now: VECTOR_TIMES.continuityIssuedAt,
      maxClockSkewSeconds: 0,
    },
    payload: continuityLinkPayload,
    canonicalPayloadJcs: canonicalize(continuityLinkPayload),
    signaturePreimageHex: bytesToHex(createProtocolSignaturePreimage(continuityLinkPayload)),
    signatureABase64Url: continuitySignatureA,
    signatureBBase64Url: continuitySignatureB,
    link: {
      payload: continuityLinkPayload,
      signatureA: continuitySignatureA,
      signatureB: continuitySignatureB,
    },
  };

  const base64Url = {
    schema: VECTOR_SCHEMA,
    valid: [
      { name: 'empty', hex: '', base64url: '' },
      { name: 'single-zero-byte', hex: '00', base64url: 'AA' },
      { name: 'single-ff-byte', hex: 'ff', base64url: '_w' },
      { name: 'url-alphabet', hex: 'fbefff', base64url: '--__' },
      {
        name: 'sequential-32-bytes',
        hex: REVOCATION_SECRET_A_HEX,
        base64url: encodeBase64Url(bytesFromHex(REVOCATION_SECRET_A_HEX)),
      },
    ],
    invalid: [
      { name: 'padding', value: 'Zg==' },
      { name: 'standard-base64-alphabet', value: '+/8' },
      { name: 'impossible-length', value: 'A' },
      { name: 'whitespace', value: 'Zg\n' },
      { name: 'non-canonical-trailing-bits', value: 'AB' },
    ],
  };

  const canonicalizationCases = [
    {
      name: 'rfc-8785-number-serialization',
      value: [333333333.3333333, 1e30, 4.5, 0.002, 1e-27],
    },
    {
      name: 'utf-16-property-order',
      value: {
        '\u20ac': 'Euro Sign',
        '\r': 'Carriage Return',
        '\ufb33': 'Hebrew Letter Dalet With Dagesh',
        '1': 'One',
        '\ud83d\ude00': 'Emoji: Grinning Face',
        '\u0080': 'Control',
        '\u00f6': 'Latin Small Letter O With Diaeresis',
      },
    },
    {
      name: 'escaping-and-nesting',
      value: {
        z: [true, null, 'line\nfeed'],
        a: { quote: '"', slash: '/', control: '\b\t' },
      },
    },
  ];
  const canonicalization = {
    schema: VECTOR_SCHEMA,
    cases: canonicalizationCases.map((testCase) => ({
      ...testCase,
      canonicalJcs: canonicalize(testCase.value),
      canonicalUtf8Hex: bytesToHex(utf8Encode(canonicalize(testCase.value))),
    })),
    rejectedJsonLiterals: [
      { name: 'lone-high-surrogate', json: '"\\ud800"' },
      { name: 'lone-low-surrogate', json: '"\\udc00"' },
      { name: 'lone-surrogate-key', json: '{"\\ud800":true}' },
    ],
  };

  const vectors = new Map<string, unknown>([
    ['base64url.json', base64Url],
    ['canonicalization.json', canonicalization],
    ['continuity-link.json', continuityLink],
    ['device-activation-v2.json', deviceActivationVector],
    ['device-authorization-v2.json', deviceAuthorizationVector],
    ['device-registry-event-v2.json', deviceRegistryEventVector],
    ['device-registry-receipt-v2.json', deviceRegistryReceipt],
    ['device-status-statement-v2.json', deviceStatusStatement],
    ['identity.json', identity],
    ['keys.json', keys],
    ['ownership-proof.json', ownershipProof],
    ['ownership-proof-v2.json', ownershipProofV2],
    ['registry-event.json', registryEvent],
    ['registry-receipt.json', registryReceipt],
    ['revocation-commitment.json', revocationCommitment],
    ['signing-key-revoke.json', signingKeyRevoke],
    ['status-statement.json', statusStatement],
    ['transparency.json', transparency],
  ]);
  return new Map(
    await Promise.all(
      Array.from(
        vectors,
        async ([name, value]) =>
          [
            name,
            await format(JSON.stringify(value), {
              parser: 'json',
              printWidth: 100,
              tabWidth: 2,
            }),
          ] as const,
      ),
    ),
  );
}

export async function writeTestVectorFiles(
  directory: URL = new URL('../vectors/', import.meta.url),
): Promise<readonly string[]> {
  const files = await buildTestVectorFiles();
  await mkdir(directory, { recursive: true });
  await Promise.all(
    Array.from(files, ([name, contents]) => writeFile(new URL(name, directory), contents, 'utf8')),
  );
  return Array.from(files.keys());
}
