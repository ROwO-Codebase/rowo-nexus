import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

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
  verifyProtocolPayload,
} from '@nexus/crypto';
import {
  canonicalize,
  continuityLinkV1Schema,
  createDeviceAuthorizationHashPreimageV2,
  createDeviceIdHashPreimageV2,
  createDeviceOperationHashPreimageV2,
  createDeviceRegistryEventHashPreimageV2,
  createGlobalTransparencyCheckpointSignaturePreimage,
  createTransparencyCheckpointSignaturePreimage,
  decodeBase64Url,
  deviceActivationPayloadV2Schema,
  deviceActivationRequestV2Schema,
  deviceAuthorizationV2Schema,
  deviceIdInputV2Schema,
  deviceRegistryEventV2Schema,
  deviceRegistryEventWithoutEventIdV2Schema,
  deviceRegistryReceiptV2Schema,
  deviceStatusStatementV2Schema,
  encodeBase64Url,
  identityGenesisV1Schema,
  ownershipProofV2Schema,
  ownershipProofV1Schema,
  registryEventV1Schema,
  registryEventWithoutEventIdV1Schema,
  registryReceiptV1Schema,
  revokeBySignatureRequestV1Schema,
  serviceKeySetSchema,
  signedGlobalTransparencyCheckpointV1Schema,
  signedTransparencyCheckpointV1Schema,
  statusStatementV1Schema,
  transparencyInclusionProofV1Schema,
} from '@nexus/protocol';
import {
  verifyAuthenticatedInclusionProof,
  verifyContinuityLink,
  verifyGlobalTransparencyCheckpoint,
  verifyInclusionProof,
  verifyOwnershipProof,
  verifyOwnershipProofV2,
  verifyDeviceRegistryReceipt,
  verifyDeviceStatusStatement,
  verifyRegistryReceipt,
  verifyRevokeBySignature,
  verifyStatusStatement,
  verifySubject,
  verifyTransparencyCheckpoint,
} from '@nexus/verifier';

import { bytesFromHex, bytesToHex } from './encoding.js';
import { FIXTURE_WARNING } from './fixtures.js';

interface JsonObject {
  readonly [key: string]: unknown;
}

interface LoadedKey {
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
  readonly publicKeyBase64Url: string;
}

function object(value: unknown, label: string): JsonObject {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    throw new TypeError(`${label} must be a JSON object.`);
  }
  return value as JsonObject;
}

function array(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) throw new TypeError(`${label} must be an array.`);
  return value;
}

function string(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new TypeError(`${label} must be a string.`);
  return value;
}

function integer(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || typeof value !== 'number') {
    throw new TypeError(`${label} must be a safe integer.`);
  }
  return value;
}

function tamperBase64Url(value: string): string {
  assert.ok(value.length > 0, 'Cannot tamper with an empty base64url value.');
  return `${value[0] === 'A' ? 'B' : 'A'}${value.slice(1)}`;
}

async function loadVector(
  directory: URL,
  name: string,
  schema = 'nexus.test-vectors.v1',
): Promise<JsonObject> {
  const parsed: unknown = JSON.parse(await readFile(new URL(name, directory), 'utf8'));
  const vector = object(parsed, name);
  assert.equal(vector.schema, schema, `${name}: schema`);
  return vector;
}

function assertExpectedSignedFields<T extends { readonly protocol: string }>(
  vector: JsonObject,
  payload: T,
  signature: string,
): void {
  assert.equal(canonicalize(payload), vector.canonicalPayloadJcs);
  assert.equal(bytesToHex(createProtocolSignaturePreimage(payload)), vector.signaturePreimageHex);
  assert.equal(signature, vector.signatureBase64Url);
}

async function hashTransparencyLeaf(eventHash: Uint8Array): Promise<Uint8Array> {
  return getDefaultCryptoProvider().sha256(concatBytes(Uint8Array.of(0x00), eventHash));
}

async function hashTransparencyNode(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return getDefaultCryptoProvider().sha256(concatBytes(Uint8Array.of(0x01), left, right));
}

async function verifyKeyFixtures(directory: URL): Promise<ReadonlyMap<string, LoadedKey>> {
  const keys = await loadVector(directory, 'keys.json');
  assert.equal(keys.warning, FIXTURE_WARNING);
  assert.match(string(keys.warning, 'keys.warning'), /NON-PRODUCTION/u);

  const loaded = new Map<string, LoadedKey>();
  for (const [index, rawFixture] of array(keys.fixtures, 'keys.fixtures').entries()) {
    const fixture = object(rawFixture, `keys.fixtures[${String(index)}]`);
    const id = string(fixture.id, 'key id');
    const seedHex = string(fixture.seedHex, `${id}.seedHex`);
    const pkcs8Hex = string(fixture.privateKeyPkcs8Hex, `${id}.privateKeyPkcs8Hex`);
    const pkcs8Base64Url = string(
      fixture.privateKeyPkcs8Base64Url,
      `${id}.privateKeyPkcs8Base64Url`,
    );
    const publicKeyHex = string(fixture.publicKeyHex, `${id}.publicKeyHex`);
    const publicKeyBase64Url = string(fixture.publicKeyBase64Url, `${id}.publicKeyBase64Url`);

    assert.equal(pkcs8Hex, `302e020100300506032b657004220420${seedHex}`);
    assert.equal(bytesToHex(decodeBase64Url(pkcs8Base64Url)), pkcs8Hex);
    assert.equal(bytesToHex(decodeBase64Url(publicKeyBase64Url)), publicKeyHex);

    const provider = getDefaultCryptoProvider();
    loaded.set(id, {
      privateKey: await provider.importEd25519PrivateKey(bytesFromHex(pkcs8Hex)),
      publicKey: await provider.importEd25519PublicKey(bytesFromHex(publicKeyHex)),
      publicKeyBase64Url,
    });
  }
  assert.equal(loaded.size, 4);
  return loaded;
}

async function verifyBase64UrlVectors(directory: URL): Promise<void> {
  const vector = await loadVector(directory, 'base64url.json');
  for (const rawCase of array(vector.valid, 'base64url.valid')) {
    const testCase = object(rawCase, 'base64url valid case');
    const hex = string(testCase.hex, 'valid.hex');
    const encoded = string(testCase.base64url, 'valid.base64url');
    assert.equal(encodeBase64Url(bytesFromHex(hex)), encoded);
    assert.equal(bytesToHex(decodeBase64Url(encoded)), hex);
  }
  for (const rawCase of array(vector.invalid, 'base64url.invalid')) {
    const testCase = object(rawCase, 'base64url invalid case');
    assert.throws(() => decodeBase64Url(string(testCase.value, 'invalid.value')));
  }
}

async function verifyCanonicalizationVectors(directory: URL): Promise<void> {
  const vector = await loadVector(directory, 'canonicalization.json');
  for (const rawCase of array(vector.cases, 'canonicalization.cases')) {
    const testCase = object(rawCase, 'canonicalization case');
    const actual = canonicalize(testCase.value);
    assert.equal(actual, testCase.canonicalJcs);
    assert.equal(bytesToHex(utf8Encode(actual)), testCase.canonicalUtf8Hex);
  }
  for (const rawCase of array(
    vector.rejectedJsonLiterals,
    'canonicalization.rejectedJsonLiterals',
  )) {
    const testCase = object(rawCase, 'canonicalization rejected case');
    const value: unknown = JSON.parse(string(testCase.json, 'rejected.json'));
    assert.throws(() => canonicalize(value));
  }
}

export async function verifyTestVectorDirectory(
  directory: URL = new URL('../vectors/', import.meta.url),
): Promise<readonly string[]> {
  const [keys] = await Promise.all([
    verifyKeyFixtures(directory),
    verifyBase64UrlVectors(directory),
    verifyCanonicalizationVectors(directory),
  ]);
  const identityKeyA = keys.get('identity-a');
  const identityKeyB = keys.get('identity-b');
  const serviceKey = keys.get('service-registry');
  const transparencyKey = keys.get('service-transparency');
  assert.ok(identityKeyA);
  assert.ok(identityKeyB);
  assert.ok(serviceKey);
  assert.ok(transparencyKey);

  const revocation = await loadVector(directory, 'revocation-commitment.json');
  assert.match(string(revocation.warning, 'revocation.warning'), /NON-PRODUCTION/u);
  const revocationSecret = bytesFromHex(string(revocation.secretHex, 'revocation.secretHex'));
  assert.equal(
    bytesToHex(createRevocationCommitmentPreimage(revocationSecret)),
    revocation.commitmentPreimageHex,
  );
  const commitment = await computeRevocationCommitment(revocationSecret);
  assert.equal(bytesToHex(commitment), revocation.commitmentHex);
  assert.equal(encodeBase64Url(commitment), revocation.commitmentBase64Url);

  const identity = await loadVector(directory, 'identity.json');
  const genesis = identityGenesisV1Schema.parse(identity.genesis);
  const genesisJcs = canonicalize(genesis);
  assert.equal(genesisJcs, identity.genesisJcs);
  assert.equal(bytesToHex(utf8Encode(genesisJcs)), identity.genesisJcsUtf8Hex);
  assert.equal(bytesToHex(createGenesisHashPreimage(genesis)), identity.genesisHashPreimageHex);
  const genesisHash = await deriveGenesisHash(genesis);
  assert.equal(bytesToHex(genesisHash), identity.genesisHashHex);
  assert.equal(encodeBase64Url(genesisHash), identity.genesisHashBase64Url);
  const subject = await deriveSubject(genesis);
  assert.equal(subject, identity.subject);
  await verifySubject(genesis, subject);

  const deviceAuthorizationVector = await loadVector(
    directory,
    'device-authorization-v2.json',
    'nexus.test-vectors.v2',
  );
  assert.match(
    string(deviceAuthorizationVector.warning, 'device authorization warning'),
    /NON-PRODUCTION/u,
  );
  assert.equal(deviceAuthorizationVector.identityGenesisProtocol, 'nexus.identity.v1');
  assert.deepEqual(identityGenesisV1Schema.parse(deviceAuthorizationVector.genesis), genesis);
  assert.equal(deviceAuthorizationVector.genesisHashBase64Url, encodeBase64Url(genesisHash));
  const deviceIdInput = deviceIdInputV2Schema.parse(deviceAuthorizationVector.deviceIdInput);
  assert.equal(canonicalize(deviceIdInput), deviceAuthorizationVector.canonicalDeviceIdInputJcs);
  assert.equal(
    bytesToHex(createDeviceIdHashPreimageV2(deviceIdInput)),
    deviceAuthorizationVector.deviceIdHashPreimageHex,
  );
  const deviceId = await deriveDeviceIdV2(deviceIdInput);
  assert.equal(deviceId, deviceAuthorizationVector.deviceId);

  const authorization = deviceAuthorizationV2Schema.parse(deviceAuthorizationVector.authorization);
  assertExpectedSignedFields(
    deviceAuthorizationVector,
    authorization.payload,
    authorization.rootSignature,
  );
  assert.equal(
    bytesToHex(createDeviceAuthorizationHashPreimageV2(authorization.payload)),
    deviceAuthorizationVector.authorizationIdHashPreimageHex,
  );
  const authorizationId = await deriveDeviceAuthorizationIdV2(authorization.payload);
  assert.equal(authorizationId, deviceAuthorizationVector.authorizationId);
  assert.equal(
    await signProtocolPayload(authorization.payload, identityKeyA.privateKey),
    authorization.rootSignature,
  );
  assert.equal(
    await verifyProtocolPayload(
      authorization.payload,
      authorization.rootSignature,
      identityKeyA.publicKey,
    ),
    true,
  );
  assert.equal(
    await verifyProtocolPayload(
      authorization.payload,
      tamperBase64Url(authorization.rootSignature),
      identityKeyA.publicKey,
    ),
    false,
  );
  const authorizationPayloadTampered = {
    ...authorization.payload,
    expiresAt: authorization.payload.expiresAt + 1,
  };
  assert.notEqual(
    await deriveDeviceAuthorizationIdV2(authorizationPayloadTampered),
    authorizationId,
  );
  assert.equal(
    await verifyProtocolPayload(
      authorizationPayloadTampered,
      authorization.rootSignature,
      identityKeyA.publicKey,
    ),
    false,
  );
  assert.notEqual(
    await deriveDeviceIdV2(
      deviceIdInputV2Schema.parse({
        ...deviceIdInput,
        signingKey: {
          ...deviceIdInput.signingKey,
          publicKey: serviceKey.publicKeyBase64Url,
        },
      }),
    ),
    deviceId,
  );

  const activationVector = await loadVector(
    directory,
    'device-activation-v2.json',
    'nexus.test-vectors.v2',
  );
  const activation = deviceActivationRequestV2Schema.parse(activationVector.request);
  assert.deepEqual(activation.authorization, authorization);
  assertExpectedSignedFields(activationVector, activation.payload, activation.deviceSignature);
  assert.equal(
    bytesToHex(createDeviceOperationHashPreimageV2(activation.payload)),
    activationVector.operationIdHashPreimageHex,
  );
  const operationId = await deriveDeviceOperationIdV2(activation.payload);
  assert.equal(operationId, activationVector.operationId);
  assert.equal(
    await signProtocolPayload(activation.payload, identityKeyB.privateKey),
    activation.deviceSignature,
  );
  assert.equal(
    await verifyProtocolPayload(
      activation.payload,
      activation.deviceSignature,
      identityKeyB.publicKey,
    ),
    true,
  );
  assert.equal(
    await verifyProtocolPayload(
      activation.payload,
      tamperBase64Url(activation.deviceSignature),
      identityKeyB.publicKey,
    ),
    false,
  );
  assert.notEqual(
    await deriveDeviceOperationIdV2({
      ...activation.payload,
      requestId: authorization.payload.authorizationNonce,
    }),
    operationId,
  );

  const ownershipV2Vector = await loadVector(
    directory,
    'ownership-proof-v2.json',
    'nexus.test-vectors.v2',
  );
  const proofV2 = ownershipProofV2Schema.parse(ownershipV2Vector.proof);
  assert.deepEqual(proofV2.payload.genesis, genesis);
  assert.deepEqual(proofV2.payload.authorization, authorization);
  assertExpectedSignedFields(ownershipV2Vector, proofV2.payload, proofV2.deviceSignature);
  assert.equal(
    await signProtocolPayload(proofV2.payload, identityKeyB.privateKey),
    proofV2.deviceSignature,
  );
  assert.equal(
    await verifyProtocolPayload(proofV2.payload, proofV2.deviceSignature, identityKeyB.publicKey),
    true,
  );
  const ownershipV2Expectation = {
    audience: proofV2.payload.aud,
    action: proofV2.payload.act,
    resource: proofV2.payload.resource,
    nonce: proofV2.payload.nonce,
    contextHash: proofV2.payload.contextHash ?? null,
    now: proofV2.payload.iat,
    maxClockSkewSeconds: 0,
  };
  const verifiedDevice = await verifyOwnershipProofV2(proofV2, ownershipV2Expectation);
  assert.equal(verifiedDevice.subject, subject);
  assert.equal(verifiedDevice.deviceId, deviceId);
  assert.equal(verifiedDevice.authorizationId, authorizationId);
  await assert.rejects(
    verifyOwnershipProofV2(
      { ...proofV2, deviceSignature: tamperBase64Url(proofV2.deviceSignature) },
      ownershipV2Expectation,
    ),
  );

  const deviceEventVector = await loadVector(
    directory,
    'device-registry-event-v2.json',
    'nexus.test-vectors.v2',
  );
  const deviceEventWithoutId = deviceRegistryEventWithoutEventIdV2Schema.parse(
    deviceEventVector.eventWithoutEventId,
  );
  const deviceEvent = deviceRegistryEventV2Schema.parse(deviceEventVector.event);
  const eventOperationPayload = deviceActivationPayloadV2Schema.parse(
    deviceEventVector.operationPayload,
  );
  assert.deepEqual(eventOperationPayload, activation.payload);
  assert.equal(
    bytesToHex(createDeviceOperationHashPreimageV2(eventOperationPayload)),
    deviceEventVector.operationIdHashPreimageHex,
  );
  assert.equal(canonicalize(deviceEventWithoutId), deviceEventVector.canonicalEventJcs);
  assert.equal(
    bytesToHex(createDeviceRegistryEventHashPreimageV2(deviceEventWithoutId)),
    deviceEventVector.eventHashPreimageHex,
  );
  const derivedDeviceEvent = await deriveDeviceRegistryEventIdV2(deviceEventWithoutId);
  assert.equal(bytesToHex(derivedDeviceEvent.eventHash), deviceEventVector.eventHashHex);
  assert.equal(encodeBase64Url(derivedDeviceEvent.eventHash), deviceEventVector.eventHashBase64Url);
  assert.equal(derivedDeviceEvent.eventId, deviceEventVector.eventId);
  assert.equal(deviceEvent.eventId, derivedDeviceEvent.eventId);
  assert.equal(deviceEvent.operationId, operationId);
  assert.notEqual(
    (
      await deriveDeviceRegistryEventIdV2({
        ...deviceEventWithoutId,
        acceptedAt: deviceEventWithoutId.acceptedAt + 1,
      })
    ).eventId,
    deviceEvent.eventId,
  );

  const deviceReceiptVector = await loadVector(
    directory,
    'device-registry-receipt-v2.json',
    'nexus.test-vectors.v2',
  );
  const deviceReceipt = deviceRegistryReceiptV2Schema.parse(deviceReceiptVector.receipt);
  const deviceReceiptKeyset = serviceKeySetSchema.parse(deviceReceiptVector.keyset);
  assertExpectedSignedFields(deviceReceiptVector, deviceReceipt.payload, deviceReceipt.signature);
  assert.equal(
    await signProtocolPayload(deviceReceipt.payload, serviceKey.privateKey),
    deviceReceipt.signature,
  );
  assert.equal(deviceReceipt.payload.eventId, deviceEvent.eventId);
  assert.equal(deviceReceipt.payload.operationId, deviceEvent.operationId);
  assert.ok(deviceReceipt.payload.authorizationId);
  assert.ok(deviceReceipt.payload.authorizationExpiresAt);
  const receiptAuthorizationId = deviceReceipt.payload.authorizationId;
  const receiptAuthorizationExpiresAt = deviceReceipt.payload.authorizationExpiresAt;
  await verifyDeviceRegistryReceipt(deviceReceipt, deviceReceiptKeyset, {
    eventId: deviceReceipt.payload.eventId,
    operationId: deviceReceipt.payload.operationId,
    subject: deviceReceipt.payload.subject,
    genesisHash: deviceReceipt.payload.genesisHash,
    eventType: deviceReceipt.payload.eventType,
    identityState: deviceReceipt.payload.identityState,
    identitySequence: deviceReceipt.payload.identitySequence,
    deviceLedgerSequence: deviceReceipt.payload.deviceLedgerSequence,
    deviceId: deviceReceipt.payload.deviceId,
    authorizationId: receiptAuthorizationId,
    deviceState: deviceReceipt.payload.deviceState,
    authorizationExpiresAt: receiptAuthorizationExpiresAt,
    acceptedAt: deviceReceipt.payload.acceptedAt,
  });
  await assert.rejects(
    verifyDeviceRegistryReceipt(
      { ...deviceReceipt, signature: tamperBase64Url(deviceReceipt.signature) },
      deviceReceiptKeyset,
    ),
  );

  const deviceStatusVector = await loadVector(
    directory,
    'device-status-statement-v2.json',
    'nexus.test-vectors.v2',
  );
  const deviceStatus = deviceStatusStatementV2Schema.parse(deviceStatusVector.statement);
  const deviceStatusKeyset = serviceKeySetSchema.parse(deviceStatusVector.keyset);
  assertExpectedSignedFields(deviceStatusVector, deviceStatus.payload, deviceStatus.signature);
  assert.equal(
    await signProtocolPayload(deviceStatus.payload, serviceKey.privateKey),
    deviceStatus.signature,
  );
  assert.equal(deviceStatus.payload.deviceId, deviceReceipt.payload.deviceId);
  assert.equal(deviceStatus.payload.authorizationId, deviceReceipt.payload.authorizationId);
  assert.ok(deviceStatus.payload.authorizationExpiresAt);
  const statusAuthorizationExpiresAt = deviceStatus.payload.authorizationExpiresAt;
  await verifyDeviceStatusStatement(
    deviceStatus,
    deviceStatusKeyset,
    integer(deviceStatusVector.verificationTime, 'device status verificationTime'),
    {
      subject: deviceStatus.payload.subject,
      genesisHash: deviceStatus.payload.genesisHash,
      deviceId: deviceStatus.payload.deviceId,
      authorizationId: deviceStatus.payload.authorizationId,
      identityState: deviceStatus.payload.identityState,
      identitySequence: deviceStatus.payload.identitySequence,
      deviceLedgerSequence: deviceStatus.payload.deviceLedgerSequence,
      deviceState: deviceStatus.payload.deviceState,
      authorizationExpiresAt: statusAuthorizationExpiresAt,
      maxClockSkewSeconds: 0,
    },
  );
  await assert.rejects(
    verifyDeviceStatusStatement(
      { ...deviceStatus, signature: tamperBase64Url(deviceStatus.signature) },
      deviceStatusKeyset,
      deviceStatus.payload.iat,
    ),
  );

  const ownership = await loadVector(directory, 'ownership-proof.json');
  const proof = ownershipProofV1Schema.parse(ownership.proof);
  assertExpectedSignedFields(ownership, proof.payload, proof.signature);
  assert.equal(await signProtocolPayload(proof.payload, identityKeyA.privateKey), proof.signature);
  assert.equal(
    await verifyProtocolPayload(proof.payload, proof.signature, identityKeyA.publicKey),
    true,
  );
  await verifyOwnershipProof(proof, {
    audience: proof.payload.aud,
    action: proof.payload.act,
    resource: proof.payload.resource,
    nonce: proof.payload.nonce,
    now: proof.payload.iat,
    maxClockSkewSeconds: 0,
  });

  const eventVector = await loadVector(directory, 'registry-event.json');
  const eventWithoutId = registryEventWithoutEventIdV1Schema.parse(eventVector.eventWithoutEventId);
  const event = registryEventV1Schema.parse(eventVector.event);
  assert.equal(canonicalize(eventWithoutId), eventVector.canonicalEventJcs);
  assert.equal(
    bytesToHex(createRegistryEventHashPreimage(eventWithoutId)),
    eventVector.eventHashPreimageHex,
  );
  const derivedEvent = await deriveRegistryEventId(eventWithoutId);
  assert.equal(bytesToHex(derivedEvent.eventHash), eventVector.eventHashHex);
  assert.equal(encodeBase64Url(derivedEvent.eventHash), eventVector.eventHashBase64Url);
  assert.equal(derivedEvent.eventId, eventVector.eventId);
  assert.equal(event.eventId, derivedEvent.eventId);

  const transparencyVector = await loadVector(directory, 'transparency.json');
  assert.match(string(transparencyVector.warning, 'transparency.warning'), /NON-PRODUCTION/u);
  const transparencyKeyset = serviceKeySetSchema.parse(transparencyVector.keyset);
  const checkpointVector = object(transparencyVector.checkpoint, 'transparency.checkpoint');
  const globalCheckpointVector = object(
    transparencyVector.globalCheckpoint,
    'transparency.globalCheckpoint',
  );
  const checkpoint = signedTransparencyCheckpointV1Schema.parse(checkpointVector.signed);
  const globalCheckpoint = signedGlobalTransparencyCheckpointV1Schema.parse(
    globalCheckpointVector.signed,
  );
  const inclusionProof = transparencyInclusionProofV1Schema.parse(
    transparencyVector.inclusionProof,
  );
  assertExpectedSignedFields(checkpointVector, checkpoint.payload, checkpoint.signature);
  assertExpectedSignedFields(
    globalCheckpointVector,
    globalCheckpoint.payload,
    globalCheckpoint.signature,
  );
  assert.equal(
    bytesToHex(createTransparencyCheckpointSignaturePreimage(checkpoint.payload)),
    checkpointVector.signaturePreimageHex,
  );
  assert.equal(
    bytesToHex(createGlobalTransparencyCheckpointSignaturePreimage(globalCheckpoint.payload)),
    globalCheckpointVector.signaturePreimageHex,
  );
  assert.equal(
    await signProtocolPayload(checkpoint.payload, transparencyKey.privateKey),
    checkpoint.signature,
  );
  assert.equal(
    await signProtocolPayload(globalCheckpoint.payload, transparencyKey.privateKey),
    globalCheckpoint.signature,
  );
  assert.equal(
    await verifyProtocolPayload(
      checkpoint.payload,
      checkpoint.signature,
      transparencyKey.publicKey,
    ),
    true,
  );

  const merkle = object(transparencyVector.merkle, 'transparency.merkle');
  const eventHashesHex = array(merkle.eventHashesHex, 'transparency.eventHashesHex').map(
    (value, index) => string(value, `transparency.eventHashesHex[${String(index)}]`),
  );
  assert.equal(eventHashesHex.length, 3);
  assert.equal(eventHashesHex[1], bytesToHex(derivedEvent.eventHash));
  const eventHashes = eventHashesHex.map(bytesFromHex);
  const leafHashes = await Promise.all(eventHashes.map(hashTransparencyLeaf));
  const expectedLeafHashes = array(merkle.leafHashesHex, 'transparency.leafHashesHex').map(
    (value, index) => string(value, `transparency.leafHashesHex[${String(index)}]`),
  );
  assert.deepEqual(leafHashes.map(bytesToHex), expectedLeafHashes);
  const firstLeaf = leafHashes[0];
  const targetLeaf = leafHashes[1];
  const thirdLeaf = leafHashes[2];
  assert.ok(firstLeaf);
  assert.ok(targetLeaf);
  assert.ok(thirdLeaf);
  const leftRoot = await hashTransparencyNode(firstLeaf, targetLeaf);
  const root = await hashTransparencyNode(leftRoot, thirdLeaf);
  assert.equal(bytesToHex(root), merkle.rootHashHex);
  assert.equal(encodeBase64Url(root), checkpoint.payload.rootHash);
  assert.equal(inclusionProof.eventHash, encodeBase64Url(derivedEvent.eventHash));
  assert.deepEqual(
    inclusionProof.auditPath.map((node) => bytesToHex(decodeBase64Url(node))),
    array(merkle.auditPathHex, 'transparency.auditPathHex'),
  );
  assert.equal(
    await verifyInclusionProof(
      decodeBase64Url(inclusionProof.eventHash),
      inclusionProof.leafIndex,
      inclusionProof.treeSize,
      inclusionProof.auditPath.map(decodeBase64Url),
      decodeBase64Url(checkpoint.payload.rootHash),
    ),
    true,
  );

  const targetGlobalShard = globalCheckpoint.payload.shards.find(
    (shard) => shard.shardId === checkpoint.payload.shardId,
  );
  assert.ok(targetGlobalShard);
  assert.equal(targetGlobalShard.treeSize, checkpoint.payload.treeSize);
  assert.equal(targetGlobalShard.rootHash, checkpoint.payload.rootHash);
  assert.deepEqual(inclusionProof.checkpoint, checkpoint);

  const transparencyVerification = object(
    transparencyVector.verification,
    'transparency.verification',
  );
  const checkpointExpected = object(
    transparencyVerification.checkpoint,
    'transparency.verification.checkpoint',
  );
  const globalExpected = object(
    transparencyVerification.globalCheckpoint,
    'transparency.verification.globalCheckpoint',
  );
  const inclusionExpected = object(
    transparencyVerification.inclusion,
    'transparency.verification.inclusion',
  );
  await verifyTransparencyCheckpoint(checkpoint, transparencyKeyset, {
    now: integer(checkpointExpected.now, 'transparency.checkpoint.now'),
    maxAgeSeconds: integer(
      checkpointExpected.maxAgeSeconds,
      'transparency.checkpoint.maxAgeSeconds',
    ),
    maxClockSkewSeconds: integer(
      checkpointExpected.maxClockSkewSeconds,
      'transparency.checkpoint.maxClockSkewSeconds',
    ),
    signerKid: string(checkpointExpected.signerKid, 'transparency.checkpoint.signerKid'),
    shardId: string(checkpointExpected.shardId, 'transparency.checkpoint.shardId'),
    treeSize: integer(checkpointExpected.treeSize, 'transparency.checkpoint.treeSize'),
    rootHash: string(checkpointExpected.rootHash, 'transparency.checkpoint.rootHash'),
  });
  await verifyGlobalTransparencyCheckpoint(globalCheckpoint, transparencyKeyset, {
    now: integer(globalExpected.now, 'transparency.global.now'),
    maxAgeSeconds: integer(globalExpected.maxAgeSeconds, 'transparency.global.maxAgeSeconds'),
    maxClockSkewSeconds: integer(
      globalExpected.maxClockSkewSeconds,
      'transparency.global.maxClockSkewSeconds',
    ),
    signerKid: string(globalExpected.signerKid, 'transparency.global.signerKid'),
    shards: globalCheckpoint.payload.shards,
  });
  await verifyAuthenticatedInclusionProof(inclusionProof, transparencyKeyset, {
    now: integer(inclusionExpected.now, 'transparency.inclusion.now'),
    maxAgeSeconds: integer(inclusionExpected.maxAgeSeconds, 'transparency.inclusion.maxAgeSeconds'),
    maxClockSkewSeconds: integer(
      inclusionExpected.maxClockSkewSeconds,
      'transparency.inclusion.maxClockSkewSeconds',
    ),
    signerKid: string(inclusionExpected.signerKid, 'transparency.inclusion.signerKid'),
    eventHash: string(inclusionExpected.eventHash, 'transparency.inclusion.eventHash'),
    shardId: string(inclusionExpected.shardId, 'transparency.inclusion.shardId'),
    treeSize: integer(inclusionExpected.treeSize, 'transparency.inclusion.treeSize'),
    rootHash: string(inclusionExpected.rootHash, 'transparency.inclusion.rootHash'),
  });

  const receiptVector = await loadVector(directory, 'registry-receipt.json');
  const receipt = registryReceiptV1Schema.parse(receiptVector.receipt);
  const receiptKeyset = serviceKeySetSchema.parse(receiptVector.keyset);
  assertExpectedSignedFields(receiptVector, receipt.payload, receipt.signature);
  assert.equal(
    await signProtocolPayload(receipt.payload, serviceKey.privateKey),
    receipt.signature,
  );
  await verifyRegistryReceipt(receipt, receiptKeyset, {
    subject: receipt.payload.subject,
    genesisHash: receipt.payload.genesisHash,
    eventType: receipt.payload.eventType,
    sequence: receipt.payload.sequence,
    state: receipt.payload.state,
  });

  const statusVector = await loadVector(directory, 'status-statement.json');
  const statement = statusStatementV1Schema.parse(statusVector.statement);
  const statusKeyset = serviceKeySetSchema.parse(statusVector.keyset);
  assertExpectedSignedFields(statusVector, statement.payload, statement.signature);
  assert.equal(
    await signProtocolPayload(statement.payload, serviceKey.privateKey),
    statement.signature,
  );
  await verifyStatusStatement(
    statement,
    statusKeyset,
    integer(statusVector.verificationTime, 'status.verificationTime'),
    { subject: statement.payload.subject, maxClockSkewSeconds: 0 },
  );

  const revokeVector = await loadVector(directory, 'signing-key-revoke.json');
  const revokeRequest = revokeBySignatureRequestV1Schema.parse(revokeVector.request);
  const revokeGenesis = identityGenesisV1Schema.parse(revokeVector.genesis);
  const revokeVerification = object(revokeVector.verification, 'revoke.verification');
  assertExpectedSignedFields(revokeVector, revokeRequest.payload, revokeRequest.signature);
  assert.equal(
    await signProtocolPayload(revokeRequest.payload, identityKeyA.privateKey),
    revokeRequest.signature,
  );
  await verifyRevokeBySignature(revokeRequest, revokeGenesis, {
    subject: string(revokeVerification.subject, 'revoke.subject') as typeof subject,
    expectedSequence: integer(revokeVerification.expectedSequence, 'revoke.expectedSequence'),
    nonce: string(revokeVerification.nonce, 'revoke.nonce'),
    now: integer(revokeVerification.now, 'revoke.now'),
    maxClockSkewSeconds: integer(
      revokeVerification.maxClockSkewSeconds,
      'revoke.maxClockSkewSeconds',
    ),
  });

  const continuityVector = await loadVector(directory, 'continuity-link.json');
  const link = continuityLinkV1Schema.parse(continuityVector.link);
  const continuityVerification = object(continuityVector.verification, 'continuity.verification');
  assert.equal(canonicalize(link.payload), continuityVector.canonicalPayloadJcs);
  assert.equal(
    bytesToHex(createProtocolSignaturePreimage(link.payload)),
    continuityVector.signaturePreimageHex,
  );
  assert.equal(link.signatureA, continuityVector.signatureABase64Url);
  assert.equal(link.signatureB, continuityVector.signatureBBase64Url);
  assert.equal(await signProtocolPayload(link.payload, identityKeyA.privateKey), link.signatureA);
  assert.equal(await signProtocolPayload(link.payload, identityKeyB.privateKey), link.signatureB);
  assert.equal(
    await verifyProtocolPayload(link.payload, link.signatureA, identityKeyA.publicKey),
    true,
  );
  assert.equal(
    await verifyProtocolPayload(link.payload, link.signatureB, identityKeyB.publicKey),
    true,
  );
  await verifyContinuityLink(link, {
    subjectA: string(
      continuityVerification.subjectA,
      'continuity.subjectA',
    ) as typeof link.payload.subjectA,
    subjectB: string(
      continuityVerification.subjectB,
      'continuity.subjectB',
    ) as typeof link.payload.subjectB,
    scope: string(continuityVerification.scope, 'continuity.scope'),
    nonce: string(continuityVerification.nonce, 'continuity.nonce'),
    now: integer(continuityVerification.now, 'continuity.now'),
    maxClockSkewSeconds: integer(
      continuityVerification.maxClockSkewSeconds,
      'continuity.maxClockSkewSeconds',
    ),
  });

  return [
    'base64url',
    'canonicalization',
    'keys',
    'revocation-commitment',
    'identity',
    'ownership-proof',
    'registry-event',
    'registry-receipt',
    'status-statement',
    'signing-key-revoke',
    'continuity-link',
    'device-activation-v2',
    'device-authorization-v2',
    'device-registry-event-v2',
    'device-registry-receipt-v2',
    'device-status-statement-v2',
    'ownership-proof-v2',
    'transparency',
  ];
}
