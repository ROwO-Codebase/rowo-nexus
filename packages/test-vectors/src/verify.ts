import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import {
  concatBytes,
  computeRevocationCommitment,
  createGenesisHashPreimage,
  createProtocolSignaturePreimage,
  createRegistryEventHashPreimage,
  createRevocationCommitmentPreimage,
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
  createGlobalTransparencyCheckpointSignaturePreimage,
  createTransparencyCheckpointSignaturePreimage,
  decodeBase64Url,
  encodeBase64Url,
  identityGenesisV1Schema,
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

async function loadVector(directory: URL, name: string): Promise<JsonObject> {
  const parsed: unknown = JSON.parse(await readFile(new URL(name, directory), 'utf8'));
  const vector = object(parsed, name);
  assert.equal(vector.schema, 'nexus.test-vectors.v1', `${name}: schema`);
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
    'transparency',
  ];
}
