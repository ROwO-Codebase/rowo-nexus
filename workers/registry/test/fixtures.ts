import {
  REVOKE_PROTOCOL_V1,
  REVOKE_SECRET_PROTOCOL_V1,
  base64Url32Schema,
  base64Url64Schema,
  deviceActivationRequestV2Schema,
  deviceAuthorizationPayloadV2Schema,
  deviceRootRevokeRequestV2Schema,
  deviceSelfRevokeRequestV2Schema,
  encodeBase64Url,
  identityGenesisV1Schema,
  revokeBySecretV1Schema,
  revokeBySignaturePayloadV1Schema,
} from '@nexus/protocol';
import type {
  IdentityGenesisV1,
  DeviceActivationRequestV2,
  DeviceAuthorizationV2,
  DeviceRootRevokeRequestV2,
  DeviceSelfRevokeRequestV2,
  NexusDeviceIdV2,
  RevokeBySecretV1,
  RevokeBySignaturePayloadV1,
} from '@nexus/protocol';
import {
  computeRevocationCommitment,
  deriveDeviceAuthorizationIdV2,
  deriveDeviceIdV2,
  deriveSubject,
  signProtocolPayload,
} from '@nexus/crypto';

import { prepareRegistration } from '../src/validation';
import type { PreparedRegistration } from '../src/types';

export interface IdentityFixture {
  genesis: IdentityGenesisV1;
  prepared: PreparedRegistration;
  privateKey: CryptoKey;
  secret: Uint8Array;
}

export interface DeviceFixture {
  authorization: DeviceAuthorizationV2;
  activation: DeviceActivationRequestV2;
  privateKey: CryptoKey;
}

export async function createIdentityFixture(): Promise<IdentityFixture> {
  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const commitment = await computeRevocationCommitment(secret);
  const genesis = identityGenesisV1Schema.parse({
    protocol: 'nexus.identity.v1',
    suite: 'NX-25519-SHA256-JCS-v1',
    signingKey: { alg: 'Ed25519', publicKey: encodeBase64Url(publicKey) },
    revocationCommitment: encodeBase64Url(commitment),
  });
  const subject = await deriveSubject(genesis);
  const preparedResult = await prepareRegistration({ subject, genesis });
  if (!preparedResult.ok) {
    throw new Error(`Fixture registration failed: ${preparedResult.error.code}`);
  }
  return { genesis, prepared: preparedResult.value, privateKey: keyPair.privateKey, secret };
}

export async function createSignatureRevocation(
  fixture: IdentityFixture,
): Promise<{ payload: RevokeBySignaturePayloadV1; signature: string }> {
  const payload = revokeBySignaturePayloadV1Schema.parse({
    protocol: REVOKE_PROTOCOL_V1,
    subject: fixture.prepared.subject,
    expectedSequence: 0,
    nonce: encodeBase64Url(crypto.getRandomValues(new Uint8Array(16))),
    iat: Math.floor(Date.now() / 1_000),
    reasonCode: 'dispose',
  });
  return {
    payload,
    signature: await signProtocolPayload(payload, fixture.privateKey),
  };
}

export function createSecretRevocation(fixture: IdentityFixture): RevokeBySecretV1 {
  return revokeBySecretV1Schema.parse({
    protocol: REVOKE_SECRET_PROTOCOL_V1,
    subject: fixture.prepared.subject,
    expectedSequence: 0,
    revocationSecret: encodeBase64Url(fixture.secret),
  });
}

export async function createDeviceFixture(fixture: IdentityFixture): Promise<DeviceFixture> {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicKey = base64Url32Schema.parse(
    encodeBase64Url(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))),
  );
  const now = Math.floor(Date.now() / 1_000);
  const deviceId = await deriveDeviceIdV2({
    subject: fixture.prepared.subject,
    signingKey: { alg: 'Ed25519', publicKey },
  });
  const payload = deviceAuthorizationPayloadV2Schema.parse({
    protocol: 'nexus.device-authorization.v2',
    subject: fixture.prepared.subject,
    genesisHash: fixture.prepared.genesisHash,
    deviceId,
    signingKey: { alg: 'Ed25519', publicKey },
    authorizationNonce: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    validFrom: now - 1,
    activationDeadline: now + 300,
    expiresAt: now + 3600,
  });
  const authorization: DeviceAuthorizationV2 = {
    payload,
    rootSignature: base64Url64Schema.parse(await signProtocolPayload(payload, fixture.privateKey)),
  };
  const authorizationId = await deriveDeviceAuthorizationIdV2(payload);
  const activationPayload = {
    protocol: 'nexus.device-activation.v2',
    subject: fixture.prepared.subject,
    deviceId,
    authorizationId,
    requestId: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    iat: now,
    exp: now + 60,
  } as const;
  const activation = deviceActivationRequestV2Schema.parse({
    authorization,
    payload: activationPayload,
    deviceSignature: await signProtocolPayload(activationPayload, pair.privateKey),
  });
  return { authorization, activation, privateKey: pair.privateKey };
}

export async function createDeviceSelfRevocation(
  fixture: IdentityFixture,
  device: DeviceFixture,
  issuedAt = Math.floor(Date.now() / 1_000),
): Promise<DeviceSelfRevokeRequestV2> {
  const authorizationId = await deriveDeviceAuthorizationIdV2(device.authorization.payload);
  const payload = {
    protocol: 'nexus.device-self-revoke.v2',
    subject: fixture.prepared.subject,
    genesisHash: fixture.prepared.genesisHash,
    deviceId: device.authorization.payload.deviceId,
    authorizationId,
    requestId: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    issuedAt,
    reasonCode: 'dispose',
  } as const;
  return deviceSelfRevokeRequestV2Schema.parse({
    authorization: device.authorization,
    payload,
    deviceSignature: await signProtocolPayload(payload, device.privateKey),
  });
}

export async function createDeviceRootRevocation(
  fixture: IdentityFixture,
  deviceId: NexusDeviceIdV2,
  issuedAt = Math.floor(Date.now() / 1_000),
): Promise<DeviceRootRevokeRequestV2> {
  const payload = {
    protocol: 'nexus.device-root-revoke.v2',
    subject: fixture.prepared.subject,
    genesisHash: fixture.prepared.genesisHash,
    deviceId,
    requestId: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    issuedAt,
    reasonCode: 'lost-device',
  } as const;
  return deviceRootRevokeRequestV2Schema.parse({
    payload,
    rootSignature: await signProtocolPayload(payload, fixture.privateKey),
  });
}
