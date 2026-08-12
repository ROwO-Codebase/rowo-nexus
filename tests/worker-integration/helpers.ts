import { env } from 'cloudflare:workers';

import {
  computeRevocationCommitment,
  deriveDeviceAuthorizationIdV2,
  deriveDeviceIdV2,
  deriveGenesisHash,
  deriveSubject,
  signProtocolPayload,
} from '@nexus/crypto';
import {
  OWNERSHIP_PROOF_PROTOCOL_V1,
  REVOKE_PROTOCOL_V1,
  REVOKE_SECRET_PROTOCOL_V1,
  base64Url32Schema,
  base64Url64Schema,
  deviceActivationRequestV2Schema,
  deviceAuthorizationPayloadV2Schema,
  deviceRegistryReceiptV2Schema,
  deviceRootRevokeRequestV2Schema,
  deviceStatusStatementV2Schema,
  encodeBase64Url,
  identityGenesisV1Schema,
  ownershipProofPayloadV1Schema,
  ownershipProofV1Schema,
  registryReceiptV1Schema,
  registryStatusV1Schema,
  revokeBySecretV1Schema,
  revokeBySignaturePayloadV1Schema,
  statusStatementV1Schema,
  type DeviceActivationRequestV2,
  type DeviceAuthorizationV2,
  type IdentityGenesisV1,
  type DeviceRegistryEventV2,
  type DeviceRegistryReceiptPayloadV2,
  type DeviceRootRevokeRequestV2,
  type DeviceStatusStatementPayloadV2,
  type NexusDeviceIdV2,
  type NexusSubject,
  type OwnershipProofV1,
  type RegistryEventV1,
  type RegistryReceiptPayloadV1,
  type RevokeBySecretV1,
  type StatusStatementPayloadV1,
} from '@nexus/protocol';

import {
  createEdgeApi,
  type Env as EdgeEnv,
  type RegistryService,
} from '../../workers/edge-api/src/index';
import { prepareRegistration } from '../../workers/registry/src/validation';

export const API_ORIGIN = 'https://nexus.rowo.link';
export const WALLET_ORIGIN = 'https://wallet.rowo.link';
export const RP_ORIGIN = 'https://rp.example';
export const ACTION = 'post.edit';
export const RESOURCE = 'post:acceptance';

const ZERO_32 = encodeBase64Url(new Uint8Array(32));
const ONE_32 = encodeBase64Url(new Uint8Array(32).fill(1));
const ZERO_64 = encodeBase64Url(new Uint8Array(64));

export interface AcceptanceIdentity {
  subject: NexusSubject;
  genesis: IdentityGenesisV1;
  genesisHash: string;
  privateKey: CryptoKey;
  revocationSecret: Uint8Array;
}

export interface AcceptanceDevice {
  authorization: DeviceAuthorizationV2;
  activation: DeviceActivationRequestV2;
  privateKey: CryptoKey;
}

export async function createAcceptanceIdentity(): Promise<AcceptanceIdentity> {
  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const signingPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  const revocationSecret = crypto.getRandomValues(new Uint8Array(32));
  const revocationCommitment = await computeRevocationCommitment(revocationSecret);
  const genesis = identityGenesisV1Schema.parse({
    protocol: 'nexus.identity.v1',
    suite: 'NX-25519-SHA256-JCS-v1',
    signingKey: { alg: 'Ed25519', publicKey: encodeBase64Url(signingPublicKey) },
    revocationCommitment: encodeBase64Url(revocationCommitment),
  });
  return {
    subject: await deriveSubject(genesis),
    genesis,
    genesisHash: encodeBase64Url(await deriveGenesisHash(genesis)),
    privateKey: keyPair.privateKey,
    revocationSecret,
  };
}

export async function createAcceptanceDevice(
  identity: AcceptanceIdentity,
  now: number,
): Promise<AcceptanceDevice> {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicKey = base64Url32Schema.parse(
    encodeBase64Url(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))),
  );
  const deviceId = await deriveDeviceIdV2({
    subject: identity.subject,
    signingKey: { alg: 'Ed25519', publicKey },
  });
  const payload = deviceAuthorizationPayloadV2Schema.parse({
    protocol: 'nexus.device-authorization.v2',
    subject: identity.subject,
    genesisHash: identity.genesisHash,
    deviceId,
    signingKey: { alg: 'Ed25519', publicKey },
    authorizationNonce: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    validFrom: now - 1,
    activationDeadline: now + 300,
    expiresAt: now + 3600,
  });
  const authorization: DeviceAuthorizationV2 = {
    payload,
    rootSignature: base64Url64Schema.parse(await signProtocolPayload(payload, identity.privateKey)),
  };
  const authorizationId = await deriveDeviceAuthorizationIdV2(payload);
  const activationPayload = {
    protocol: 'nexus.device-activation.v2',
    subject: identity.subject,
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

export async function rootRevokeAcceptanceDevice(
  identity: AcceptanceIdentity,
  deviceId: NexusDeviceIdV2,
  issuedAt: number,
): Promise<DeviceRootRevokeRequestV2> {
  const payload = {
    protocol: 'nexus.device-root-revoke.v2',
    subject: identity.subject,
    genesisHash: identity.genesisHash,
    deviceId,
    requestId: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    issuedAt,
    reasonCode: 'lost-device',
  } as const;
  return deviceRootRevokeRequestV2Schema.parse({
    payload,
    rootSignature: await signProtocolPayload(payload, identity.privateKey),
  });
}

export function registryServiceAdapter(): RegistryService {
  return {
    async register(input) {
      const prepared = await prepareRegistration(input);
      if (!prepared.ok) return prepared;
      return await env.IDENTITY_STATE.getByName(prepared.value.subject).register(prepared.value);
    },
    async status(subject) {
      return await env.IDENTITY_STATE.getByName(subject).status();
    },
    async statusBatch(subjects) {
      return await Promise.all(
        subjects.map(async (subject) => await env.IDENTITY_STATE.getByName(subject).status()),
      );
    },
    async revokeBySignature(input) {
      return await env.IDENTITY_STATE.getByName(input.payload.subject).revokeBySignature(input);
    },
    async revokeBySecret(input) {
      return await env.IDENTITY_STATE.getByName(input.subject).revokeBySecret(input);
    },
    async activateDevice(input) {
      return await env.IDENTITY_STATE.getByName(input.payload.subject).activateDevice(input);
    },
    async deviceStatus(input) {
      return await env.IDENTITY_STATE.getByName(input.subject).deviceStatus({
        deviceId: input.deviceId,
        authorizationId: input.authorizationId,
      });
    },
    async deviceStatusBatch(inputs) {
      return await Promise.all(
        inputs.map(
          async (input) =>
            await env.IDENTITY_STATE.getByName(input.subject).deviceStatus({
              deviceId: input.deviceId,
              authorizationId: input.authorizationId,
            }),
        ),
      );
    },
    async revokeDeviceSelf(input) {
      return await env.IDENTITY_STATE.getByName(input.payload.subject).revokeDeviceSelf(input);
    },
    async revokeDeviceRoot(input) {
      return await env.IDENTITY_STATE.getByName(input.payload.subject).revokeDeviceRoot(input);
    },
  };
}

function fakeReceiptSignature(payload: RegistryReceiptPayloadV1) {
  return Promise.resolve(registryReceiptV1Schema.parse({ payload, signature: ZERO_64 }));
}

function fakeStatusSignature(payload: StatusStatementPayloadV1) {
  return Promise.resolve(statusStatementV1Schema.parse({ payload, signature: ZERO_64 }));
}

function fakeDeviceReceiptSignature(payload: DeviceRegistryReceiptPayloadV2) {
  return Promise.resolve(deviceRegistryReceiptV2Schema.parse({ payload, signature: ZERO_64 }));
}

function fakeDeviceStatusSignature(payload: DeviceStatusStatementPayloadV2) {
  return Promise.resolve(deviceStatusStatementV2Schema.parse({ payload, signature: ZERO_64 }));
}

export function createAcceptanceEdge(now: number) {
  const registry = registryServiceAdapter();
  const edgeEnv: EdgeEnv = {
    REGISTRY_SERVICE: registry,
    PUBLIC_API_RATE_LIMITER: { limit: () => Promise.resolve({ success: true }) },
    PUBLIC_API_ORIGIN: API_ORIGIN,
    WALLET_ORIGIN,
    STATUS_TTL_SECONDS: '60',
    SERVICE_JWKS_JSON: JSON.stringify({
      keys: [
        {
          kty: 'OKP',
          crv: 'Ed25519',
          alg: 'EdDSA',
          kid: 'acceptance-receipt',
          x: ZERO_32,
          use: 'sig',
        },
        {
          kty: 'OKP',
          crv: 'Ed25519',
          alg: 'EdDSA',
          kid: 'acceptance-status',
          x: ONE_32,
          use: 'sig',
        },
      ],
    }),
    RECEIPT_SIGNING_KID: 'acceptance-receipt',
    RECEIPT_SIGNING_PRIVATE_KEY: 'acceptance-test-only',
    STATUS_SIGNING_KID: 'acceptance-status',
    STATUS_SIGNING_PRIVATE_KEY: 'acceptance-test-only',
  };
  const app = createEdgeApi({
    now: () => now,
    monotonicNow: () => 1,
    requestId: () => `nxr_${'A'.repeat(22)}`,
    metricSink: null,
    signReceipt: fakeReceiptSignature,
    signStatus: fakeStatusSignature,
    signDeviceReceipt: fakeDeviceReceiptSignature,
    signDeviceStatus: fakeDeviceStatusSignature,
  });
  return { app, edgeEnv, registry };
}

export function nexusPost(path: string, body: unknown, origin?: string): Request {
  return new Request(`${API_ORIGIN}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/nexus+json',
      ...(origin === undefined ? {} : { Origin: origin }),
    },
    body: JSON.stringify(body),
  });
}

export async function registerThroughEdge(
  identity: AcceptanceIdentity,
  now: number,
): Promise<Response> {
  const { app, edgeEnv } = createAcceptanceEdge(now);
  return await app.fetch(
    nexusPost(
      '/v1/identity/register',
      { subject: identity.subject, genesis: identity.genesis },
      WALLET_ORIGIN,
    ),
    edgeEnv,
  );
}

export function secretRevocation(identity: AcceptanceIdentity): RevokeBySecretV1 {
  return revokeBySecretV1Schema.parse({
    protocol: REVOKE_SECRET_PROTOCOL_V1,
    subject: identity.subject,
    expectedSequence: 0,
    revocationSecret: encodeBase64Url(identity.revocationSecret),
  });
}

export async function signatureRevocation(identity: AcceptanceIdentity, now: number) {
  const payload = revokeBySignaturePayloadV1Schema.parse({
    protocol: REVOKE_PROTOCOL_V1,
    subject: identity.subject,
    expectedSequence: 0,
    nonce: encodeBase64Url(crypto.getRandomValues(new Uint8Array(16))),
    iat: now,
    reasonCode: 'dispose',
  });
  return { payload, signature: await signProtocolPayload(payload, identity.privateKey) };
}

export async function ownershipProof(
  identity: AcceptanceIdentity,
  nonce: string,
  now: number,
): Promise<OwnershipProofV1> {
  const payload = ownershipProofPayloadV1Schema.parse({
    protocol: OWNERSHIP_PROOF_PROTOCOL_V1,
    subject: identity.subject,
    genesis: identity.genesis,
    aud: RP_ORIGIN,
    act: ACTION,
    resource: RESOURCE,
    nonce,
    iat: now - 5,
    exp: now + 55,
  });
  return ownershipProofV1Schema.parse({
    payload,
    signature: await signProtocolPayload(payload, identity.privateKey),
  });
}

export async function authoritativeStatusThroughEdge(subject: NexusSubject, now: number) {
  const { app, edgeEnv } = createAcceptanceEdge(now);
  const response = await app.fetch(
    nexusPost('/v1/identity/status', { subject }, RP_ORIGIN),
    edgeEnv,
  );
  if (response.status === 404) return { state: 'not-found' as const };
  if (!response.ok) throw new Error(`Authoritative status failed with HTTP ${response.status}.`);
  const status = registryStatusV1Schema.parse(await response.json());
  return status.state === 'active'
    ? {
        state: 'active' as const,
        sequence: status.sequence,
        registeredAt: status.registeredAt,
      }
    : {
        state: 'revoked' as const,
        sequence: status.sequence,
        registeredAt: status.registeredAt,
        ...(status.revokedAt === null ? {} : { revokedAt: status.revokedAt }),
      };
}

export async function resetAcceptanceState(): Promise<void> {
  await Promise.all([env.TEST_QUEUE_CONTROL.reset(), env.TEST_DEVICE_QUEUE_CONTROL.reset()]);
  await env.INDEX_DB.batch([
    env.INDEX_DB.prepare('DELETE FROM device_projection_heads'),
    env.INDEX_DB.prepare('DELETE FROM device_states'),
    env.INDEX_DB.prepare('DELETE FROM device_registry_events'),
    env.INDEX_DB.prepare('DELETE FROM registry_events'),
    env.INDEX_DB.prepare('DELETE FROM pending_registry_events'),
    env.INDEX_DB.prepare('DELETE FROM identities'),
  ]);
}

export async function queuedEvents(expectedCount: number): Promise<RegistryEventV1[]> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const messages = await env.TEST_QUEUE_CONTROL.getMessages();
    if (messages.length >= expectedCount) return messages;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`Timed out waiting for ${expectedCount} registry Queue messages.`);
}

export async function queuedDeviceEvents(expectedCount: number): Promise<DeviceRegistryEventV2[]> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const messages = await env.TEST_DEVICE_QUEUE_CONTROL.getMessages();
    if (messages.length >= expectedCount) return messages;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`Timed out waiting for ${expectedCount} device registry Queue messages.`);
}
