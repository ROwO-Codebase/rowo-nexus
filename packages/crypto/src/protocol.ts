import {
  createDeviceAuthorizationHashPreimageV2,
  createDeviceIdHashPreimageV2,
  createDeviceOperationHashPreimageV2,
  createDeviceRegistryEventHashPreimageV2,
  createGenesisHashPreimage as createCanonicalGenesisHashPreimage,
  createRegistryEventHashPreimage as createCanonicalRegistryEventHashPreimage,
  createRevocationCommitmentPreimage as createCanonicalRevocationCommitmentPreimage,
  createSignaturePreimage,
  decodeBase64UrlExact,
  ED25519_SIGNATURE_BYTE_LENGTH,
  encodeBase64Url,
  formatRegistryEventId,
  formatDeviceAuthorizationIdV2,
  formatDeviceIdV2,
  formatDeviceOperationIdV2,
  formatDeviceRegistryEventIdV2,
  formatSubject,
  SHA256_BYTE_LENGTH,
} from '@nexus/protocol';
import type {
  DeviceAuthorizationPayloadV2,
  DeviceIdInputV2,
  DeviceOperationPayloadV2,
  DeviceRegistryEventWithoutEventIdV2,
  IdentityGenesisV1,
  NexusEventId,
  NexusDeviceAuthorizationIdV2,
  NexusDeviceEventIdV2,
  NexusDeviceIdV2,
  NexusDeviceOperationIdV2,
  NexusSubject,
  RegistryEventWithoutEventIdV1,
} from '@nexus/protocol';

import type { CryptoProvider } from './provider.js';
import { getDefaultCryptoProvider } from './webcrypto.js';

const ASCII_PROTOCOL_IDENTIFIER = /^[\x21-\x7e]+$/;

export interface ProtocolPayload {
  readonly protocol: string;
}

function assertProtocolIdentifier(protocol: string): void {
  if (!ASCII_PROTOCOL_IDENTIFIER.test(protocol)) {
    throw new TypeError('Protocol identifier must be a non-empty printable ASCII string.');
  }
}

function requireExactLength(value: Uint8Array, length: number, label: string): void {
  if (value.byteLength !== length) {
    throw new RangeError(`${label} must be exactly ${length} bytes.`);
  }
}

export function createProtocolSignaturePreimage<T extends ProtocolPayload>(payload: T): Uint8Array {
  assertProtocolIdentifier(payload.protocol);
  return createSignaturePreimage(payload.protocol, payload);
}

export function createRevocationCommitmentPreimage(secret32: Uint8Array): Uint8Array {
  return createCanonicalRevocationCommitmentPreimage(secret32);
}

export function createGenesisHashPreimage(genesis: IdentityGenesisV1): Uint8Array {
  return createCanonicalGenesisHashPreimage(genesis);
}

export function createRegistryEventHashPreimage(
  eventWithoutEventId: RegistryEventWithoutEventIdV1,
): Uint8Array {
  return createCanonicalRegistryEventHashPreimage(eventWithoutEventId);
}

export async function signProtocolPayload<T extends ProtocolPayload>(
  payload: T,
  privateKey: CryptoKey,
  provider: CryptoProvider = getDefaultCryptoProvider(),
): Promise<string> {
  const signature = await provider.signEd25519(
    privateKey,
    createProtocolSignaturePreimage(payload),
  );
  requireExactLength(signature, ED25519_SIGNATURE_BYTE_LENGTH, 'Ed25519 signature');
  return encodeBase64Url(signature);
}

export async function verifyProtocolPayload<T extends ProtocolPayload>(
  payload: T,
  signature: string,
  publicKey: CryptoKey,
  provider: CryptoProvider = getDefaultCryptoProvider(),
): Promise<boolean> {
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = decodeBase64UrlExact(signature, ED25519_SIGNATURE_BYTE_LENGTH);
  } catch {
    return false;
  }
  return provider.verifyEd25519(
    publicKey,
    signatureBytes,
    createProtocolSignaturePreimage(payload),
  );
}

export async function computeRevocationCommitment(
  secret32: Uint8Array,
  provider: CryptoProvider = getDefaultCryptoProvider(),
): Promise<Uint8Array> {
  return provider.sha256(createRevocationCommitmentPreimage(secret32));
}

export async function deriveGenesisHash(
  genesis: IdentityGenesisV1,
  provider: CryptoProvider = getDefaultCryptoProvider(),
): Promise<Uint8Array> {
  return provider.sha256(createGenesisHashPreimage(genesis));
}

export async function deriveSubject(
  genesis: IdentityGenesisV1,
  provider: CryptoProvider = getDefaultCryptoProvider(),
): Promise<NexusSubject> {
  const hash = await deriveGenesisHash(genesis, provider);
  requireExactLength(hash, SHA256_BYTE_LENGTH, 'Genesis hash');
  return formatSubject(hash);
}

export async function deriveRegistryEventId(
  eventWithoutEventId: RegistryEventWithoutEventIdV1,
  provider: CryptoProvider = getDefaultCryptoProvider(),
): Promise<{ readonly eventHash: Uint8Array; readonly eventId: NexusEventId }> {
  const eventHash = await provider.sha256(createRegistryEventHashPreimage(eventWithoutEventId));
  requireExactLength(eventHash, SHA256_BYTE_LENGTH, 'Registry event hash');
  return {
    eventHash,
    eventId: formatRegistryEventId(eventHash),
  };
}

export async function deriveDeviceIdV2(
  input: DeviceIdInputV2,
  provider: CryptoProvider = getDefaultCryptoProvider(),
): Promise<NexusDeviceIdV2> {
  const hash = await provider.sha256(createDeviceIdHashPreimageV2(input));
  requireExactLength(hash, SHA256_BYTE_LENGTH, 'Device ID hash');
  return formatDeviceIdV2(hash);
}

export async function deriveDeviceAuthorizationIdV2(
  payload: DeviceAuthorizationPayloadV2,
  provider: CryptoProvider = getDefaultCryptoProvider(),
): Promise<NexusDeviceAuthorizationIdV2> {
  const hash = await provider.sha256(createDeviceAuthorizationHashPreimageV2(payload));
  requireExactLength(hash, SHA256_BYTE_LENGTH, 'Device authorization hash');
  return formatDeviceAuthorizationIdV2(hash);
}

export async function deriveDeviceOperationIdV2(
  signedPayload: DeviceOperationPayloadV2,
  provider: CryptoProvider = getDefaultCryptoProvider(),
): Promise<NexusDeviceOperationIdV2> {
  const hash = await provider.sha256(createDeviceOperationHashPreimageV2(signedPayload));
  requireExactLength(hash, SHA256_BYTE_LENGTH, 'Device operation hash');
  return formatDeviceOperationIdV2(hash);
}

export async function deriveDeviceRegistryEventIdV2(
  eventWithoutEventId: DeviceRegistryEventWithoutEventIdV2,
  provider: CryptoProvider = getDefaultCryptoProvider(),
): Promise<{
  readonly eventHash: Uint8Array;
  readonly eventId: NexusDeviceEventIdV2;
}> {
  const eventHash = await provider.sha256(
    createDeviceRegistryEventHashPreimageV2(eventWithoutEventId),
  );
  requireExactLength(eventHash, SHA256_BYTE_LENGTH, 'Device registry event hash');
  return { eventHash, eventId: formatDeviceRegistryEventIdV2(eventHash) };
}
