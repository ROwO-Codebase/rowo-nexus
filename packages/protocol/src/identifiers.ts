import {
  NEXUS_DEVICE_AUTHORIZATION_ID_PREFIX_V2,
  NEXUS_DEVICE_EVENT_ID_PREFIX_V2,
  NEXUS_DEVICE_ID_PREFIX_V2,
  NEXUS_DEVICE_OPERATION_ID_PREFIX_V2,
  NEXUS_EVENT_ID_PREFIX,
  NEXUS_SUBJECT_PREFIX,
  SHA256_BYTE_LENGTH,
} from './constants.js';
import { encodeBase64Url } from './base64url.js';
import type {
  NexusDeviceAuthorizationIdV2,
  NexusDeviceEventIdV2,
  NexusDeviceIdV2,
  NexusDeviceOperationIdV2,
  NexusEventId,
  NexusSubject,
} from './types.js';

function requireHash32(hash: Uint8Array): void {
  if (hash.length !== SHA256_BYTE_LENGTH) {
    throw new RangeError(`Expected a ${String(SHA256_BYTE_LENGTH)}-byte SHA-256 hash.`);
  }
}

export function formatSubject(genesisHash: Uint8Array): NexusSubject {
  requireHash32(genesisHash);
  return `${NEXUS_SUBJECT_PREFIX}${encodeBase64Url(genesisHash)}`;
}

export function formatRegistryEventId(eventHash: Uint8Array): NexusEventId {
  requireHash32(eventHash);
  return `${NEXUS_EVENT_ID_PREFIX}${encodeBase64Url(eventHash)}`;
}

export function formatDeviceIdV2(deviceHash: Uint8Array): NexusDeviceIdV2 {
  requireHash32(deviceHash);
  return `${NEXUS_DEVICE_ID_PREFIX_V2}${encodeBase64Url(deviceHash)}`;
}

export function formatDeviceAuthorizationIdV2(
  authorizationHash: Uint8Array,
): NexusDeviceAuthorizationIdV2 {
  requireHash32(authorizationHash);
  return `${NEXUS_DEVICE_AUTHORIZATION_ID_PREFIX_V2}${encodeBase64Url(authorizationHash)}`;
}

export function formatDeviceOperationIdV2(operationHash: Uint8Array): NexusDeviceOperationIdV2 {
  requireHash32(operationHash);
  return `${NEXUS_DEVICE_OPERATION_ID_PREFIX_V2}${encodeBase64Url(operationHash)}`;
}

export function formatDeviceRegistryEventIdV2(eventHash: Uint8Array): NexusDeviceEventIdV2 {
  requireHash32(eventHash);
  return `${NEXUS_DEVICE_EVENT_ID_PREFIX_V2}${encodeBase64Url(eventHash)}`;
}
