import { NEXUS_EVENT_ID_PREFIX, NEXUS_SUBJECT_PREFIX, SHA256_BYTE_LENGTH } from './constants.js';
import { encodeBase64Url } from './base64url.js';
import type { NexusEventId, NexusSubject } from './types.js';

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
