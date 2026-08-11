import { canonicalize, canonicalizeToBytes, encodeBase64Url } from '@nexus/protocol';
import type {
  Base64Url32,
  RegistryEventV1,
  RevokeBySecretV1,
  RevokeBySignaturePayloadV1,
} from '@nexus/protocol';
import {
  createProtocolSignaturePreimage,
  deriveRegistryEventId,
  getDefaultCryptoProvider,
} from '@nexus/crypto';

export type RegistryEventWithoutId = Omit<RegistryEventV1, 'eventId'>;

export interface MaterializedRegistryEvent {
  event: RegistryEventV1;
  eventHash: Uint8Array;
  payloadJcs: string;
}

export async function materializeRegistryEvent(
  eventWithoutId: RegistryEventWithoutId,
): Promise<MaterializedRegistryEvent> {
  const { eventHash, eventId } = await deriveRegistryEventId(eventWithoutId);
  const event: RegistryEventV1 = { ...eventWithoutId, eventId };
  return { event, eventHash, payloadJcs: canonicalize(event) };
}

/**
 * NEXUS_SPEC v1 defines actionHash's field but not a new action hash domain.
 * The local v1 convention is deliberately limited to already-defined bytes:
 * registration uses genesisHash directly, signing revocation hashes the exact
 * protocol signature preimage, and secret revocation hashes a canonical copy
 * with the raw terminal secret replaced by the stored public commitment.
 */
export async function signatureRevocationActionHash(
  payload: RevokeBySignaturePayloadV1,
): Promise<Base64Url32> {
  const bytes = createProtocolSignaturePreimage(payload);
  return encodeBase64Url(await getDefaultCryptoProvider().sha256(bytes)) as Base64Url32;
}

export async function secretRevocationActionHash(
  payload: RevokeBySecretV1,
  storedCommitment: Uint8Array,
): Promise<Base64Url32> {
  const sanitized = {
    ...payload,
    revocationSecret: encodeBase64Url(storedCommitment),
  };
  const bytes = canonicalizeToBytes(sanitized);
  return encodeBase64Url(await getDefaultCryptoProvider().sha256(bytes)) as Base64Url32;
}
