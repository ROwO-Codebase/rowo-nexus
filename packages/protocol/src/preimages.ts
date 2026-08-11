import {
  GENESIS_HASH_DOMAIN,
  REGISTRY_EVENT_HASH_DOMAIN,
  REVOCATION_COMMITMENT_DOMAIN,
  REVOCATION_SECRET_BYTE_LENGTH,
  SIGNATURE_DOMAIN,
} from './constants.js';
import { canonicalizeToBytes } from './canonical.js';
import type {
  GlobalTransparencyCheckpointPayloadV1,
  IdentityGenesisV1,
  RegistryEventWithoutEventIdV1,
  TransparencyCheckpointPayloadV1,
} from './types.js';

const textEncoder = new TextEncoder();

function concatenate(...parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

export function createSignaturePreimage(
  protocolIdentifier: string,
  unsignedPayload: unknown,
): Uint8Array {
  if (!/^[\x20-\x7e]+$/u.test(protocolIdentifier) || protocolIdentifier.includes('\0')) {
    throw new TypeError('Protocol identifier must be non-empty printable ASCII without NUL.');
  }
  return concatenate(
    textEncoder.encode(SIGNATURE_DOMAIN),
    textEncoder.encode(protocolIdentifier),
    Uint8Array.of(0),
    canonicalizeToBytes(unsignedPayload),
  );
}

export function createGenesisHashPreimage(genesis: IdentityGenesisV1): Uint8Array {
  return concatenate(textEncoder.encode(GENESIS_HASH_DOMAIN), canonicalizeToBytes(genesis));
}

export function createRevocationCommitmentPreimage(secret32: Uint8Array): Uint8Array {
  if (secret32.length !== REVOCATION_SECRET_BYTE_LENGTH) {
    throw new RangeError(
      `Revocation secret must be ${String(REVOCATION_SECRET_BYTE_LENGTH)} bytes.`,
    );
  }
  return concatenate(textEncoder.encode(REVOCATION_COMMITMENT_DOMAIN), secret32);
}

export function createRegistryEventHashPreimage(
  eventWithoutEventId: RegistryEventWithoutEventIdV1,
): Uint8Array {
  return concatenate(
    textEncoder.encode(REGISTRY_EVENT_HASH_DOMAIN),
    canonicalizeToBytes(eventWithoutEventId),
  );
}

export function createTransparencyCheckpointSignaturePreimage(
  payload: TransparencyCheckpointPayloadV1,
): Uint8Array {
  return createSignaturePreimage(payload.protocol, payload);
}

export function createGlobalTransparencyCheckpointSignaturePreimage(
  payload: GlobalTransparencyCheckpointPayloadV1,
): Uint8Array {
  return createSignaturePreimage(payload.protocol, payload);
}
