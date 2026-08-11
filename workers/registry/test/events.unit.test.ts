import {
  canonicalizeToBytes,
  encodeBase64Url,
  registryEventWithoutEventIdV1Schema,
  revokeBySecretV1Schema,
  revokeBySignaturePayloadV1Schema,
} from '@nexus/protocol';
import { createProtocolSignaturePreimage, getDefaultCryptoProvider } from '@nexus/crypto';
import { describe, expect, it } from 'vitest';

import {
  materializeRegistryEvent,
  secretRevocationActionHash,
  signatureRevocationActionHash,
} from '../src/events';

const HASH = encodeBase64Url(new Uint8Array(32).fill(7));
const SUBJECT = `nx1_${HASH}` as const;

describe('registry event materialization', () => {
  it('derives a stable eventId from the exact v1 event without eventId', async () => {
    const input = registryEventWithoutEventIdV1Schema.parse({
      protocol: 'nexus.registry-event.v1',
      eventType: 'registered',
      subject: SUBJECT,
      genesisHash: HASH,
      sequence: 0,
      state: 'active',
      acceptedAt: 1_786_400_000,
      actionHash: HASH,
    });
    const first = await materializeRegistryEvent(input);
    const second = await materializeRegistryEvent(input);

    expect(first.event.eventId).toMatch(/^nxe1_[A-Za-z0-9_-]{43}$/u);
    expect(first.event.eventId).toBe(second.event.eventId);
    expect(first.eventHash).toEqual(second.eventHash);
    expect(JSON.parse(first.payloadJcs)).toEqual(first.event);
  });
});

describe('v1 actionHash convention', () => {
  it('hashes the already-specified signature preimage for signed revocation', async () => {
    const payload = revokeBySignaturePayloadV1Schema.parse({
      protocol: 'nexus.revoke.v1',
      subject: SUBJECT,
      expectedSequence: 0,
      nonce: encodeBase64Url(new Uint8Array(16).fill(3)),
      iat: 1_786_400_000,
    });
    const expected = encodeBase64Url(
      await getDefaultCryptoProvider().sha256(createProtocolSignaturePreimage(payload)),
    );
    await expect(signatureRevocationActionHash(payload)).resolves.toBe(expected);
  });

  it('replaces the raw secret with the stored commitment before hashing', async () => {
    const base = {
      protocol: 'nexus.revoke-secret.v1',
      subject: SUBJECT,
      expectedSequence: 0,
    } as const;
    const first = revokeBySecretV1Schema.parse({
      ...base,
      revocationSecret: encodeBase64Url(new Uint8Array(32).fill(1)),
    });
    const second = revokeBySecretV1Schema.parse({
      ...base,
      revocationSecret: encodeBase64Url(new Uint8Array(32).fill(2)),
    });
    const commitment = new Uint8Array(32).fill(9);
    const sanitized = { ...first, revocationSecret: encodeBase64Url(commitment) };
    const expected = encodeBase64Url(
      await getDefaultCryptoProvider().sha256(canonicalizeToBytes(sanitized)),
    );

    await expect(secretRevocationActionHash(first, commitment)).resolves.toBe(expected);
    await expect(secretRevocationActionHash(second, commitment)).resolves.toBe(expected);
  });
});
