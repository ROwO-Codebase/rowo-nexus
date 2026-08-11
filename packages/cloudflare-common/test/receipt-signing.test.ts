import { createProtocolSignaturePreimage } from '@nexus/crypto';
import {
  base64Url32Schema,
  decodeBase64Url,
  encodeBase64Url,
  formatRegistryEventId,
  formatSubject,
  type RegistryReceiptPayloadV1,
  type StatusStatementPayloadV1,
} from '@nexus/protocol';
import { describe, expect, it } from 'vitest';

import { signRegistryReceipt, signStatusStatement } from '../src/receipt-signing.js';

async function signingFixture(): Promise<{
  readonly config: {
    readonly signerKid: string;
    readonly privateKeyPkcs8: Uint8Array;
  };
  readonly publicKey: CryptoKey;
}> {
  const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  return {
    config: { signerKid: 'registry-2026-08', privateKeyPkcs8: pkcs8 },
    publicKey: pair.publicKey,
  };
}

const subject = formatSubject(new Uint8Array(32).fill(1));
const eventId = formatRegistryEventId(new Uint8Array(32).fill(2));
const genesisHash = base64Url32Schema.parse(encodeBase64Url(new Uint8Array(32).fill(3)));

function asArrayBufferView(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  copy.set(bytes);
  return copy;
}

describe('service receipt signing', () => {
  it('imports a PKCS#8 key and signs a registry payload', async () => {
    const { config, publicKey } = await signingFixture();
    const payload: RegistryReceiptPayloadV1 = {
      protocol: 'nexus.registry-receipt.v1',
      eventId,
      subject,
      genesisHash,
      eventType: 'registered',
      sequence: 0,
      state: 'active',
      acceptedAt: 1_786_400_000,
      signerKid: config.signerKid,
    };

    const receipt = await signRegistryReceipt(payload, config);
    const verified = await crypto.subtle.verify(
      'Ed25519',
      publicKey,
      asArrayBufferView(decodeBase64Url(receipt.signature)),
      asArrayBufferView(createProtocolSignaturePreimage(payload)),
    );

    expect(verified).toBe(true);
    expect(receipt.payload).toEqual(payload);
  });

  it('signs a short-lived status statement', async () => {
    const { config } = await signingFixture();
    const encodedConfig = {
      signerKid: config.signerKid,
      privateKeyPkcs8: encodeBase64Url(config.privateKeyPkcs8),
    };
    const payload: StatusStatementPayloadV1 = {
      protocol: 'nexus.status-statement.v1',
      subject,
      state: 'active',
      sequence: 0,
      registeredAt: 1_786_400_000,
      iat: 1_786_400_100,
      exp: 1_786_400_160,
      signerKid: config.signerKid,
    };

    await expect(signStatusStatement(payload, encodedConfig)).resolves.toMatchObject({ payload });
  });

  it('fails closed when payload kid and configured key kid differ', async () => {
    const { config } = await signingFixture();
    const payload: StatusStatementPayloadV1 = {
      protocol: 'nexus.status-statement.v1',
      subject,
      state: 'active',
      sequence: 0,
      registeredAt: 1_786_400_000,
      iat: 1_786_400_100,
      exp: 1_786_400_160,
      signerKid: 'unexpected-kid',
    };

    await expect(signStatusStatement(payload, config)).rejects.toMatchObject({
      code: 'INTERNAL_ERROR',
    });
  });
});
