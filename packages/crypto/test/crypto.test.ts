import { describe, expect, it } from 'vitest';

import {
  concatBytes,
  constantTimeEqual,
  createProtocolSignaturePreimage,
  signProtocolPayload,
  utf8Encode,
  verifyProtocolPayload,
  WebCryptoProvider,
} from '../src/index.js';

const provider = new WebCryptoProvider();

describe('WebCryptoProvider', () => {
  it('hashes with SHA-256', async () => {
    const digest = await provider.sha256(utf8Encode('abc'));
    expect(toHex(digest)).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('generates, imports, exports, signs, and verifies Ed25519 keys', async () => {
    const generated = await provider.generateEd25519KeyPair({ privateKeyExtractable: true });
    const rawPublicKey = await provider.exportEd25519PublicKey(generated.publicKey);
    const pkcs8PrivateKey = await provider.exportEd25519PrivateKey(generated.privateKey);
    const publicKey = await provider.importEd25519PublicKey(rawPublicKey);
    const privateKey = await provider.importEd25519PrivateKey(pkcs8PrivateKey);
    const message = utf8Encode('Nexus signing test');
    const signature = await provider.signEd25519(privateKey, message);

    expect(rawPublicKey).toHaveLength(32);
    expect(signature).toHaveLength(64);
    await expect(provider.verifyEd25519(publicKey, signature, message)).resolves.toBe(true);
    await expect(
      provider.verifyEd25519(publicKey, signature, utf8Encode('modified')),
    ).resolves.toBe(false);
  });

  it('creates and verifies domain-separated protocol signatures', async () => {
    const keys = await provider.generateEd25519KeyPair();
    const payload = {
      protocol: 'nexus.test.v1',
      nested: { z: 2, a: 1 },
      value: 'signed',
    } as const;
    const signature = await signProtocolPayload(payload, keys.privateKey, provider);

    await expect(verifyProtocolPayload(payload, signature, keys.publicKey, provider)).resolves.toBe(
      true,
    );
    await expect(
      verifyProtocolPayload({ ...payload, value: 'tampered' }, signature, keys.publicKey, provider),
    ).resolves.toBe(false);
    await expect(
      verifyProtocolPayload(payload, `${signature}=`, keys.publicKey, provider),
    ).resolves.toBe(false);

    const expectedPrefix = concatBytes(
      utf8Encode('NEXUS-SIGNATURE\0'),
      utf8Encode(payload.protocol),
      new Uint8Array([0]),
    );
    expect(createProtocolSignaturePreimage(payload).slice(0, expectedPrefix.length)).toEqual(
      expectedPrefix,
    );
    expect(
      createProtocolSignaturePreimage({
        protocol: payload.protocol,
        value: payload.value,
        nested: { a: 1, z: 2 },
      }),
    ).toEqual(createProtocolSignaturePreimage(payload));
  });

  it('derives HKDF-SHA-256 output deterministically', async () => {
    const parameters = {
      inputKeyMaterial: new Uint8Array(22).fill(0x0b),
      salt: fromHex('000102030405060708090a0b0c'),
      info: fromHex('f0f1f2f3f4f5f6f7f8f9'),
      length: 42,
    } as const;
    const output = await provider.hkdfSha256(parameters);

    expect(toHex(output)).toBe(
      '3cb25f25faacd57a90434f64d0362f2a' +
        '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
        '34007208d5b887185865',
    );
  });

  it('round-trips AES-256-GCM and rejects tampering', async () => {
    const key = provider.randomBytes(32);
    const iv = provider.randomBytes(12);
    const additionalData = utf8Encode('explicit associated data');
    const plaintext = utf8Encode('opaque wallet backup material');
    const ciphertext = await provider.encryptAes256Gcm({
      key,
      iv,
      additionalData,
      tagLength: 128,
      plaintext,
    });
    const decrypted = await provider.decryptAes256Gcm({
      key,
      iv,
      additionalData,
      tagLength: 128,
      ciphertext,
    });

    expect(decrypted).toEqual(plaintext);

    const tampered = ciphertext.slice();
    tampered[0] = (tampered[0] ?? 0) ^ 1;
    await expect(
      provider.decryptAes256Gcm({
        key,
        iv,
        additionalData,
        tagLength: 128,
        ciphertext: tampered,
      }),
    ).rejects.toBeDefined();
  });

  it('generates requested random lengths, including values above one Web Crypto quota', () => {
    for (const length of [0, 1, 16, 32, 65_537]) {
      expect(provider.randomBytes(length)).toHaveLength(length);
    }
    expect(() => provider.randomBytes(-1)).toThrow(RangeError);
    expect(() => provider.randomBytes(1.5)).toThrow(RangeError);
  });

  it('supports optional X25519 key agreement', async () => {
    const alice = await provider.generateX25519KeyPair();
    const bob = await provider.generateX25519KeyPair();
    const alicePublicRaw = await provider.exportX25519PublicKey(alice.publicKey);
    const bobPublicRaw = await provider.exportX25519PublicKey(bob.publicKey);
    const alicePublic = await provider.importX25519PublicKey(alicePublicRaw);
    const bobPublic = await provider.importX25519PublicKey(bobPublicRaw);

    const aliceShared = await provider.deriveX25519Bits(alice.privateKey, bobPublic, 32);
    const bobShared = await provider.deriveX25519Bits(bob.privateKey, alicePublic, 32);

    expect(aliceShared).toHaveLength(32);
    expect(aliceShared).toEqual(bobShared);
  });
});

describe('byte helpers', () => {
  it('concatenates UTF-8 and binary data without mutation', () => {
    const first = utf8Encode('ROwO');
    const second = new Uint8Array([0, 1, 2]);
    const joined = concatBytes(first, second);

    expect(joined).toEqual(new Uint8Array([...first, 0, 1, 2]));
    joined[0] = 0;
    expect(first[0]).not.toBe(0);
  });

  it('compares equal and unequal byte strings with length included', () => {
    expect(constantTimeEqual(new Uint8Array(), new Uint8Array())).toBe(true);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 0]))).toBe(false);
  });
});

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function fromHex(value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(value)) {
    throw new TypeError('Expected canonical lowercase hexadecimal.');
  }
  const output = new Uint8Array(value.length / 2);
  for (let offset = 0; offset < value.length; offset += 2) {
    output[offset / 2] = Number.parseInt(value.slice(offset, offset + 2), 16);
  }
  return output;
}
