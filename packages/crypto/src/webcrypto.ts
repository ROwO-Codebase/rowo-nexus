import type {
  Aes256GcmDecryptParameters,
  Aes256GcmEncryptParameters,
  CryptoProvider,
  Ed25519KeyPair,
  HkdfSha256Parameters,
  KeyGenerationOptions,
  PrivateKeyImportOptions,
  X25519KeyPair,
} from './provider.js';

const ED25519 = { name: 'Ed25519' } as const satisfies Algorithm;
const X25519 = { name: 'X25519' } as const satisfies Algorithm;
const SHA_256 = 'SHA-256';
const AES_GCM = 'AES-GCM';
const HKDF = 'HKDF';
const RAW_25519_KEY_BYTES = 32;
const AES_256_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;
const WEB_CRYPTO_RANDOM_QUOTA = 65_536;
const HKDF_SHA256_MAX_OUTPUT_BYTES = 255 * 32;

function copyToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function copyBuffer(buffer: ArrayBuffer): Uint8Array {
  return new Uint8Array(buffer.slice(0));
}

function requireByteLength(bytes: Uint8Array, expected: number, label: string): void {
  if (bytes.byteLength !== expected) {
    throw new RangeError(`${label} must be exactly ${expected} bytes.`);
  }
}

function requireNonNegativeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${label} must be a non-negative safe integer.`);
  }
}

function requirePositiveInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RangeError(`${label} must be a positive safe integer.`);
  }
}

function asEd25519KeyPair(keyPair: CryptoKeyPair): Ed25519KeyPair {
  return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
}

function asX25519KeyPair(keyPair: CryptoKeyPair): X25519KeyPair {
  return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
}

function requireKeyPair(generated: CryptoKey | CryptoKeyPair, algorithm: string): CryptoKeyPair {
  if ('publicKey' in generated && 'privateKey' in generated) {
    return generated;
  }
  throw new TypeError(`${algorithm} key generation did not return a key pair.`);
}

export class WebCryptoProvider implements CryptoProvider {
  readonly #crypto: Crypto;

  public constructor(webCrypto?: Crypto) {
    const resolvedCrypto = webCrypto ?? globalThis.crypto;
    if (typeof resolvedCrypto === 'undefined') {
      throw new Error('Web Crypto is not available in this runtime.');
    }
    this.#crypto = resolvedCrypto;
  }

  public randomBytes(length: number): Uint8Array {
    requireNonNegativeInteger(length, 'Random byte length');
    const output = new Uint8Array(length);

    for (let offset = 0; offset < output.byteLength; offset += WEB_CRYPTO_RANDOM_QUOTA) {
      const end = Math.min(offset + WEB_CRYPTO_RANDOM_QUOTA, output.byteLength);
      this.#crypto.getRandomValues(output.subarray(offset, end));
    }
    return output;
  }

  public async sha256(data: Uint8Array): Promise<Uint8Array> {
    const digest = await this.#crypto.subtle.digest(SHA_256, copyToArrayBuffer(data));
    return copyBuffer(digest);
  }

  public async generateEd25519KeyPair(options: KeyGenerationOptions = {}): Promise<Ed25519KeyPair> {
    const generated = await this.#crypto.subtle.generateKey(
      ED25519,
      options.privateKeyExtractable ?? false,
      ['sign', 'verify'],
    );
    return asEd25519KeyPair(requireKeyPair(generated, ED25519.name));
  }

  public async importEd25519PublicKey(raw32: Uint8Array): Promise<CryptoKey> {
    requireByteLength(raw32, RAW_25519_KEY_BYTES, 'Ed25519 public key');
    return this.#crypto.subtle.importKey('raw', copyToArrayBuffer(raw32), ED25519, true, [
      'verify',
    ]);
  }

  public async importEd25519PrivateKey(
    pkcs8: Uint8Array,
    options: PrivateKeyImportOptions = {},
  ): Promise<CryptoKey> {
    return this.#crypto.subtle.importKey(
      'pkcs8',
      copyToArrayBuffer(pkcs8),
      ED25519,
      options.extractable ?? false,
      ['sign'],
    );
  }

  public async exportEd25519PublicKey(key: CryptoKey): Promise<Uint8Array> {
    const exported = await this.#crypto.subtle.exportKey('raw', key);
    const raw = copyBuffer(exported);
    requireByteLength(raw, RAW_25519_KEY_BYTES, 'Exported Ed25519 public key');
    return raw;
  }

  public async exportEd25519PrivateKey(key: CryptoKey): Promise<Uint8Array> {
    return copyBuffer(await this.#crypto.subtle.exportKey('pkcs8', key));
  }

  public async signEd25519(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
    const signature = copyBuffer(
      await this.#crypto.subtle.sign(ED25519, privateKey, copyToArrayBuffer(data)),
    );
    requireByteLength(signature, ED25519_SIGNATURE_BYTES, 'Ed25519 signature');
    return signature;
  }

  public async verifyEd25519(
    publicKey: CryptoKey,
    signature64: Uint8Array,
    data: Uint8Array,
  ): Promise<boolean> {
    if (signature64.byteLength !== ED25519_SIGNATURE_BYTES) {
      return false;
    }
    return this.#crypto.subtle.verify(
      ED25519,
      publicKey,
      copyToArrayBuffer(signature64),
      copyToArrayBuffer(data),
    );
  }

  public async generateX25519KeyPair(options: KeyGenerationOptions = {}): Promise<X25519KeyPair> {
    const generated = await this.#crypto.subtle.generateKey(
      X25519,
      options.privateKeyExtractable ?? false,
      ['deriveBits'],
    );
    return asX25519KeyPair(requireKeyPair(generated, X25519.name));
  }

  public async importX25519PublicKey(raw32: Uint8Array): Promise<CryptoKey> {
    requireByteLength(raw32, RAW_25519_KEY_BYTES, 'X25519 public key');
    return this.#crypto.subtle.importKey('raw', copyToArrayBuffer(raw32), X25519, true, []);
  }

  public async importX25519PrivateKey(
    pkcs8: Uint8Array,
    options: PrivateKeyImportOptions = {},
  ): Promise<CryptoKey> {
    return this.#crypto.subtle.importKey(
      'pkcs8',
      copyToArrayBuffer(pkcs8),
      X25519,
      options.extractable ?? false,
      ['deriveBits'],
    );
  }

  public async exportX25519PublicKey(key: CryptoKey): Promise<Uint8Array> {
    const exported = copyBuffer(await this.#crypto.subtle.exportKey('raw', key));
    requireByteLength(exported, RAW_25519_KEY_BYTES, 'Exported X25519 public key');
    return exported;
  }

  public async exportX25519PrivateKey(key: CryptoKey): Promise<Uint8Array> {
    return copyBuffer(await this.#crypto.subtle.exportKey('pkcs8', key));
  }

  public async deriveX25519Bits(
    privateKey: CryptoKey,
    publicKey: CryptoKey,
    length: number,
  ): Promise<Uint8Array> {
    requirePositiveInteger(length, 'X25519 output length');
    const bits = await this.#crypto.subtle.deriveBits(
      { name: X25519.name, public: publicKey },
      privateKey,
      length * 8,
    );
    return copyBuffer(bits);
  }

  public async hkdfSha256(parameters: HkdfSha256Parameters): Promise<Uint8Array> {
    requirePositiveInteger(parameters.length, 'HKDF output length');
    if (parameters.length > HKDF_SHA256_MAX_OUTPUT_BYTES) {
      throw new RangeError(
        `HKDF-SHA-256 output must not exceed ${HKDF_SHA256_MAX_OUTPUT_BYTES} bytes.`,
      );
    }

    const inputKey = await this.#crypto.subtle.importKey(
      'raw',
      copyToArrayBuffer(parameters.inputKeyMaterial),
      HKDF,
      false,
      ['deriveBits'],
    );
    const bits = await this.#crypto.subtle.deriveBits(
      {
        name: HKDF,
        hash: SHA_256,
        salt: copyToArrayBuffer(parameters.salt),
        info: copyToArrayBuffer(parameters.info),
      },
      inputKey,
      parameters.length * 8,
    );
    return copyBuffer(bits);
  }

  public async encryptAes256Gcm(parameters: Aes256GcmEncryptParameters): Promise<Uint8Array> {
    const key = await this.importAes256GcmKey(parameters.key, ['encrypt']);
    const algorithm = this.createAesGcmParameters(parameters);
    return copyBuffer(
      await this.#crypto.subtle.encrypt(algorithm, key, copyToArrayBuffer(parameters.plaintext)),
    );
  }

  public async decryptAes256Gcm(parameters: Aes256GcmDecryptParameters): Promise<Uint8Array> {
    const key = await this.importAes256GcmKey(parameters.key, ['decrypt']);
    const algorithm = this.createAesGcmParameters(parameters);
    return copyBuffer(
      await this.#crypto.subtle.decrypt(algorithm, key, copyToArrayBuffer(parameters.ciphertext)),
    );
  }

  private async importAes256GcmKey(
    rawKey: Uint8Array,
    usages: readonly KeyUsage[],
  ): Promise<CryptoKey> {
    requireByteLength(rawKey, AES_256_KEY_BYTES, 'AES-256-GCM key');
    return this.#crypto.subtle.importKey(
      'raw',
      copyToArrayBuffer(rawKey),
      { name: AES_GCM, length: 256 },
      false,
      [...usages],
    );
  }

  private createAesGcmParameters(parameters: Aes256GcmEncryptParameters): AesGcmParams;
  private createAesGcmParameters(parameters: Aes256GcmDecryptParameters): AesGcmParams;
  private createAesGcmParameters(
    parameters: Aes256GcmEncryptParameters | Aes256GcmDecryptParameters,
  ): AesGcmParams {
    const algorithm: AesGcmParams = {
      name: AES_GCM,
      iv: copyToArrayBuffer(parameters.iv),
      tagLength: parameters.tagLength,
    };
    if (parameters.additionalData !== undefined) {
      algorithm.additionalData = copyToArrayBuffer(parameters.additionalData);
    }
    return algorithm;
  }
}

let defaultProvider: CryptoProvider | undefined;

export function getDefaultCryptoProvider(): CryptoProvider {
  defaultProvider ??= new WebCryptoProvider();
  return defaultProvider;
}
