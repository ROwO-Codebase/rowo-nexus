export interface KeyGenerationOptions {
  readonly privateKeyExtractable?: boolean;
}

export interface PrivateKeyImportOptions {
  readonly extractable?: boolean;
}

export interface Ed25519KeyPair {
  readonly publicKey: CryptoKey;
  readonly privateKey: CryptoKey;
}

export interface X25519KeyPair {
  readonly publicKey: CryptoKey;
  readonly privateKey: CryptoKey;
}

export interface HkdfSha256Parameters {
  readonly inputKeyMaterial: Uint8Array;
  readonly salt: Uint8Array;
  readonly info: Uint8Array;
  /** Output length in bytes. */
  readonly length: number;
}

export type AesGcmTagLength = 32 | 64 | 96 | 104 | 112 | 120 | 128;

export interface Aes256GcmParameters {
  /** Exactly 32 raw key bytes. */
  readonly key: Uint8Array;
  /** Caller-selected IV. This primitive helper does not define a wire format. */
  readonly iv: Uint8Array;
  readonly additionalData?: Uint8Array;
  /** Explicit tag length in bits. */
  readonly tagLength: AesGcmTagLength;
}

export interface Aes256GcmEncryptParameters extends Aes256GcmParameters {
  readonly plaintext: Uint8Array;
}

export interface Aes256GcmDecryptParameters extends Aes256GcmParameters {
  /** Web Crypto AES-GCM output: ciphertext followed by the authentication tag. */
  readonly ciphertext: Uint8Array;
}

export interface CryptoProvider {
  randomBytes(length: number): Uint8Array;
  sha256(data: Uint8Array): Promise<Uint8Array>;

  generateEd25519KeyPair(options?: KeyGenerationOptions): Promise<Ed25519KeyPair>;
  importEd25519PublicKey(raw32: Uint8Array): Promise<CryptoKey>;
  importEd25519PrivateKey(pkcs8: Uint8Array, options?: PrivateKeyImportOptions): Promise<CryptoKey>;
  exportEd25519PublicKey(key: CryptoKey): Promise<Uint8Array>;
  exportEd25519PrivateKey(key: CryptoKey): Promise<Uint8Array>;
  signEd25519(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array>;
  verifyEd25519(publicKey: CryptoKey, signature64: Uint8Array, data: Uint8Array): Promise<boolean>;

  generateX25519KeyPair(options?: KeyGenerationOptions): Promise<X25519KeyPair>;
  importX25519PublicKey(raw32: Uint8Array): Promise<CryptoKey>;
  importX25519PrivateKey(pkcs8: Uint8Array, options?: PrivateKeyImportOptions): Promise<CryptoKey>;
  exportX25519PublicKey(key: CryptoKey): Promise<Uint8Array>;
  exportX25519PrivateKey(key: CryptoKey): Promise<Uint8Array>;
  deriveX25519Bits(
    privateKey: CryptoKey,
    publicKey: CryptoKey,
    length: number,
  ): Promise<Uint8Array>;

  hkdfSha256(parameters: HkdfSha256Parameters): Promise<Uint8Array>;
  encryptAes256Gcm(parameters: Aes256GcmEncryptParameters): Promise<Uint8Array>;
  decryptAes256Gcm(parameters: Aes256GcmDecryptParameters): Promise<Uint8Array>;
}
