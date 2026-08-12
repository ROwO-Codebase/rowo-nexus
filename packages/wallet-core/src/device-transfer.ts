import type { CryptoProvider } from '@nexus/crypto';
import {
  canonicalizeToBytes,
  decodeBase64Url,
  decodeBase64UrlExact,
  encodeBase64Url,
  type DeviceAuthorizationV2,
  type IdentityGenesisV1,
  type NexusSubject,
} from '@nexus/protocol';

import { WalletCoreError } from './errors.js';
import type { DeviceTransferEnvelopeV2 } from './types.js';

const TRANSFER_PROTOCOL = 'nexus.device-transfer.v2' as const;
const TRANSFER_PLAINTEXT_PROTOCOL = 'nexus.device-transfer-plaintext.v2' as const;
const TRANSFER_SUITE = 'NX-HKDF-SHA256-AES256GCM-v2' as const;
const TRANSFER_INFO = new TextEncoder().encode('NEXUS-DEVICE-TRANSFER\0v2\0');
const textDecoder = new TextDecoder('utf-8', { fatal: true });
const MAX_TRANSFER_CIPHERTEXT_BYTES = 64 * 1024;
const MAX_TRANSFER_CIPHERTEXT_CHARACTERS = Math.ceil((MAX_TRANSFER_CIPHERTEXT_BYTES * 4) / 3);

export interface DeviceTransferPlaintextV2 {
  protocol: typeof TRANSFER_PLAINTEXT_PROTOCOL;
  subject: NexusSubject;
  genesis: IdentityGenesisV1;
  authorization: DeviceAuthorizationV2;
  devicePrivateKey: {
    alg: 'Ed25519';
    format: 'pkcs8';
    bytes: string;
  };
}

interface TransferHeaderV2 {
  protocol: typeof TRANSFER_PROTOCOL;
  suite: typeof TRANSFER_SUITE;
  bundleId: string;
  salt: string;
  iv: string;
}

function invalidTransfer(message: string, cause?: unknown): WalletCoreError {
  return new WalletCoreError(
    'INVALID_REQUEST',
    message,
    cause === undefined ? undefined : { cause },
  );
}

function header(bundle: DeviceTransferEnvelopeV2): TransferHeaderV2 {
  return {
    protocol: bundle.protocol,
    suite: bundle.suite,
    bundleId: bundle.bundleId,
    salt: bundle.salt,
    iv: bundle.iv,
  };
}

function requireExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw invalidTransfer(`${label} contains missing or unknown fields.`);
  }
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidTransfer(`${label} must be an object.`);
  }
  return value as Record<string, unknown>;
}

export function validateDeviceTransferEnvelope(
  value: DeviceTransferEnvelopeV2,
): DeviceTransferEnvelopeV2 {
  const input = asObject(value, 'The device transfer bundle');
  requireExactKeys(
    input,
    ['protocol', 'suite', 'bundleId', 'salt', 'iv', 'ciphertext'],
    'The device transfer bundle',
  );
  if (value.protocol !== TRANSFER_PROTOCOL || value.suite !== TRANSFER_SUITE) {
    throw invalidTransfer('The device transfer protocol or encryption suite is unsupported.');
  }
  if (
    typeof value.ciphertext !== 'string' ||
    value.ciphertext.length > MAX_TRANSFER_CIPHERTEXT_CHARACTERS
  ) {
    throw invalidTransfer('The device transfer ciphertext is too large or invalid.');
  }
  try {
    decodeBase64UrlExact(value.bundleId, 32);
    decodeBase64UrlExact(value.salt, 32);
    decodeBase64UrlExact(value.iv, 12);
    const ciphertext = decodeBase64Url(value.ciphertext);
    if (ciphertext.byteLength < 16 || ciphertext.byteLength > MAX_TRANSFER_CIPHERTEXT_BYTES) {
      throw new Error('invalid ciphertext length');
    }
  } catch (error) {
    throw invalidTransfer('The device transfer bundle encoding is invalid.', error);
  }
  return structuredClone(value);
}

export async function encryptDeviceTransfer(
  plaintext: Omit<DeviceTransferPlaintextV2, 'protocol'>,
  crypto: CryptoProvider,
): Promise<{ bundle: DeviceTransferEnvelopeV2; transferKey: Uint8Array }> {
  const transferKey = crypto.randomBytes(32);
  const bundleId = crypto.randomBytes(32);
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  if (
    transferKey.byteLength !== 32 ||
    bundleId.byteLength !== 32 ||
    salt.byteLength !== 32 ||
    iv.byteLength !== 12
  ) {
    throw new WalletCoreError('STORAGE_ERROR', 'The CSPRNG returned invalid transfer material.');
  }
  const transferHeader: TransferHeaderV2 = {
    protocol: TRANSFER_PROTOCOL,
    suite: TRANSFER_SUITE,
    bundleId: encodeBase64Url(bundleId),
    salt: encodeBase64Url(salt),
    iv: encodeBase64Url(iv),
  };
  let contentKey: Uint8Array | undefined;
  let plaintextBytes: Uint8Array | undefined;
  try {
    contentKey = await crypto.hkdfSha256({
      inputKeyMaterial: transferKey,
      salt,
      info: TRANSFER_INFO,
      length: 32,
    });
    plaintextBytes = canonicalizeToBytes({
      protocol: TRANSFER_PLAINTEXT_PROTOCOL,
      ...plaintext,
    });
    const ciphertext = await crypto.encryptAes256Gcm({
      key: contentKey,
      iv,
      additionalData: canonicalizeToBytes(transferHeader),
      tagLength: 128,
      plaintext: plaintextBytes,
    });
    const returnedTransferKey = Uint8Array.from(transferKey);
    return {
      bundle: { ...transferHeader, ciphertext: encodeBase64Url(ciphertext) },
      transferKey: returnedTransferKey,
    };
  } finally {
    transferKey.fill(0);
    contentKey?.fill(0);
    plaintextBytes?.fill(0);
  }
}

export async function decryptDeviceTransfer(
  input: DeviceTransferEnvelopeV2,
  transferKey: Uint8Array,
  crypto: CryptoProvider,
): Promise<{
  subject: NexusSubject;
  genesis: IdentityGenesisV1;
  authorization: unknown;
  devicePrivateKeyPkcs8: Uint8Array;
}> {
  const bundle = validateDeviceTransferEnvelope(input);
  if (transferKey.byteLength !== 32) {
    throw invalidTransfer('The transfer key must contain exactly 32 bytes.');
  }
  const salt = decodeBase64UrlExact(bundle.salt, 32);
  const iv = decodeBase64UrlExact(bundle.iv, 12);
  const inputKeyMaterial = Uint8Array.from(transferKey);
  let contentKey: Uint8Array;
  try {
    contentKey = await crypto.hkdfSha256({
      inputKeyMaterial,
      salt,
      info: TRANSFER_INFO,
      length: 32,
    });
  } finally {
    inputKeyMaterial.fill(0);
  }
  let plaintextBytes: Uint8Array;
  try {
    plaintextBytes = await crypto.decryptAes256Gcm({
      key: contentKey,
      iv,
      additionalData: canonicalizeToBytes(header(bundle)),
      tagLength: 128,
      ciphertext: decodeBase64Url(bundle.ciphertext),
    });
  } catch (error) {
    throw invalidTransfer('The transfer key or encrypted bundle is invalid.', error);
  } finally {
    contentKey.fill(0);
  }

  try {
    const parsed = JSON.parse(textDecoder.decode(plaintextBytes)) as unknown;
    const object = asObject(parsed, 'The decrypted device transfer');
    requireExactKeys(
      object,
      ['protocol', 'subject', 'genesis', 'authorization', 'devicePrivateKey'],
      'The decrypted device transfer',
    );
    if (object.protocol !== TRANSFER_PLAINTEXT_PROTOCOL || typeof object.subject !== 'string') {
      throw invalidTransfer('The decrypted device transfer protocol is invalid.');
    }
    const privateKey = asObject(object.devicePrivateKey, 'The transferred device private key');
    requireExactKeys(privateKey, ['alg', 'format', 'bytes'], 'The transferred device private key');
    if (
      privateKey.alg !== 'Ed25519' ||
      privateKey.format !== 'pkcs8' ||
      typeof privateKey.bytes !== 'string'
    ) {
      throw invalidTransfer('The transferred device private key format is invalid.');
    }
    const keyBytes = decodeBase64Url(privateKey.bytes);
    if (keyBytes.byteLength < 32 || keyBytes.byteLength > 512) {
      throw invalidTransfer('The transferred device private key length is invalid.');
    }
    return {
      subject: object.subject as NexusSubject,
      genesis: object.genesis as IdentityGenesisV1,
      authorization: object.authorization,
      devicePrivateKeyPkcs8: keyBytes,
    };
  } catch (error) {
    if (error instanceof WalletCoreError) throw error;
    throw invalidTransfer('The decrypted device transfer is malformed.', error);
  } finally {
    plaintextBytes.fill(0);
  }
}

/** Internal test/debug primitive; never exposes root private material. */
export async function decryptDeviceTransferPlaintext(
  input: DeviceTransferEnvelopeV2,
  transferKey: Uint8Array,
  crypto: CryptoProvider,
): Promise<DeviceTransferPlaintextV2> {
  const decrypted = await decryptDeviceTransfer(input, transferKey, crypto);
  try {
    return {
      protocol: TRANSFER_PLAINTEXT_PROTOCOL,
      subject: decrypted.subject,
      genesis: decrypted.genesis,
      authorization: decrypted.authorization as DeviceAuthorizationV2,
      devicePrivateKey: {
        alg: 'Ed25519',
        format: 'pkcs8',
        bytes: encodeBase64Url(decrypted.devicePrivateKeyPkcs8),
      },
    };
  } finally {
    decrypted.devicePrivateKeyPkcs8.fill(0);
  }
}
