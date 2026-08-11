import { getDefaultCryptoProvider, signProtocolPayload, type CryptoProvider } from '@nexus/crypto';
import {
  decodeBase64Url,
  registryReceiptV1Schema,
  registryReceiptPayloadV1Schema,
  statusStatementV1Schema,
  statusStatementPayloadV1Schema,
  type RegistryReceiptPayloadV1,
  type RegistryReceiptV1,
  type StatusStatementPayloadV1,
  type StatusStatementV1,
} from '@nexus/protocol';

import { NexusFault } from './errors.js';

export interface ServiceSigningConfig {
  /** Expected public key identifier. It must match payload.signerKid. */
  readonly signerKid: string;
  /** Ed25519 PKCS#8 as unpadded base64url, PEM, or an owned byte view. */
  readonly privateKeyPkcs8: string | Uint8Array;
  readonly provider?: CryptoProvider;
}

const importedKeyPromises = new WeakMap<ServiceSigningConfig, Promise<CryptoKey>>();

function decodePem(value: string): Uint8Array {
  const match = /^\s*-----BEGIN PRIVATE KEY-----([\s\S]+)-----END PRIVATE KEY-----\s*$/u.exec(
    value,
  );
  if (match === null) {
    throw new NexusFault('INTERNAL_ERROR');
  }
  const body = match[1]?.replaceAll(/\s/gu, '') ?? '';
  if (body.length === 0 || !/^[A-Za-z0-9+/]+={0,2}$/u.test(body)) {
    throw new NexusFault('INTERNAL_ERROR');
  }

  try {
    const binary = atob(body);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new NexusFault('INTERNAL_ERROR');
  }
}

function decodePkcs8(value: string | Uint8Array): Uint8Array {
  if (value instanceof Uint8Array) {
    return value.slice();
  }
  if (value.includes('-----BEGIN')) {
    return decodePem(value);
  }

  try {
    return decodeBase64Url(value);
  } catch {
    throw new NexusFault('INTERNAL_ERROR');
  }
}

async function importSigningKey(config: ServiceSigningConfig): Promise<CryptoKey> {
  const existing = importedKeyPromises.get(config);
  if (existing !== undefined) {
    return existing;
  }

  const provider = config.provider ?? getDefaultCryptoProvider();
  const pkcs8 = decodePkcs8(config.privateKeyPkcs8);
  const pending = provider.importEd25519PrivateKey(pkcs8, { extractable: false }).finally(() => {
    pkcs8.fill(0);
  });
  importedKeyPromises.set(config, pending);

  try {
    return await pending;
  } catch {
    importedKeyPromises.delete(config);
    throw new NexusFault('INTERNAL_ERROR');
  }
}

function assertSignerKid(payloadKid: string, config: ServiceSigningConfig): void {
  if (payloadKid !== config.signerKid) {
    throw new NexusFault('INTERNAL_ERROR');
  }
}

export async function signRegistryReceipt(
  payload: RegistryReceiptPayloadV1,
  config: ServiceSigningConfig,
): Promise<RegistryReceiptV1> {
  const parsed = registryReceiptPayloadV1Schema.parse(payload);
  assertSignerKid(parsed.signerKid, config);
  const provider = config.provider ?? getDefaultCryptoProvider();
  const privateKey = await importSigningKey(config);
  const signature = await signProtocolPayload(parsed, privateKey, provider);
  return registryReceiptV1Schema.parse({ payload: parsed, signature });
}

export async function signStatusStatement(
  payload: StatusStatementPayloadV1,
  config: ServiceSigningConfig,
): Promise<StatusStatementV1> {
  const parsed = statusStatementPayloadV1Schema.parse(payload);
  assertSignerKid(parsed.signerKid, config);
  const provider = config.provider ?? getDefaultCryptoProvider();
  const privateKey = await importSigningKey(config);
  const signature = await signProtocolPayload(parsed, privateKey, provider);
  return statusStatementV1Schema.parse({ payload: parsed, signature });
}
