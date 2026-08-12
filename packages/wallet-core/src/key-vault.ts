import { createProtocolSignaturePreimage } from '@nexus/crypto';
import { encodeBase64Url } from '@nexus/protocol';

import { WalletCoreError } from './errors.js';
import {
  DEFAULT_WALLET_DATABASE_NAME,
  KEY_MATERIAL_STORE,
  openWalletDatabase,
  requestResult,
  requireIndexedDb,
  requireWebCrypto,
  transactionComplete,
} from './indexed-db.js';
import type { KeyRef, KeyVaultStorage, SecretRef } from './types.js';

type StoredKeyKind = 'signing-key' | 'agreement-key' | 'device-signing-key';

interface StoredKeyRecord {
  ref: KeyRef;
  kind: StoredKeyKind;
  privateKey: CryptoKey;
  publicKey: ArrayBuffer;
}

interface StoredSecretRecord {
  ref: SecretRef;
  kind: 'revocation-secret';
  secret: ArrayBuffer;
}

interface StoredCancelledDeviceKeyRefRecord {
  ref: KeyRef;
  kind: 'cancelled-device-key-ref';
}

type StoredVaultRecord = StoredKeyRecord | StoredSecretRecord | StoredCancelledDeviceKeyRefRecord;

export interface ManagedProtocolPayload {
  protocol: string;
}

interface ManagedKeyVaultCapabilities {
  createDeviceSigningKeyRef(): KeyRef;
  importDeviceSigningKeyAtRef(
    ref: KeyRef,
    privateKeyPkcs8: Uint8Array,
    expectedPublicKey: Uint8Array,
  ): Promise<void>;
  cancelDeviceSigningKeyRef(ref: KeyRef): Promise<void>;
  signProtocolPayload<T extends ManagedProtocolPayload>(
    ref: KeyRef,
    payload: T,
  ): Promise<Uint8Array>;
}

const managedCapabilities = new WeakMap<object, ManagedKeyVaultCapabilities>();
const ROOT_SIGNING_PROTOCOLS = new Set([
  'nexus.ownership-proof.v1',
  'nexus.continuity-link.v1',
  'nexus.revoke.v1',
  'nexus.device-authorization.v2',
  'nexus.device-root-revoke.v2',
]);
const DEVICE_SIGNING_PROTOCOLS = new Set([
  'nexus.device-activation.v2',
  'nexus.ownership-proof.v2',
  'nexus.device-self-revoke.v2',
]);

export function getManagedKeyVaultCapabilities(
  vault: KeyVaultStorage,
): ManagedKeyVaultCapabilities | undefined {
  return managedCapabilities.get(vault);
}

/** Package-internal test seam; not exported from the package entry point. */
export function signManagedProtocolPayload<T extends ManagedProtocolPayload>(
  vault: KeyVaultStorage,
  ref: KeyRef,
  payload: T,
): Promise<Uint8Array> {
  const capability = managedCapabilities.get(vault);
  if (capability === undefined) {
    throw new WalletCoreError('INVALID_REQUEST', 'This is not a managed key vault.');
  }
  return capability.signProtocolPayload(ref, payload);
}

export interface WebCryptoIndexedDbKeyVaultOptions {
  databaseName?: string;
  indexedDB?: IDBFactory;
  crypto?: Crypto;
  /** @internal Deterministic import-race test hook. */
  beforeDeviceKeyImport?: () => Promise<void>;
}

function copyBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

function isCryptoKeyPair(value: CryptoKey | CryptoKeyPair): value is CryptoKeyPair {
  return 'privateKey' in value && 'publicKey' in value;
}

function isConstraintError(error: unknown): boolean {
  if (error instanceof DOMException && error.name === 'ConstraintError') return true;
  return (
    error instanceof Error &&
    error.cause instanceof DOMException &&
    error.cause.name === 'ConstraintError'
  );
}

function asKeyRef(value: string): KeyRef {
  return value as KeyRef;
}

function asSecretRef(value: string): SecretRef {
  return value as SecretRef;
}

function newReference(cryptoApi: Crypto, prefix: 'key' | 'secret'): string {
  const random = new Uint8Array(18);
  cryptoApi.getRandomValues(random);
  return `${prefix}_${encodeBase64Url(random)}`;
}

function requireKey(record: StoredVaultRecord | undefined, ref: KeyRef): StoredKeyRecord {
  if (
    record === undefined ||
    record.kind === 'revocation-secret' ||
    record.kind === 'cancelled-device-key-ref'
  ) {
    throw new WalletCoreError('STORAGE_ERROR', `Key reference ${String(ref)} does not exist.`);
  }
  return record;
}

async function importDeviceSigningKey(
  cryptoApi: Crypto,
  ref: KeyRef,
  privateKeyPkcs8: Uint8Array,
  expectedPublicKey: Uint8Array,
): Promise<StoredKeyRecord> {
  if (expectedPublicKey.byteLength !== 32) {
    throw new WalletCoreError(
      'INVALID_REQUEST',
      'An Ed25519 device public key must contain exactly 32 bytes.',
    );
  }
  let privateKey: CryptoKey;
  let publicKey: CryptoKey;
  const privateKeyImportBytes = copyBuffer(privateKeyPkcs8);
  try {
    [privateKey, publicKey] = await Promise.all([
      cryptoApi.subtle.importKey('pkcs8', privateKeyImportBytes, { name: 'Ed25519' }, false, [
        'sign',
      ]),
      cryptoApi.subtle.importKey('raw', copyBuffer(expectedPublicKey), { name: 'Ed25519' }, false, [
        'verify',
      ]),
    ]);
  } catch (error) {
    throw new WalletCoreError('INVALID_REQUEST', 'The device private key is invalid.', {
      cause: error,
    });
  } finally {
    new Uint8Array(privateKeyImportBytes).fill(0);
  }

  const challenge = new Uint8Array(32);
  cryptoApi.getRandomValues(challenge);
  const signature = await cryptoApi.subtle.sign('Ed25519', privateKey, challenge);
  const matches = await cryptoApi.subtle.verify('Ed25519', publicKey, signature, challenge);
  challenge.fill(0);
  if (!matches) {
    throw new WalletCoreError(
      'INVALID_REQUEST',
      'The device private key does not match its authorized public key.',
    );
  }
  return {
    ref,
    kind: 'device-signing-key',
    privateKey,
    publicKey: copyBuffer(expectedPublicKey),
  };
}

function requireSecret(record: StoredVaultRecord | undefined, ref: SecretRef): StoredSecretRecord {
  if (record === undefined || record.kind !== 'revocation-secret') {
    throw new WalletCoreError('STORAGE_ERROR', `Secret reference ${String(ref)} does not exist.`);
  }
  return record;
}

async function generateKeyRecord(
  cryptoApi: Crypto,
  kind: StoredKeyKind,
  ref: KeyRef,
): Promise<StoredKeyRecord> {
  const algorithm = kind === 'agreement-key' ? 'X25519' : 'Ed25519';
  const usages: KeyUsage[] = kind === 'agreement-key' ? ['deriveBits'] : ['sign', 'verify'];
  const generated = await cryptoApi.subtle.generateKey({ name: algorithm }, false, usages);
  if (!isCryptoKeyPair(generated)) {
    throw new WalletCoreError(
      'STORAGE_ERROR',
      `${algorithm} key generation did not return a key pair.`,
    );
  }
  const publicKey = await cryptoApi.subtle.exportKey('raw', generated.publicKey);
  return { ref, kind, privateKey: generated.privateKey, publicKey };
}

/**
 * Stores non-extractable private CryptoKey objects and revocation secrets in
 * IndexedDB. Public raw private-key export/import and root recovery are
 * intentionally unsupported; WalletCore alone receives the private capability
 * for certified device-key import and canceled-reference journaling.
 */
export class WebCryptoIndexedDbKeyVault implements KeyVaultStorage {
  readonly #databaseName: string;
  readonly #factory: IDBFactory;
  readonly #crypto: Crypto;
  readonly #beforeDeviceKeyImport: (() => Promise<void>) | undefined;
  #database: Promise<IDBDatabase> | undefined;

  public constructor(options: WebCryptoIndexedDbKeyVaultOptions = {}) {
    this.#databaseName = options.databaseName ?? DEFAULT_WALLET_DATABASE_NAME;
    this.#factory = requireIndexedDb(options.indexedDB);
    this.#crypto = requireWebCrypto(options.crypto);
    this.#beforeDeviceKeyImport = options.beforeDeviceKeyImport;
    managedCapabilities.set(this, {
      createDeviceSigningKeyRef: () => asKeyRef(newReference(this.#crypto, 'key')),
      importDeviceSigningKeyAtRef: (ref, privateKeyPkcs8, expectedPublicKey) =>
        this.#importDeviceSigningKeyAtRef(ref, privateKeyPkcs8, expectedPublicKey),
      cancelDeviceSigningKeyRef: (ref) => this.#cancelDeviceSigningKeyRef(ref),
      signProtocolPayload: (ref, payload) => this.#signProtocolPayload(ref, payload),
    });
  }

  public async createSigningKey(): Promise<KeyRef> {
    return this.#createKey('signing-key');
  }

  async #importDeviceSigningKeyAtRef(
    ref: KeyRef,
    privateKeyPkcs8: Uint8Array,
    expectedPublicKey: Uint8Array,
  ): Promise<void> {
    await this.#beforeDeviceKeyImport?.();
    const record = await importDeviceSigningKey(
      this.#crypto,
      ref,
      privateKeyPkcs8,
      expectedPublicKey,
    );
    await this.#add(record);
  }

  async #cancelDeviceSigningKeyRef(ref: KeyRef): Promise<void> {
    const database = await this.#open();
    const transaction = database.transaction(KEY_MATERIAL_STORE, 'readwrite');
    const completion = transactionComplete(transaction);
    const store = transaction.objectStore(KEY_MATERIAL_STORE);
    const existing = await requestResult<StoredVaultRecord | undefined>(
      // IndexedDB's legacy DOM declaration returns IDBRequest<any> at this boundary.
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      store.get(ref),
    );
    if (
      existing !== undefined &&
      existing.kind !== 'device-signing-key' &&
      existing.kind !== 'cancelled-device-key-ref'
    ) {
      transaction.abort();
      await completion.catch(() => undefined);
      throw new WalletCoreError(
        'STORAGE_ERROR',
        'A device-key cancellation cannot replace another key role.',
      );
    }
    await requestResult(
      store.put({
        ref,
        kind: 'cancelled-device-key-ref',
      } satisfies StoredCancelledDeviceKeyRefRecord),
    );
    await completion;
  }

  public async createAgreementKey(): Promise<KeyRef> {
    return this.#createKey('agreement-key');
  }

  async #signProtocolPayload(ref: KeyRef, payload: ManagedProtocolPayload): Promise<Uint8Array> {
    const record = requireKey(await this.#get(ref), ref);
    const allowed =
      record.kind === 'signing-key'
        ? ROOT_SIGNING_PROTOCOLS
        : record.kind === 'device-signing-key'
          ? DEVICE_SIGNING_PROTOCOLS
          : undefined;
    if (allowed === undefined || !allowed.has(payload.protocol)) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'This key role is not authorized to sign the requested protocol payload.',
      );
    }
    const signature = await this.#crypto.subtle.sign(
      'Ed25519',
      record.privateKey,
      copyBuffer(createProtocolSignaturePreimage(payload)),
    );
    return new Uint8Array(signature);
  }

  public async readPublicKey(ref: KeyRef): Promise<Uint8Array> {
    const record = requireKey(await this.#get(ref), ref);
    return new Uint8Array(record.publicKey.slice(0));
  }

  public async deleteKey(ref: KeyRef): Promise<void> {
    await this.#deleteUnlessCancelled(ref);
  }

  public async storeRevocationSecret(secret: Uint8Array): Promise<SecretRef> {
    if (secret.byteLength !== 32) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'A revocation secret must contain exactly 32 bytes.',
      );
    }
    const ref = asSecretRef(newReference(this.#crypto, 'secret'));
    await this.#add({ ref, kind: 'revocation-secret', secret: copyBuffer(secret) });
    return ref;
  }

  public async readRevocationSecret(ref: SecretRef): Promise<Uint8Array> {
    const record = requireSecret(await this.#get(ref), ref);
    return new Uint8Array(record.secret.slice(0));
  }

  public async deleteSecret(ref: SecretRef): Promise<void> {
    await this.#deleteUnlessCancelled(ref);
  }

  public async hasKey(ref: KeyRef): Promise<boolean> {
    const record = await this.#get(ref);
    return (
      record !== undefined &&
      record.kind !== 'revocation-secret' &&
      record.kind !== 'cancelled-device-key-ref'
    );
  }

  public async hasSecret(ref: SecretRef): Promise<boolean> {
    const record = await this.#get(ref);
    return record?.kind === 'revocation-secret';
  }

  public async close(): Promise<void> {
    if (this.#database === undefined) return;
    const database = await this.#database;
    database.close();
    this.#database = undefined;
  }

  async #createKey(kind: StoredKeyKind): Promise<KeyRef> {
    const ref = asKeyRef(newReference(this.#crypto, 'key'));
    const record = await generateKeyRecord(this.#crypto, kind, ref);
    await this.#add(record);
    return ref;
  }

  async #open(): Promise<IDBDatabase> {
    this.#database ??= openWalletDatabase(this.#factory, this.#databaseName);
    return this.#database;
  }

  async #add(record: StoredVaultRecord): Promise<void> {
    const database = await this.#open();
    const transaction = database.transaction(KEY_MATERIAL_STORE, 'readwrite');
    const completion = transactionComplete(transaction);
    try {
      await requestResult(transaction.objectStore(KEY_MATERIAL_STORE).add(record));
      await completion;
    } catch (error) {
      await completion.catch(() => undefined);
      if (isConstraintError(error)) {
        throw new WalletCoreError(
          'REGISTRY_CONFLICT',
          'The device key reference was already stored or canceled.',
          { cause: error },
        );
      }
      throw error;
    }
  }

  async #get(ref: KeyRef | SecretRef): Promise<StoredVaultRecord | undefined> {
    const database = await this.#open();
    const transaction = database.transaction(KEY_MATERIAL_STORE, 'readonly');
    const completion = transactionComplete(transaction);
    const result = await requestResult<StoredVaultRecord | undefined>(
      // IndexedDB's legacy DOM declaration returns IDBRequest<any> at this boundary.
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      transaction.objectStore(KEY_MATERIAL_STORE).get(ref),
    );
    await completion;
    return result;
  }

  async #deleteUnlessCancelled(ref: KeyRef | SecretRef): Promise<void> {
    const database = await this.#open();
    const transaction = database.transaction(KEY_MATERIAL_STORE, 'readwrite');
    const completion = transactionComplete(transaction);
    const store = transaction.objectStore(KEY_MATERIAL_STORE);
    const existing = await requestResult<StoredVaultRecord | undefined>(
      // IndexedDB's legacy DOM declaration returns IDBRequest<any> at this boundary.
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      store.get(ref),
    );
    if (existing?.kind !== 'cancelled-device-key-ref') {
      await requestResult(store.delete(ref));
    }
    await completion;
  }
}

export interface InMemoryKeyVaultOptions {
  crypto?: Crypto;
  /** @internal Deterministic import-race test hook. */
  beforeDeviceKeyImport?: () => Promise<void>;
}

export class InMemoryKeyVault implements KeyVaultStorage {
  readonly #crypto: Crypto;
  readonly #records = new Map<KeyRef | SecretRef, StoredVaultRecord>();
  readonly #beforeDeviceKeyImport: (() => Promise<void>) | undefined;

  public constructor(options: InMemoryKeyVaultOptions = {}) {
    this.#crypto = requireWebCrypto(options.crypto);
    this.#beforeDeviceKeyImport = options.beforeDeviceKeyImport;
    managedCapabilities.set(this, {
      createDeviceSigningKeyRef: () => asKeyRef(newReference(this.#crypto, 'key')),
      importDeviceSigningKeyAtRef: (ref, privateKeyPkcs8, expectedPublicKey) =>
        this.#importDeviceSigningKeyAtRef(ref, privateKeyPkcs8, expectedPublicKey),
      cancelDeviceSigningKeyRef: (ref) => this.#cancelDeviceSigningKeyRef(ref),
      signProtocolPayload: (ref, payload) => this.#signProtocolPayload(ref, payload),
    });
  }

  public async createSigningKey(): Promise<KeyRef> {
    return this.#createKey('signing-key');
  }

  async #importDeviceSigningKeyAtRef(
    ref: KeyRef,
    privateKeyPkcs8: Uint8Array,
    expectedPublicKey: Uint8Array,
  ): Promise<void> {
    await this.#beforeDeviceKeyImport?.();
    const record = await importDeviceSigningKey(
      this.#crypto,
      ref,
      privateKeyPkcs8,
      expectedPublicKey,
    );
    if (this.#records.has(ref)) {
      throw new WalletCoreError('REGISTRY_CONFLICT', 'The device key reference already exists.');
    }
    this.#records.set(ref, record);
  }

  #cancelDeviceSigningKeyRef(ref: KeyRef): Promise<void> {
    const existing = this.#records.get(ref);
    if (
      existing !== undefined &&
      existing.kind !== 'device-signing-key' &&
      existing.kind !== 'cancelled-device-key-ref'
    ) {
      throw new WalletCoreError(
        'STORAGE_ERROR',
        'A device-key cancellation cannot replace another key role.',
      );
    }
    this.#records.set(ref, { ref, kind: 'cancelled-device-key-ref' });
    return Promise.resolve();
  }

  public async createAgreementKey(): Promise<KeyRef> {
    return this.#createKey('agreement-key');
  }

  async #signProtocolPayload(ref: KeyRef, payload: ManagedProtocolPayload): Promise<Uint8Array> {
    const record = requireKey(this.#records.get(ref), ref);
    const allowed =
      record.kind === 'signing-key'
        ? ROOT_SIGNING_PROTOCOLS
        : record.kind === 'device-signing-key'
          ? DEVICE_SIGNING_PROTOCOLS
          : undefined;
    if (allowed === undefined || !allowed.has(payload.protocol)) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'This key role is not authorized to sign the requested protocol payload.',
      );
    }
    const signature = await this.#crypto.subtle.sign(
      'Ed25519',
      record.privateKey,
      copyBuffer(createProtocolSignaturePreimage(payload)),
    );
    return new Uint8Array(signature);
  }

  public readPublicKey(ref: KeyRef): Promise<Uint8Array> {
    const record = requireKey(this.#records.get(ref), ref);
    return Promise.resolve(new Uint8Array(record.publicKey.slice(0)));
  }

  public deleteKey(ref: KeyRef): Promise<void> {
    this.#deleteUnlessCancelled(ref);
    return Promise.resolve();
  }

  public storeRevocationSecret(secret: Uint8Array): Promise<SecretRef> {
    if (secret.byteLength !== 32) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'A revocation secret must contain exactly 32 bytes.',
      );
    }
    const ref = asSecretRef(newReference(this.#crypto, 'secret'));
    this.#records.set(ref, { ref, kind: 'revocation-secret', secret: copyBuffer(secret) });
    return Promise.resolve(ref);
  }

  public readRevocationSecret(ref: SecretRef): Promise<Uint8Array> {
    const record = requireSecret(this.#records.get(ref), ref);
    return Promise.resolve(new Uint8Array(record.secret.slice(0)));
  }

  public deleteSecret(ref: SecretRef): Promise<void> {
    this.#deleteUnlessCancelled(ref);
    return Promise.resolve();
  }

  public hasKey(ref: KeyRef): Promise<boolean> {
    const record = this.#records.get(ref);
    return Promise.resolve(
      record !== undefined &&
        record.kind !== 'revocation-secret' &&
        record.kind !== 'cancelled-device-key-ref',
    );
  }

  public hasSecret(ref: SecretRef): Promise<boolean> {
    return Promise.resolve(this.#records.get(ref)?.kind === 'revocation-secret');
  }

  #deleteUnlessCancelled(ref: KeyRef | SecretRef): void {
    if (this.#records.get(ref)?.kind !== 'cancelled-device-key-ref') {
      this.#records.delete(ref);
    }
  }

  async #createKey(kind: StoredKeyKind): Promise<KeyRef> {
    const ref = asKeyRef(newReference(this.#crypto, 'key'));
    this.#records.set(ref, await generateKeyRecord(this.#crypto, kind, ref));
    return ref;
  }
}
