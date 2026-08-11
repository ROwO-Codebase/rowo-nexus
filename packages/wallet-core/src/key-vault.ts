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
import type { KeyRef, KeyVault, SecretRef } from './types.js';

type StoredKeyKind = 'signing-key' | 'agreement-key';

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

type StoredVaultRecord = StoredKeyRecord | StoredSecretRecord;

export interface WebCryptoIndexedDbKeyVaultOptions {
  databaseName?: string;
  indexedDB?: IDBFactory;
  crypto?: Crypto;
}

function copyBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

function isCryptoKeyPair(value: CryptoKey | CryptoKeyPair): value is CryptoKeyPair {
  return 'privateKey' in value && 'publicKey' in value;
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
  if (record === undefined || record.kind === 'revocation-secret') {
    throw new WalletCoreError('STORAGE_ERROR', `Key reference ${String(ref)} does not exist.`);
  }
  return record;
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
  const algorithm = kind === 'signing-key' ? 'Ed25519' : 'X25519';
  const usages: KeyUsage[] = kind === 'signing-key' ? ['sign', 'verify'] : ['deriveBits'];
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
 * IndexedDB. Key export/backup is intentionally outside this implementation.
 */
export class WebCryptoIndexedDbKeyVault implements KeyVault {
  readonly #databaseName: string;
  readonly #factory: IDBFactory;
  readonly #crypto: Crypto;
  #database: Promise<IDBDatabase> | undefined;

  public constructor(options: WebCryptoIndexedDbKeyVaultOptions = {}) {
    this.#databaseName = options.databaseName ?? DEFAULT_WALLET_DATABASE_NAME;
    this.#factory = requireIndexedDb(options.indexedDB);
    this.#crypto = requireWebCrypto(options.crypto);
  }

  public async createSigningKey(): Promise<KeyRef> {
    return this.#createKey('signing-key');
  }

  public async createAgreementKey(): Promise<KeyRef> {
    return this.#createKey('agreement-key');
  }

  public async sign(ref: KeyRef, data: Uint8Array): Promise<Uint8Array> {
    const record = requireKey(await this.#get(ref), ref);
    if (record.kind !== 'signing-key') {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'An agreement key cannot sign protocol payloads.',
      );
    }
    const signature = await this.#crypto.subtle.sign(
      'Ed25519',
      record.privateKey,
      Uint8Array.from(data),
    );
    return new Uint8Array(signature);
  }

  public async readPublicKey(ref: KeyRef): Promise<Uint8Array> {
    const record = requireKey(await this.#get(ref), ref);
    return new Uint8Array(record.publicKey.slice(0));
  }

  public async deleteKey(ref: KeyRef): Promise<void> {
    await this.#delete(ref);
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
    await this.#delete(ref);
  }

  public async hasKey(ref: KeyRef): Promise<boolean> {
    const record = await this.#get(ref);
    return record !== undefined && record.kind !== 'revocation-secret';
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
    await requestResult(transaction.objectStore(KEY_MATERIAL_STORE).add(record));
    await completion;
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

  async #delete(ref: KeyRef | SecretRef): Promise<void> {
    const database = await this.#open();
    const transaction = database.transaction(KEY_MATERIAL_STORE, 'readwrite');
    const completion = transactionComplete(transaction);
    await requestResult(transaction.objectStore(KEY_MATERIAL_STORE).delete(ref));
    await completion;
  }
}

export interface InMemoryKeyVaultOptions {
  crypto?: Crypto;
}

export class InMemoryKeyVault implements KeyVault {
  readonly #crypto: Crypto;
  readonly #records = new Map<KeyRef | SecretRef, StoredVaultRecord>();

  public constructor(options: InMemoryKeyVaultOptions = {}) {
    this.#crypto = requireWebCrypto(options.crypto);
  }

  public async createSigningKey(): Promise<KeyRef> {
    return this.#createKey('signing-key');
  }

  public async createAgreementKey(): Promise<KeyRef> {
    return this.#createKey('agreement-key');
  }

  public async sign(ref: KeyRef, data: Uint8Array): Promise<Uint8Array> {
    const record = requireKey(this.#records.get(ref), ref);
    if (record.kind !== 'signing-key') {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'An agreement key cannot sign protocol payloads.',
      );
    }
    const signature = await this.#crypto.subtle.sign(
      'Ed25519',
      record.privateKey,
      Uint8Array.from(data),
    );
    return new Uint8Array(signature);
  }

  public readPublicKey(ref: KeyRef): Promise<Uint8Array> {
    const record = requireKey(this.#records.get(ref), ref);
    return Promise.resolve(new Uint8Array(record.publicKey.slice(0)));
  }

  public deleteKey(ref: KeyRef): Promise<void> {
    this.#records.delete(ref);
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
    this.#records.delete(ref);
    return Promise.resolve();
  }

  public hasKey(ref: KeyRef): Promise<boolean> {
    const record = this.#records.get(ref);
    return Promise.resolve(record !== undefined && record.kind !== 'revocation-secret');
  }

  public hasSecret(ref: SecretRef): Promise<boolean> {
    return Promise.resolve(this.#records.get(ref)?.kind === 'revocation-secret');
  }

  async #createKey(kind: StoredKeyKind): Promise<KeyRef> {
    const ref = asKeyRef(newReference(this.#crypto, 'key'));
    this.#records.set(ref, await generateKeyRecord(this.#crypto, kind, ref));
    return ref;
  }
}
