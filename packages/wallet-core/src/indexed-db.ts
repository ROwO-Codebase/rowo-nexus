export const DEFAULT_WALLET_DATABASE_NAME = 'nexus-wallet-v1';
export const WALLET_DATABASE_VERSION = 1;
export const KEY_MATERIAL_STORE = 'key-material';
export const IDENTITY_RECORD_STORE = 'identity-records';

function databaseError(message: string, cause?: unknown): Error {
  return new Error(message, cause === undefined ? undefined : { cause });
}

export function openWalletDatabase(factory: IDBFactory, name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = factory.open(name, WALLET_DATABASE_VERSION);

    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(KEY_MATERIAL_STORE)) {
        database.createObjectStore(KEY_MATERIAL_STORE, { keyPath: 'ref' });
      }
      if (!database.objectStoreNames.contains(IDENTITY_RECORD_STORE)) {
        database.createObjectStore(IDENTITY_RECORD_STORE, { keyPath: 'localId' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(databaseError('Unable to open the Nexus wallet database.', request.error));
    request.onblocked = () =>
      reject(databaseError('The Nexus wallet database upgrade is blocked.'));
  });
}

export function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(databaseError('An IndexedDB request failed.', request.error));
  });
}

export function transactionComplete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () =>
      reject(databaseError('An IndexedDB transaction was aborted.', transaction.error));
    transaction.onerror = () =>
      reject(databaseError('An IndexedDB transaction failed.', transaction.error));
  });
}

export function requireIndexedDb(factory?: IDBFactory): IDBFactory {
  if (factory !== undefined) return factory;
  if (typeof globalThis.indexedDB === 'undefined') {
    throw databaseError('IndexedDB is unavailable in this runtime.');
  }
  return globalThis.indexedDB;
}

export function requireWebCrypto(cryptoApi?: Crypto): Crypto {
  if (cryptoApi !== undefined) return cryptoApi;
  if (typeof globalThis.crypto === 'undefined' || globalThis.crypto.subtle === undefined) {
    throw databaseError('Web Crypto is unavailable in this runtime.');
  }
  return globalThis.crypto;
}
