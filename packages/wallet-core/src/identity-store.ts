import {
  DEFAULT_WALLET_DATABASE_NAME,
  IDENTITY_RECORD_STORE,
  openWalletDatabase,
  requestResult,
  requireIndexedDb,
  transactionComplete,
} from './indexed-db.js';
import { WalletCoreError } from './errors.js';
import type { IdentityStore, LocalIdentityRecordV1, LocalIssuedDeviceRecordV2 } from './types.js';

export interface IndexedDbIdentityStoreOptions {
  databaseName?: string;
  indexedDB?: IDBFactory;
}

function cloneRecord(record: LocalIdentityRecordV1): LocalIdentityRecordV1 {
  return structuredClone(record);
}

const MAX_ISSUED_DEVICE_CATALOGUE_ENTRIES = 256;

export class IndexedDbIdentityStore implements IdentityStore {
  readonly #databaseName: string;
  readonly #factory: IDBFactory;
  #database: Promise<IDBDatabase> | undefined;

  public constructor(options: IndexedDbIdentityStoreOptions = {}) {
    this.#databaseName = options.databaseName ?? DEFAULT_WALLET_DATABASE_NAME;
    this.#factory = requireIndexedDb(options.indexedDB);
  }

  public async get(localId: string): Promise<LocalIdentityRecordV1 | undefined> {
    const database = await this.#open();
    const transaction = database.transaction(IDENTITY_RECORD_STORE, 'readonly');
    const completion = transactionComplete(transaction);
    const result = await requestResult<LocalIdentityRecordV1 | undefined>(
      // IndexedDB's legacy DOM declaration returns IDBRequest<any> at this boundary.
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      transaction.objectStore(IDENTITY_RECORD_STORE).get(localId),
    );
    await completion;
    return result === undefined ? undefined : cloneRecord(result);
  }

  public async list(): Promise<LocalIdentityRecordV1[]> {
    const database = await this.#open();
    const transaction = database.transaction(IDENTITY_RECORD_STORE, 'readonly');
    const completion = transactionComplete(transaction);
    const result = await requestResult<LocalIdentityRecordV1[]>(
      // IndexedDB's legacy DOM declaration returns IDBRequest<any[]> at this boundary.
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      transaction.objectStore(IDENTITY_RECORD_STORE).getAll(),
    );
    await completion;
    return result.map(cloneRecord);
  }

  public async put(record: LocalIdentityRecordV1): Promise<void> {
    const database = await this.#open();
    const transaction = database.transaction(IDENTITY_RECORD_STORE, 'readwrite');
    const completion = transactionComplete(transaction);
    await requestResult(transaction.objectStore(IDENTITY_RECORD_STORE).put(cloneRecord(record)));
    await completion;
  }

  public async appendIssuedDevice(
    localId: string,
    device: LocalIssuedDeviceRecordV2,
  ): Promise<void> {
    await this.update(localId, (current) => {
      if (current.localState !== 'active' || current.deviceV2 !== undefined) {
        throw new WalletCoreError(
          'INVALID_REQUEST',
          'Only an active root identity can record an issued device.',
        );
      }
      if ((current.issuedDevicesV2 ?? []).some((entry) => entry.deviceId === device.deviceId)) {
        throw new WalletCoreError(
          'REGISTRY_CONFLICT',
          'This device is already in the root catalogue.',
        );
      }
      if ((current.issuedDevicesV2 ?? []).length >= MAX_ISSUED_DEVICE_CATALOGUE_ENTRIES) {
        throw new WalletCoreError(
          'STORAGE_ERROR',
          'The issued-device catalogue reached its 256-entry safety limit.',
        );
      }
      return {
        ...current,
        issuedDevicesV2: [...(current.issuedDevicesV2 ?? []), structuredClone(device)],
      };
    });
  }

  public async update(
    localId: string,
    mutate: (record: LocalIdentityRecordV1) => LocalIdentityRecordV1,
  ): Promise<LocalIdentityRecordV1> {
    const database = await this.#open();
    const transaction = database.transaction(IDENTITY_RECORD_STORE, 'readwrite');
    const completion = transactionComplete(transaction);
    const store = transaction.objectStore(IDENTITY_RECORD_STORE);
    const current = await requestResult<LocalIdentityRecordV1 | undefined>(
      // IndexedDB's legacy DOM declaration returns IDBRequest<any> at this boundary.
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      store.get(localId),
    );
    if (current === undefined) {
      transaction.abort();
      await completion.catch(() => undefined);
      throw new WalletCoreError('IDENTITY_NOT_FOUND', `Local identity ${localId} does not exist.`);
    }
    let updated: LocalIdentityRecordV1;
    try {
      updated = cloneRecord(mutate(cloneRecord(current)));
    } catch (error) {
      transaction.abort();
      await completion.catch(() => undefined);
      throw error;
    }
    if (updated.localId !== localId) {
      transaction.abort();
      await completion.catch(() => undefined);
      throw new WalletCoreError('STORAGE_ERROR', 'An identity update cannot change its local ID.');
    }
    await requestResult(store.put(updated));
    await completion;
    return cloneRecord(updated);
  }

  public async delete(localId: string): Promise<void> {
    const database = await this.#open();
    const transaction = database.transaction(IDENTITY_RECORD_STORE, 'readwrite');
    const completion = transactionComplete(transaction);
    await requestResult(transaction.objectStore(IDENTITY_RECORD_STORE).delete(localId));
    await completion;
  }

  public async reserveDeviceRecord(record: LocalIdentityRecordV1): Promise<void> {
    if (record.deviceV2 === undefined) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'A reserved device record requires v2 metadata.',
      );
    }
    const database = await this.#open();
    const transaction = database.transaction(IDENTITY_RECORD_STORE, 'readwrite');
    const completion = transactionComplete(transaction);
    const store = transaction.objectStore(IDENTITY_RECORD_STORE);
    const records = await requestResult<LocalIdentityRecordV1[]>(
      // IndexedDB's legacy DOM declaration returns IDBRequest<any[]> at this boundary.
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      store.getAll(),
    );
    if (records.some((existing) => existing.deviceV2?.deviceId === record.deviceV2?.deviceId)) {
      transaction.abort();
      await completion.catch(() => undefined);
      throw new WalletCoreError(
        'REGISTRY_CONFLICT',
        'This device key is already installed in the wallet.',
      );
    }
    await requestResult(store.add(cloneRecord(record)));
    await completion;
  }

  public async close(): Promise<void> {
    if (this.#database === undefined) return;
    const database = await this.#database;
    database.close();
    this.#database = undefined;
  }

  async #open(): Promise<IDBDatabase> {
    this.#database ??= openWalletDatabase(this.#factory, this.#databaseName);
    return this.#database;
  }
}

export class InMemoryIdentityStore implements IdentityStore {
  readonly #records = new Map<string, LocalIdentityRecordV1>();

  public get(localId: string): Promise<LocalIdentityRecordV1 | undefined> {
    const record = this.#records.get(localId);
    return Promise.resolve(record === undefined ? undefined : cloneRecord(record));
  }

  public list(): Promise<LocalIdentityRecordV1[]> {
    return Promise.resolve([...this.#records.values()].map(cloneRecord));
  }

  public put(record: LocalIdentityRecordV1): Promise<void> {
    this.#records.set(record.localId, cloneRecord(record));
    return Promise.resolve();
  }

  public appendIssuedDevice(localId: string, device: LocalIssuedDeviceRecordV2): Promise<void> {
    return this.update(localId, (current) => {
      if (current.localState !== 'active' || current.deviceV2 !== undefined) {
        throw new WalletCoreError(
          'INVALID_REQUEST',
          'Only an active root identity can record an issued device.',
        );
      }
      if ((current.issuedDevicesV2 ?? []).some((entry) => entry.deviceId === device.deviceId)) {
        throw new WalletCoreError(
          'REGISTRY_CONFLICT',
          'This device is already in the root catalogue.',
        );
      }
      if ((current.issuedDevicesV2 ?? []).length >= MAX_ISSUED_DEVICE_CATALOGUE_ENTRIES) {
        throw new WalletCoreError(
          'STORAGE_ERROR',
          'The issued-device catalogue reached its 256-entry safety limit.',
        );
      }
      return {
        ...current,
        issuedDevicesV2: [...(current.issuedDevicesV2 ?? []), structuredClone(device)],
      };
    }).then(() => undefined);
  }

  public update(
    localId: string,
    mutate: (record: LocalIdentityRecordV1) => LocalIdentityRecordV1,
  ): Promise<LocalIdentityRecordV1> {
    const current = this.#records.get(localId);
    if (current === undefined) {
      return Promise.reject(
        new WalletCoreError('IDENTITY_NOT_FOUND', `Local identity ${localId} does not exist.`),
      );
    }
    let updated: LocalIdentityRecordV1;
    try {
      updated = cloneRecord(mutate(cloneRecord(current)));
    } catch (error) {
      return Promise.reject(error instanceof Error ? error : new Error('Identity update failed.'));
    }
    if (updated.localId !== localId) {
      return Promise.reject(
        new WalletCoreError('STORAGE_ERROR', 'An identity update cannot change its local ID.'),
      );
    }
    this.#records.set(localId, cloneRecord(updated));
    return Promise.resolve(cloneRecord(updated));
  }

  public delete(localId: string): Promise<void> {
    this.#records.delete(localId);
    return Promise.resolve();
  }

  public reserveDeviceRecord(record: LocalIdentityRecordV1): Promise<void> {
    if (record.deviceV2 === undefined) {
      return Promise.reject(
        new WalletCoreError('INVALID_REQUEST', 'A reserved device record requires v2 metadata.'),
      );
    }
    if (
      [...this.#records.values()].some(
        (existing) => existing.deviceV2?.deviceId === record.deviceV2?.deviceId,
      )
    ) {
      return Promise.reject(
        new WalletCoreError(
          'REGISTRY_CONFLICT',
          'This device key is already installed in the wallet.',
        ),
      );
    }
    this.#records.set(record.localId, cloneRecord(record));
    return Promise.resolve();
  }
}
