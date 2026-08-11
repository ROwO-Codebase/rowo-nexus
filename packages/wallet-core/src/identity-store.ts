import {
  DEFAULT_WALLET_DATABASE_NAME,
  IDENTITY_RECORD_STORE,
  openWalletDatabase,
  requestResult,
  requireIndexedDb,
  transactionComplete,
} from './indexed-db.js';
import type { IdentityStore, LocalIdentityRecordV1 } from './types.js';

export interface IndexedDbIdentityStoreOptions {
  databaseName?: string;
  indexedDB?: IDBFactory;
}

function cloneRecord(record: LocalIdentityRecordV1): LocalIdentityRecordV1 {
  return structuredClone(record);
}

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

  public async delete(localId: string): Promise<void> {
    const database = await this.#open();
    const transaction = database.transaction(IDENTITY_RECORD_STORE, 'readwrite');
    const completion = transactionComplete(transaction);
    await requestResult(transaction.objectStore(IDENTITY_RECORD_STORE).delete(localId));
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

  public delete(localId: string): Promise<void> {
    this.#records.delete(localId);
    return Promise.resolve();
  }
}
