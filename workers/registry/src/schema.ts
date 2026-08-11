const SCHEMA_VERSION = 1;

interface SchemaVersionRow {
  [key: string]: SqlStorageValue;
  version: number;
}

/**
 * Runs synchronously inside the constructor's blockConcurrencyWhile gate. The
 * three protocol tables intentionally match NEXUS_SPEC section 21 exactly;
 * schema_meta is only the local SQLite migration ledger.
 */
export function migrateSchema(state: DurableObjectState): void {
  state.storage.transactionSync(() => {
    const sql = state.storage.sql;
    sql.exec(`
      CREATE TABLE IF NOT EXISTS schema_meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        version INTEGER NOT NULL
      )
    `);

    const current = sql
      .exec<SchemaVersionRow>('SELECT version FROM schema_meta WHERE singleton = 1')
      .toArray()[0];

    if (current !== undefined && current.version !== SCHEMA_VERSION) {
      throw new Error(`Unsupported IdentityState schema version ${current.version}.`);
    }
    if (current !== undefined) {
      return;
    }

    sql.exec(`
      CREATE TABLE IF NOT EXISTS identity_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        subject TEXT NOT NULL UNIQUE,
        protocol TEXT NOT NULL,
        suite TEXT NOT NULL,
        genesis_jcs TEXT NOT NULL,
        genesis_hash BLOB NOT NULL,
        signing_public_key BLOB NOT NULL,
        agreement_public_key BLOB,
        revocation_commitment BLOB NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
        sequence INTEGER NOT NULL,
        registered_at INTEGER NOT NULL,
        revoked_at INTEGER,
        revocation_event_id TEXT
      )
    `);
    sql.exec(`
      CREATE TABLE IF NOT EXISTS actions (
        sequence INTEGER PRIMARY KEY,
        event_id TEXT NOT NULL UNIQUE,
        action_type TEXT NOT NULL,
        event_hash BLOB NOT NULL,
        accepted_at INTEGER NOT NULL
      )
    `);
    sql.exec(`
      CREATE TABLE IF NOT EXISTS outbox (
        event_id TEXT PRIMARY KEY,
        payload_jcs TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        published_at INTEGER,
        attempt_count INTEGER NOT NULL DEFAULT 0
      )
    `);
    sql.exec('INSERT INTO schema_meta (singleton, version) VALUES (1, ?)', SCHEMA_VERSION);
  });
}
