const SCHEMA_VERSION = 2;

interface SchemaVersionRow {
  [key: string]: SqlStorageValue;
  version: number;
}

/**
 * Runs synchronously at an authoritative method boundary. The three v1
 * protocol tables stay byte-for-byte unchanged; v2 device authority uses
 * separate additive tables and a separate monotonic sequence.
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

    if (current !== undefined && current.version !== 1 && current.version !== SCHEMA_VERSION) {
      throw new Error(`Unsupported IdentityState schema version ${current.version}.`);
    }
    if (current === undefined) {
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
      sql.exec('INSERT INTO schema_meta (singleton, version) VALUES (1, 1)');
    }

    // Device authority is deliberately stored beside, rather than folded into,
    // the v1 lifecycle tables. In particular, no device mutation may alter the
    // v1 identity_state.sequence or the exact actions/outbox schemas.
    sql.exec(`
      CREATE TABLE IF NOT EXISTS device_ledger (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        sequence INTEGER NOT NULL
      )
    `);
    sql.exec(`
      CREATE TABLE IF NOT EXISTS device_state (
        device_id TEXT PRIMARY KEY,
        authorization_id TEXT,
        authorization_jcs TEXT,
        signing_public_key BLOB,
        state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
        authorization_expires_at INTEGER,
        activated_at INTEGER,
        revoked_at INTEGER,
        revoked_by TEXT CHECK (revoked_by IS NULL OR revoked_by IN ('root', 'device')),
        activation_event_id TEXT,
        revocation_event_id TEXT
      )
    `);
    sql.exec(`
      CREATE TABLE IF NOT EXISTS device_operations (
        operation_id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL UNIQUE,
        operation_type TEXT NOT NULL CHECK (operation_type IN ('activate', 'revoke-root', 'revoke-self')),
        device_id TEXT NOT NULL,
        authorization_id TEXT,
        event_hash BLOB NOT NULL,
        accepted_at INTEGER NOT NULL
      )
    `);
    sql.exec(`
      CREATE TABLE IF NOT EXISTS device_outbox (
        event_id TEXT PRIMARY KEY,
        payload_jcs TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        published_at INTEGER,
        attempt_count INTEGER NOT NULL DEFAULT 0
      )
    `);
    sql.exec('INSERT OR IGNORE INTO device_ledger (singleton, sequence) VALUES (1, 0)');
    sql.exec('UPDATE schema_meta SET version = ? WHERE singleton = 1', SCHEMA_VERSION);
  });
}
