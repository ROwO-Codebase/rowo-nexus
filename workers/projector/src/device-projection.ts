import type { DeviceRegistryEventV2, RegistryEventV1 } from '@nexus/protocol';

interface GenesisRow {
  genesis_hash: string;
}

interface StoredDeviceEventRow {
  event_id: DeviceRegistryEventV2['eventId'];
  protocol: DeviceRegistryEventV2['protocol'];
  operation_id: DeviceRegistryEventV2['operationId'];
  event_type: DeviceRegistryEventV2['eventType'];
  subject: DeviceRegistryEventV2['subject'];
  genesis_hash: DeviceRegistryEventV2['genesisHash'];
  identity_sequence: number;
  identity_state: DeviceRegistryEventV2['identityState'];
  device_ledger_sequence: number;
  device_id: DeviceRegistryEventV2['deviceId'];
  authorization_id: NonNullable<DeviceRegistryEventV2['authorizationId']> | null;
  device_state: DeviceRegistryEventV2['deviceState'];
  authorization_expires_at: number | null;
  accepted_at: number;
  action_hash: DeviceRegistryEventV2['actionHash'];
  revoked_by: NonNullable<DeviceRegistryEventV2['revokedBy']> | null;
}

export class DeviceProjectionInvariantError extends Error {
  readonly code = 'DEVICE_PROJECTION_INVARIANT_VIOLATION';

  constructor(reason: string) {
    super(reason);
    this.name = 'DeviceProjectionInvariantError';
  }
}

/**
 * Prevents an independently delivered v2 event from attaching device state to
 * a conflicting v1 anchor. The subject hash should already make this
 * impossible; retaining the check gives the rebuildable projection a fail-
 * closed corruption boundary.
 */
async function assertDeviceEventGenesis(
  database: D1Database,
  event: DeviceRegistryEventV2,
): Promise<void> {
  const [identity, priorEvent] = await Promise.all([
    database
      .prepare('SELECT genesis_hash FROM identities WHERE subject = ? LIMIT 1')
      .bind(event.subject)
      .first<GenesisRow>(),
    database
      .prepare(
        `SELECT genesis_hash FROM device_registry_events
         WHERE subject = ? LIMIT 1`,
      )
      .bind(event.subject)
      .first<GenesisRow>(),
  ]);

  if (identity !== null && identity.genesis_hash !== event.genesisHash) {
    throw new DeviceProjectionInvariantError('device event conflicts with identity genesis hash');
  }
  if (priorEvent !== null && priorEvent.genesis_hash !== event.genesisHash) {
    throw new DeviceProjectionInvariantError('subject has conflicting device-event genesis hash');
  }
}

export async function assertRegistrationDeviceGenesis(
  database: D1Database,
  event: RegistryEventV1,
): Promise<void> {
  const priorEvent = await database
    .prepare(
      `SELECT genesis_hash FROM device_registry_events
       WHERE subject = ? LIMIT 1`,
    )
    .bind(event.subject)
    .first<GenesisRow>();
  if (priorEvent !== null && priorEvent.genesis_hash !== event.genesisHash) {
    throw new DeviceProjectionInvariantError(
      'registration conflicts with device-event genesis hash',
    );
  }
}

async function storeDeviceEvent(database: D1Database, event: DeviceRegistryEventV2): Promise<void> {
  await database
    .prepare(
      `INSERT INTO device_registry_events (
         event_id, protocol, operation_id, event_type, subject, genesis_hash,
         identity_sequence, identity_state, device_ledger_sequence, device_id,
         authorization_id, device_state, authorization_expires_at, accepted_at,
         action_hash, revoked_by
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(event_id) DO NOTHING`,
    )
    .bind(
      event.eventId,
      event.protocol,
      event.operationId,
      event.eventType,
      event.subject,
      event.genesisHash,
      event.identitySequence,
      event.identityState,
      event.deviceLedgerSequence,
      event.deviceId,
      event.authorizationId ?? null,
      event.deviceState,
      event.authorizationExpiresAt ?? null,
      event.acceptedAt,
      event.actionHash,
      event.revokedBy ?? null,
    )
    .run();
}

async function materializeDeviceEvent(
  database: D1Database,
  event: DeviceRegistryEventV2,
): Promise<void> {
  const identity = await database
    .prepare('SELECT genesis_hash FROM identities WHERE subject = ? LIMIT 1')
    .bind(event.subject)
    .first<GenesisRow>();
  if (identity === null) {
    return;
  }
  if (identity.genesis_hash !== event.genesisHash) {
    throw new DeviceProjectionInvariantError('device event conflicts with projected identity');
  }

  const activatedAt = event.eventType === 'activated' ? event.acceptedAt : null;
  const revokedAt = event.eventType === 'revoked' ? event.acceptedAt : null;

  await database.batch([
    database
      .prepare(
        `INSERT INTO device_states (
           subject, genesis_hash, device_id, authorization_id, state,
           event_sequence, authorization_expires_at, activated_at, revoked_at,
           revoked_by, updated_at, latest_event_id
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(subject, device_id) DO UPDATE SET
           authorization_id = COALESCE(excluded.authorization_id, device_states.authorization_id),
           state = excluded.state,
           event_sequence = excluded.event_sequence,
           authorization_expires_at = COALESCE(
             excluded.authorization_expires_at,
             device_states.authorization_expires_at
           ),
           activated_at = COALESCE(device_states.activated_at, excluded.activated_at),
           revoked_at = excluded.revoked_at,
           revoked_by = excluded.revoked_by,
           updated_at = excluded.updated_at,
           latest_event_id = excluded.latest_event_id
         WHERE device_states.event_sequence < excluded.event_sequence
           AND device_states.state <> 'revoked'`,
      )
      .bind(
        event.subject,
        event.genesisHash,
        event.deviceId,
        event.authorizationId ?? null,
        event.deviceState,
        event.deviceLedgerSequence,
        event.authorizationExpiresAt ?? null,
        activatedAt,
        revokedAt,
        event.revokedBy ?? null,
        event.acceptedAt,
        event.eventId,
      ),
    database
      .prepare(
        `INSERT INTO device_projection_heads (
           subject, genesis_hash, max_device_ledger_sequence, updated_at
         ) VALUES (?, ?, ?, ?)
         ON CONFLICT(subject) DO UPDATE SET
           max_device_ledger_sequence = excluded.max_device_ledger_sequence,
           updated_at = excluded.updated_at
         WHERE device_projection_heads.max_device_ledger_sequence
               < excluded.max_device_ledger_sequence`,
      )
      .bind(event.subject, event.genesisHash, event.deviceLedgerSequence, event.acceptedAt),
  ]);
}

export async function applyDeviceRegistryEvent(
  database: D1Database,
  event: DeviceRegistryEventV2,
): Promise<void> {
  await assertDeviceEventGenesis(database, event);
  await storeDeviceEvent(database, event);
  await materializeDeviceEvent(database, event);
}

/** Materialize v2 events that won their queue race against v1 registration. */
export async function reconcileDeviceEventsForIdentity(
  database: D1Database,
  subject: RegistryEventV1['subject'],
): Promise<void> {
  const result = await database
    .prepare(
      `SELECT event_id, protocol, operation_id, event_type, subject, genesis_hash,
              identity_sequence, identity_state, device_ledger_sequence, device_id,
              authorization_id, device_state, authorization_expires_at, accepted_at,
              action_hash, revoked_by
       FROM device_registry_events
       WHERE subject = ?
       ORDER BY device_ledger_sequence ASC`,
    )
    .bind(subject)
    .all<StoredDeviceEventRow>();

  for (const row of result.results) {
    await materializeDeviceEvent(database, deviceEventFromRow(row));
  }
}

function deviceEventFromRow(row: StoredDeviceEventRow): DeviceRegistryEventV2 {
  return {
    protocol: row.protocol,
    eventId: row.event_id,
    operationId: row.operation_id,
    eventType: row.event_type,
    subject: row.subject,
    genesisHash: row.genesis_hash,
    identitySequence: row.identity_sequence,
    identityState: row.identity_state,
    deviceLedgerSequence: row.device_ledger_sequence,
    deviceId: row.device_id,
    ...(row.authorization_id === null ? {} : { authorizationId: row.authorization_id }),
    deviceState: row.device_state,
    ...(row.authorization_expires_at === null
      ? {}
      : { authorizationExpiresAt: row.authorization_expires_at }),
    acceptedAt: row.accepted_at,
    actionHash: row.action_hash,
    ...(row.revoked_by === null ? {} : { revokedBy: row.revoked_by }),
  };
}
