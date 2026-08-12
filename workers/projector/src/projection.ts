import { IDENTITY_PROTOCOL_V1, NEXUS_SUITE_V1, type RegistryEventV1 } from '@nexus/protocol';

import {
  assertRegistrationDeviceGenesis,
  reconcileDeviceEventsForIdentity,
} from './device-projection';

interface IdentityGenesisRow {
  genesis_hash: string;
}

export class ProjectionInvariantError extends Error {
  readonly code = 'PROJECTION_INVARIANT_VIOLATION';

  constructor(reason: string) {
    super(reason);
    this.name = 'ProjectionInvariantError';
  }
}

async function assertIdentityGenesis(database: D1Database, event: RegistryEventV1): Promise<void> {
  const identity = await database
    .prepare('SELECT genesis_hash FROM identities WHERE subject = ? LIMIT 1')
    .bind(event.subject)
    .first<IdentityGenesisRow>();

  if (identity !== null && identity.genesis_hash !== event.genesisHash) {
    throw new ProjectionInvariantError('subject has conflicting genesis hash');
  }
}

async function applyRegistration(database: D1Database, event: RegistryEventV1): Promise<void> {
  await assertIdentityGenesis(database, event);
  await assertRegistrationDeviceGenesis(database, event);

  await database.batch([
    database
      .prepare(
        `INSERT INTO identities (
           subject, genesis_hash, protocol, suite, state, sequence,
           registered_at, revoked_at, updated_at
         ) VALUES (?, ?, ?, ?, 'active', 0, ?, NULL, ?)
         ON CONFLICT(subject) DO NOTHING`,
      )
      .bind(
        event.subject,
        event.genesisHash,
        IDENTITY_PROTOCOL_V1,
        NEXUS_SUITE_V1,
        event.acceptedAt,
        event.acceptedAt,
      ),
    database
      .prepare(
        `INSERT INTO registry_events (
           event_id, subject, event_type, sequence, accepted_at, action_hash
         )
         SELECT ?, ?, ?, ?, ?, ?
         WHERE EXISTS (
           SELECT 1 FROM identities
           WHERE subject = ? AND genesis_hash = ?
         )
         ON CONFLICT(event_id) DO NOTHING`,
      )
      .bind(
        event.eventId,
        event.subject,
        event.eventType,
        event.sequence,
        event.acceptedAt,
        event.actionHash,
        event.subject,
        event.genesisHash,
      ),
    database
      .prepare(
        `UPDATE identities
         SET state = 'revoked',
             sequence = (
               SELECT sequence FROM pending_registry_events
               WHERE subject = identities.subject
                 AND genesis_hash = identities.genesis_hash
                 AND sequence = identities.sequence + 1
               LIMIT 1
             ),
             revoked_at = (
               SELECT accepted_at FROM pending_registry_events
               WHERE subject = identities.subject
                 AND genesis_hash = identities.genesis_hash
                 AND sequence = identities.sequence + 1
               LIMIT 1
             ),
             updated_at = (
               SELECT accepted_at FROM pending_registry_events
               WHERE subject = identities.subject
                 AND genesis_hash = identities.genesis_hash
                 AND sequence = identities.sequence + 1
               LIMIT 1
             )
         WHERE subject = ?
           AND state = 'active'
           AND EXISTS (
             SELECT 1 FROM pending_registry_events
             WHERE subject = identities.subject
               AND genesis_hash = identities.genesis_hash
               AND event_type = 'revoked'
               AND state = 'revoked'
               AND sequence = identities.sequence + 1
           )`,
      )
      .bind(event.subject),
    database
      .prepare(
        `INSERT INTO registry_events (
           event_id, subject, event_type, sequence, accepted_at, action_hash
         )
         SELECT pending.event_id, pending.subject, pending.event_type,
                pending.sequence, pending.accepted_at, pending.action_hash
         FROM pending_registry_events AS pending
         JOIN identities AS identity
           ON identity.subject = pending.subject
          AND identity.genesis_hash = pending.genesis_hash
          AND identity.sequence >= pending.sequence
         WHERE pending.subject = ?
         ON CONFLICT(event_id) DO NOTHING`,
      )
      .bind(event.subject),
    database
      .prepare(
        `DELETE FROM pending_registry_events
         WHERE subject = ?
           AND EXISTS (
             SELECT 1 FROM registry_events
             WHERE registry_events.event_id = pending_registry_events.event_id
           )`,
      )
      .bind(event.subject),
  ]);

  // Device events use a separate Queue and may arrive first. Reconcile only
  // after the matching v1 anchor has been projected.
  await reconcileDeviceEventsForIdentity(database, event.subject);
}

async function applyRevocation(database: D1Database, event: RegistryEventV1): Promise<void> {
  await assertIdentityGenesis(database, event);

  await database.batch([
    database
      .prepare(
        `UPDATE identities
         SET state = 'revoked', sequence = ?, revoked_at = ?, updated_at = ?
         WHERE subject = ?
           AND genesis_hash = ?
           AND state = 'active'
           AND sequence + 1 = ?`,
      )
      .bind(
        event.sequence,
        event.acceptedAt,
        event.acceptedAt,
        event.subject,
        event.genesisHash,
        event.sequence,
      ),
    database
      .prepare(
        `INSERT INTO registry_events (
           event_id, subject, event_type, sequence, accepted_at, action_hash
         )
         SELECT ?, ?, ?, ?, ?, ?
         WHERE EXISTS (
           SELECT 1 FROM identities
           WHERE subject = ?
             AND genesis_hash = ?
             AND sequence >= ?
         )
         ON CONFLICT(event_id) DO NOTHING`,
      )
      .bind(
        event.eventId,
        event.subject,
        event.eventType,
        event.sequence,
        event.acceptedAt,
        event.actionHash,
        event.subject,
        event.genesisHash,
        event.sequence,
      ),
    database
      .prepare(
        `INSERT INTO pending_registry_events (
           event_id, protocol, event_type, subject, genesis_hash,
           sequence, state, accepted_at, action_hash
         )
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
         WHERE NOT EXISTS (
           SELECT 1 FROM identities WHERE subject = ?
         )
         ON CONFLICT(event_id) DO NOTHING`,
      )
      .bind(
        event.eventId,
        event.protocol,
        event.eventType,
        event.subject,
        event.genesisHash,
        event.sequence,
        event.state,
        event.acceptedAt,
        event.actionHash,
        event.subject,
      ),
    database
      .prepare(
        `DELETE FROM pending_registry_events
         WHERE event_id = ?
           AND EXISTS (
             SELECT 1 FROM registry_events WHERE event_id = ?
           )`,
      )
      .bind(event.eventId, event.eventId),
  ]);
}

export async function applyRegistryEvent(
  database: D1Database,
  event: RegistryEventV1,
): Promise<void> {
  if (event.eventType === 'registered') {
    await applyRegistration(database, event);
    return;
  }

  await applyRevocation(database, event);
}
