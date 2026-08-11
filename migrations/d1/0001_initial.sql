PRAGMA foreign_keys = ON;

-- This database is a rebuildable operational projection. It is never a
-- lifecycle authorization source; IdentityState Durable Objects remain the
-- sole authority for current state.
CREATE TABLE identities (
  subject TEXT PRIMARY KEY,
  genesis_hash TEXT NOT NULL,
  protocol TEXT NOT NULL CHECK (protocol = 'nexus.identity.v1'),
  suite TEXT NOT NULL CHECK (suite = 'NX-25519-SHA256-JCS-v1'),
  state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
  sequence INTEGER NOT NULL CHECK (sequence >= 0),
  registered_at INTEGER NOT NULL CHECK (registered_at >= 0),
  revoked_at INTEGER CHECK (revoked_at IS NULL OR revoked_at >= 0),
  updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
  CHECK (
    (state = 'active' AND revoked_at IS NULL) OR
    (state = 'revoked' AND revoked_at IS NOT NULL)
  )
);

CREATE TABLE registry_events (
  event_id TEXT PRIMARY KEY,
  subject TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('registered', 'revoked')),
  sequence INTEGER NOT NULL CHECK (sequence >= 0),
  accepted_at INTEGER NOT NULL CHECK (accepted_at >= 0),
  action_hash TEXT NOT NULL,
  FOREIGN KEY (subject) REFERENCES identities(subject)
);

-- A revocation may be delivered before registration because Queues delivery
-- is at-least-once and unordered. Keep the exact RegistryEventV1 fields until
-- the registration event creates the only legitimate identity row.
CREATE TABLE pending_registry_events (
  event_id TEXT PRIMARY KEY,
  protocol TEXT NOT NULL CHECK (protocol = 'nexus.registry-event.v1'),
  event_type TEXT NOT NULL CHECK (event_type = 'revoked'),
  subject TEXT NOT NULL,
  genesis_hash TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK (sequence = 1),
  state TEXT NOT NULL CHECK (state = 'revoked'),
  accepted_at INTEGER NOT NULL CHECK (accepted_at >= 0),
  action_hash TEXT NOT NULL
);

CREATE INDEX idx_identities_state ON identities(state);
CREATE INDEX idx_identities_registered_at ON identities(registered_at);
CREATE UNIQUE INDEX idx_registry_events_subject_sequence
  ON registry_events(subject, sequence);
CREATE UNIQUE INDEX idx_pending_registry_events_subject_sequence
  ON pending_registry_events(subject, sequence);
