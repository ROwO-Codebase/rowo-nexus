-- Device registry events use a separate, additive ledger. They deliberately do
-- not change the v1 identity lifecycle sequence.
--
-- Device events may arrive before the v1 registration event because the two
-- queues are independently at-least-once and unordered. The event table
-- therefore has no identity foreign key. Materialized device state is created
-- only after the matching v1 identity anchor is present.
CREATE TABLE device_registry_events (
  event_id TEXT PRIMARY KEY,
  protocol TEXT NOT NULL CHECK (protocol = 'nexus.device-registry-event.v2'),
  operation_id TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL CHECK (event_type IN ('activated', 'revoked')),
  subject TEXT NOT NULL,
  genesis_hash TEXT NOT NULL,
  identity_sequence INTEGER NOT NULL CHECK (identity_sequence IN (0, 1)),
  identity_state TEXT NOT NULL CHECK (identity_state IN ('active', 'revoked')),
  device_ledger_sequence INTEGER NOT NULL CHECK (device_ledger_sequence >= 1),
  device_id TEXT NOT NULL,
  authorization_id TEXT,
  device_state TEXT NOT NULL CHECK (device_state IN ('active', 'revoked')),
  authorization_expires_at INTEGER
    CHECK (authorization_expires_at IS NULL OR authorization_expires_at >= 0),
  accepted_at INTEGER NOT NULL CHECK (accepted_at >= 0),
  action_hash TEXT NOT NULL,
  revoked_by TEXT CHECK (revoked_by IS NULL OR revoked_by IN ('root', 'device')),
  CHECK (
    (event_type = 'activated' AND device_state = 'active'
      AND identity_state = 'active' AND identity_sequence = 0
      AND authorization_id IS NOT NULL AND authorization_expires_at IS NOT NULL
      AND revoked_by IS NULL)
    OR
    (event_type = 'revoked' AND device_state = 'revoked'
      AND revoked_by IS NOT NULL)
  ),
  UNIQUE (subject, device_ledger_sequence)
);

-- This is an internal operational projection only. No Worker route enumerates
-- this table. In particular, it contains no private key, device label,
-- platform metadata, RP scope, or installation identifier.
CREATE TABLE device_states (
  subject TEXT NOT NULL,
  genesis_hash TEXT NOT NULL,
  device_id TEXT NOT NULL,
  authorization_id TEXT,
  state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
  event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1),
  authorization_expires_at INTEGER
    CHECK (authorization_expires_at IS NULL OR authorization_expires_at >= 0),
  activated_at INTEGER CHECK (activated_at IS NULL OR activated_at >= 0),
  revoked_at INTEGER CHECK (revoked_at IS NULL OR revoked_at >= 0),
  revoked_by TEXT CHECK (revoked_by IS NULL OR revoked_by IN ('root', 'device')),
  updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
  latest_event_id TEXT NOT NULL UNIQUE,
  PRIMARY KEY (subject, device_id),
  FOREIGN KEY (subject) REFERENCES identities(subject),
  FOREIGN KEY (latest_event_id) REFERENCES device_registry_events(event_id),
  CHECK (
    (state = 'active' AND authorization_id IS NOT NULL
      AND authorization_expires_at IS NOT NULL AND activated_at IS NOT NULL
      AND revoked_at IS NULL AND revoked_by IS NULL)
    OR
    (state = 'revoked' AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL)
  )
);

CREATE TABLE device_projection_heads (
  subject TEXT PRIMARY KEY,
  genesis_hash TEXT NOT NULL,
  max_device_ledger_sequence INTEGER NOT NULL
    CHECK (max_device_ledger_sequence >= 1),
  updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
  FOREIGN KEY (subject) REFERENCES identities(subject)
);

CREATE INDEX idx_device_registry_events_subject_device
  ON device_registry_events(subject, device_id);
CREATE INDEX idx_device_registry_events_subject_accepted
  ON device_registry_events(subject, accepted_at);
CREATE INDEX idx_device_states_state ON device_states(state);
