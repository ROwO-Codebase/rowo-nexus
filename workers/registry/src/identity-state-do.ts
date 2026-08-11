import { DurableObject } from 'cloudflare:workers';
import { encodeBase64Url, identityGenesisV1Schema, registryEventV1Schema } from '@nexus/protocol';
import type { Base64Url32, NexusSubject, RegistryEventV1, RevokeBySecretV1 } from '@nexus/protocol';
import {
  NexusVerificationError,
  verifyRevocationSecret,
  verifyRevokeBySignature,
} from '@nexus/verifier';

import { fail, succeed } from './errors';
import {
  materializeRegistryEvent,
  secretRevocationActionHash,
  signatureRevocationActionHash,
} from './events';
import { migrateSchema } from './schema';
import type {
  AuthoritativeStatus,
  PreparedRegistration,
  RegistryEnv,
  RegistryErrorCode,
  RegistryMutation,
  RegistryResult,
  RevokeBySignatureCommand,
  StoredIdentityRow,
  StoredOutboxRow,
} from './types';
import {
  assertPreparedRegistration,
  parseSecretCommand,
  parseSignatureCommand,
} from './validation';

const BASE_RETRY_DELAY_MS = 2_000;
const MAX_RETRY_DELAY_MS = 5 * 60_000;
const MAX_CLOCK_SKEW_SECONDS = 60;
const MAX_REVOCATION_AGE_SECONDS = 300;

interface EventPayloadRow {
  [key: string]: SqlStorageValue;
  payload_jcs: string;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1_000);
}

function copyBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function verifierCode(error: unknown): RegistryErrorCode {
  if (!(error instanceof NexusVerificationError)) {
    return 'INTERNAL_ERROR';
  }
  switch (error.code) {
    case 'INVALID_SIGNATURE':
      return 'INVALID_SIGNATURE';
    case 'INVALID_REVOCATION_SECRET':
      return 'INVALID_REVOCATION_SECRET';
    case 'INVALID_SUBJECT':
      return 'INVALID_SUBJECT';
    case 'SEQUENCE_CONFLICT':
      return 'SEQUENCE_CONFLICT';
    case 'UNSUPPORTED_PROTOCOL':
      return 'UNSUPPORTED_PROTOCOL';
    case 'UNSUPPORTED_SUITE':
      return 'UNSUPPORTED_SUITE';
    case 'BAD_REQUEST':
    case 'WRONG_NONCE':
    case 'PROOF_NOT_YET_VALID':
    case 'PROOF_EXPIRED':
    case 'PROOF_LIFETIME_EXCEEDED':
      return 'BAD_REQUEST';
    default:
      return 'INTERNAL_ERROR';
  }
}

export class IdentityState extends DurableObject<RegistryEnv> {
  #flushPromise: Promise<void> | null = null;

  constructor(ctx: DurableObjectState, env: RegistryEnv) {
    super(ctx, env);
  }

  async register(input: PreparedRegistration): Promise<RegistryResult<RegistryMutation>> {
    try {
      // Recompute all self-certifying and decoded material at the DO boundary;
      // never trust even an internal caller's wire-supplied subject or hashes.
      const prepared = await assertPreparedRegistration(input);
      if (!prepared.ok) {
        return prepared;
      }
      const registration = prepared.value;

      // Validation and self-certifying recomputation complete before the first
      // write. Read-only probes for unknown subjects never create tables.
      migrateSchema(this.ctx);

      const existing = this.#readIdentity();
      if (existing !== null) {
        this.#kickOutbox();
        if (existing.genesis_jcs !== registration.genesisJcs) {
          this.#recordGenesisConflict();
          return fail('SUBJECT_GENESIS_CONFLICT');
        }
        return succeed(this.#mutationFromRow(existing));
      }

      const acceptedAt = nowSeconds();
      const materialized = await materializeRegistryEvent({
        protocol: 'nexus.registry-event.v1',
        eventType: 'registered',
        subject: registration.subject,
        genesisHash: registration.genesisHash,
        sequence: 0,
        state: 'active',
        acceptedAt,
        // The genesis hash is the v1 registration actionHash convention.
        actionHash: registration.genesisHash,
      });

      const result = this.ctx.storage.transactionSync<RegistryResult<RegistryMutation>>(() => {
        const raced = this.#readIdentity();
        if (raced !== null) {
          if (raced.genesis_jcs !== registration.genesisJcs) {
            this.#recordGenesisConflict();
            return fail('SUBJECT_GENESIS_CONFLICT');
          }
          return succeed(this.#mutationFromRow(raced));
        }

        this.ctx.storage.sql.exec(
          `INSERT INTO identity_state (
             singleton, subject, protocol, suite, genesis_jcs, genesis_hash,
             signing_public_key, agreement_public_key, revocation_commitment,
             state, sequence, registered_at, revoked_at, revocation_event_id
           ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 0, ?, NULL, NULL)`,
          registration.subject,
          registration.genesis.protocol,
          registration.genesis.suite,
          registration.genesisJcs,
          copyBuffer(registration.genesisHashBytes),
          copyBuffer(registration.signingPublicKey),
          registration.agreementPublicKey === null
            ? null
            : copyBuffer(registration.agreementPublicKey),
          copyBuffer(registration.revocationCommitment),
          acceptedAt,
        );
        this.#insertActionAndOutbox(
          0,
          'register',
          materialized.event.eventId,
          materialized.eventHash,
          acceptedAt,
          materialized.payloadJcs,
        );
        const inserted = this.#readIdentity();
        if (inserted === null) {
          throw new Error('Identity row was not persisted.');
        }
        return succeed(this.#mutationFromRow(inserted));
      });

      this.#kickOutbox();
      return result;
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }

  status(): RegistryResult<AuthoritativeStatus> {
    try {
      const row = this.#readIdentity();
      if (row === null) {
        return fail('IDENTITY_NOT_FOUND');
      }
      this.#kickOutbox();
      return succeed(this.#statusFromRow(row));
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }

  async revokeBySignature(
    input: RevokeBySignatureCommand,
  ): Promise<RegistryResult<RegistryMutation>> {
    const parsed = parseSignatureCommand(input);
    if (!parsed.ok) {
      return parsed;
    }

    try {
      const initial = this.#readIdentity();
      if (initial === null) {
        return fail('IDENTITY_NOT_FOUND');
      }
      if (initial.state === 'revoked') {
        this.#kickOutbox();
        return succeed(this.#mutationFromRow(initial));
      }
      migrateSchema(this.ctx);
      if (parsed.value.payload.expectedSequence !== initial.sequence) {
        return fail('SEQUENCE_CONFLICT');
      }

      const genesis = identityGenesisV1Schema.parse(JSON.parse(initial.genesis_jcs));
      const verificationTime = nowSeconds();
      try {
        await verifyRevokeBySignature(
          {
            mode: 'signature',
            payload: parsed.value.payload,
            signature: parsed.value.signature,
          },
          genesis,
          {
            subject: initial.subject as NexusSubject,
            expectedSequence: initial.sequence,
            nonce: parsed.value.payload.nonce,
            now: verificationTime,
            maxClockSkewSeconds: MAX_CLOCK_SKEW_SECONDS,
            maxAgeSeconds: MAX_REVOCATION_AGE_SECONDS,
          },
        );
      } catch (error) {
        return fail(verifierCode(error));
      }

      const actionHash = await signatureRevocationActionHash(parsed.value.payload);
      return await this.#commitRevocation(initial, actionHash);
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }

  async revokeBySecret(input: RevokeBySecretV1): Promise<RegistryResult<RegistryMutation>> {
    const parsed = parseSecretCommand(input);
    if (!parsed.ok) {
      return parsed;
    }

    try {
      const initial = this.#readIdentity();
      if (initial === null) {
        return fail('IDENTITY_NOT_FOUND');
      }
      if (initial.state === 'revoked') {
        this.#kickOutbox();
        return succeed(this.#mutationFromRow(initial));
      }
      migrateSchema(this.ctx);
      if (parsed.value.expectedSequence !== initial.sequence) {
        return fail('SEQUENCE_CONFLICT');
      }

      const genesis = identityGenesisV1Schema.parse(JSON.parse(initial.genesis_jcs));
      try {
        await verifyRevocationSecret({ mode: 'secret', payload: parsed.value }, genesis, {
          subject: initial.subject as NexusSubject,
          expectedSequence: initial.sequence,
        });
      } catch (error) {
        return fail(verifierCode(error));
      }

      const actionHash = await secretRevocationActionHash(
        parsed.value,
        new Uint8Array(initial.revocation_commitment),
      );
      return await this.#commitRevocation(initial, actionHash);
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }

  override async alarm(): Promise<void> {
    if (!this.#hasLifecycleSchema()) {
      return;
    }
    try {
      await this.#requestFlush();
    } catch {
      // Cloudflare's built-in alarm retries stop after six attempts. Explicitly
      // rescheduling here keeps a durable outbox recoverable through a long
      // Queue outage without ever rolling back authoritative lifecycle state.
      await this.ctx.storage.setAlarm(Date.now() + MAX_RETRY_DELAY_MS);
    }
  }

  async #commitRevocation(
    initial: StoredIdentityRow,
    actionHash: Base64Url32,
  ): Promise<RegistryResult<RegistryMutation>> {
    const acceptedAt = nowSeconds();
    const nextSequence = initial.sequence + 1;
    const materialized = await materializeRegistryEvent({
      protocol: 'nexus.registry-event.v1',
      eventType: 'revoked',
      subject: initial.subject as NexusSubject,
      genesisHash: encodeBase64Url(new Uint8Array(initial.genesis_hash)) as Base64Url32,
      sequence: nextSequence,
      state: 'revoked',
      acceptedAt,
      actionHash,
    });

    const result = this.ctx.storage.transactionSync<RegistryResult<RegistryMutation>>(() => {
      const current = this.#readIdentity();
      if (current === null) {
        return fail('IDENTITY_NOT_FOUND');
      }
      if (current.state === 'revoked') {
        return succeed(this.#mutationFromRow(current));
      }
      if (current.sequence !== initial.sequence) {
        return fail('SEQUENCE_CONFLICT');
      }

      this.ctx.storage.sql.exec(
        `UPDATE identity_state
           SET state = 'revoked', sequence = ?, revoked_at = ?, revocation_event_id = ?
         WHERE singleton = 1 AND state = 'active' AND sequence = ?`,
        nextSequence,
        acceptedAt,
        materialized.event.eventId,
        initial.sequence,
      );
      this.#insertActionAndOutbox(
        nextSequence,
        'revoke',
        materialized.event.eventId,
        materialized.eventHash,
        acceptedAt,
        materialized.payloadJcs,
      );
      const revoked = this.#readIdentity();
      if (revoked === null) {
        throw new Error('Revoked identity row disappeared.');
      }
      return succeed(this.#mutationFromRow(revoked));
    });

    this.#kickOutbox();
    return result;
  }

  #readIdentity(): StoredIdentityRow | null {
    if (!this.#hasLifecycleSchema()) {
      return null;
    }
    return (
      this.ctx.storage.sql
        .exec<StoredIdentityRow>('SELECT * FROM identity_state WHERE singleton = 1')
        .toArray()[0] ?? null
    );
  }

  #hasLifecycleSchema(): boolean {
    return (
      this.ctx.storage.sql
        .exec<{ present: number }>(
          `SELECT COUNT(*) AS present
             FROM sqlite_master
            WHERE type = 'table' AND name = 'identity_state'`,
        )
        .one().present === 1
    );
  }

  #eventForSequence(sequence: number): RegistryEventV1 {
    const row = this.ctx.storage.sql
      .exec<EventPayloadRow>(
        `SELECT o.payload_jcs
           FROM actions AS a
           JOIN outbox AS o ON o.event_id = a.event_id
          WHERE a.sequence = ?`,
        sequence,
      )
      .toArray()[0];
    if (row === undefined) {
      throw new Error('Identity action event is missing.');
    }
    return registryEventV1Schema.parse(JSON.parse(row.payload_jcs));
  }

  #statusFromRow(row: StoredIdentityRow): AuthoritativeStatus {
    const event = this.#eventForSequence(row.sequence);
    return {
      subject: row.subject,
      state: row.state,
      sequence: row.sequence,
      registeredAt: row.registered_at,
      revokedAt: row.revoked_at,
      genesis: identityGenesisV1Schema.parse(JSON.parse(row.genesis_jcs)),
      genesisHash: encodeBase64Url(new Uint8Array(row.genesis_hash)),
      eventId: event.eventId,
      eventType: event.eventType,
      acceptedAt: event.acceptedAt,
    };
  }

  #mutationFromRow(row: StoredIdentityRow): RegistryMutation {
    const event = this.#eventForSequence(row.sequence);
    return { ...this.#statusFromRow(row), event };
  }

  #insertActionAndOutbox(
    sequence: number,
    actionType: 'register' | 'revoke',
    eventId: string,
    eventHash: Uint8Array,
    acceptedAt: number,
    payloadJcs: string,
  ): void {
    this.ctx.storage.sql.exec(
      `INSERT INTO actions (sequence, event_id, action_type, event_hash, accepted_at)
       VALUES (?, ?, ?, ?, ?)`,
      sequence,
      eventId,
      actionType,
      copyBuffer(eventHash),
      acceptedAt,
    );
    this.ctx.storage.sql.exec(
      `INSERT INTO outbox (event_id, payload_jcs, created_at, published_at, attempt_count)
       VALUES (?, ?, ?, NULL, 0)`,
      eventId,
      payloadJcs,
      acceptedAt,
    );
  }

  #recordGenesisConflict(): void {
    // Privacy-safe critical signal: no subject, key, request, or network data.
    try {
      this.env.METRICS?.writeDataPoint({
        blobs: ['registry', 'subject_genesis_conflict'],
        doubles: [1],
      });
    } catch {
      // An operational metric must never alter authoritative conflict handling.
    }
  }

  #kickOutbox(): void {
    this.ctx.waitUntil(
      (async () => {
        await this.#ensureAlarm(Date.now() + BASE_RETRY_DELAY_MS);
        await this.#requestFlush();
      })(),
    );
  }

  #requestFlush(): Promise<void> {
    if (this.#flushPromise === null) {
      this.#flushPromise = this.#flushPendingOutbox().finally(() => {
        this.#flushPromise = null;
      });
    }
    return this.#flushPromise;
  }

  async #flushPendingOutbox(): Promise<void> {
    for (;;) {
      const pending = this.ctx.storage.sql
        .exec<StoredOutboxRow>(
          `SELECT event_id, payload_jcs, created_at, published_at, attempt_count
             FROM outbox
            WHERE published_at IS NULL
            ORDER BY created_at, event_id
            LIMIT 1`,
        )
        .toArray()[0];

      if (pending === undefined) {
        await this.ctx.storage.deleteAlarm();
        // Close the race in which a mutation committed while deleteAlarm was
        // yielding. A new pending row always gets either this loop or an alarm.
        const remaining = this.ctx.storage.sql
          .exec<{ pending: number }>(
            'SELECT COUNT(*) AS pending FROM outbox WHERE published_at IS NULL',
          )
          .one().pending;
        if (remaining === 0) {
          return;
        }
        await this.#ensureAlarm(Date.now() + BASE_RETRY_DELAY_MS);
        continue;
      }

      const attempt = this.ctx.storage.transactionSync<number>(() => {
        this.ctx.storage.sql.exec(
          'UPDATE outbox SET attempt_count = attempt_count + 1 WHERE event_id = ?',
          pending.event_id,
        );
        return this.ctx.storage.sql
          .exec<{ attempt_count: number }>(
            'SELECT attempt_count FROM outbox WHERE event_id = ?',
            pending.event_id,
          )
          .one().attempt_count;
      });

      const event = registryEventV1Schema.parse(JSON.parse(pending.payload_jcs));
      try {
        await this.env.REGISTRY_EVENTS.send(event);
      } catch {
        const exponent = Math.min(attempt - 1, 20);
        const delay = Math.min(MAX_RETRY_DELAY_MS, BASE_RETRY_DELAY_MS * 2 ** exponent);
        await this.ctx.storage.setAlarm(Date.now() + delay);
        return;
      }

      // A crash after send and before this write can duplicate the queue event;
      // this is intentional at-least-once behavior and eventId is stable.
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec(
          `UPDATE outbox
              SET published_at = ?
            WHERE event_id = ? AND published_at IS NULL`,
          nowSeconds(),
          pending.event_id,
        );
      });
    }
  }

  async #ensureAlarm(scheduledTime: number): Promise<void> {
    const current = await this.ctx.storage.getAlarm();
    if (current === null || current > scheduledTime) {
      await this.ctx.storage.setAlarm(scheduledTime);
    }
  }
}
