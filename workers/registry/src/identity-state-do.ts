import { DurableObject } from 'cloudflare:workers';
import {
  canonicalize,
  decodeBase64UrlExact,
  deviceActivationRequestV2Schema,
  deviceRegistryEventV2Schema,
  deviceRootRevokeRequestV2Schema,
  deviceSelfRevokeRequestV2Schema,
  encodeBase64Url,
  identityGenesisV1Schema,
  registryEventV1Schema,
} from '@nexus/protocol';
import type {
  Base64Url32,
  DeviceActivationRequestV2,
  DeviceAuthorizationV2,
  DeviceRegistryEventV2,
  DeviceRootRevokeRequestV2,
  DeviceSelfRevokeRequestV2,
  DeviceOperationPayloadV2,
  NexusDeviceAuthorizationIdV2,
  NexusDeviceIdV2,
  NexusDeviceOperationIdV2,
  NexusSubject,
  RegistryEventV1,
  RevokeBySecretV1,
} from '@nexus/protocol';
import {
  constantTimeEqual,
  deriveDeviceAuthorizationIdV2,
  deriveDeviceIdV2,
  deriveDeviceOperationIdV2,
  getDefaultCryptoProvider,
  verifyProtocolPayload,
} from '@nexus/crypto';
import {
  NexusVerificationError,
  verifyRevocationSecret,
  verifyRevokeBySignature,
} from '@nexus/verifier';

import { fail, succeed } from './errors';
import {
  materializeRegistryEvent,
  materializeDeviceRegistryEvent,
  secretRevocationActionHash,
  signedDeviceActionHash,
  signatureRevocationActionHash,
} from './events';
import { migrateSchema } from './schema';
import type {
  AuthoritativeStatus,
  AuthoritativeDeviceStatusV2,
  DeviceRegistryMutationV2,
  PreparedRegistration,
  RegistryEnv,
  RegistryErrorCode,
  RegistryMutation,
  RegistryResult,
  RevokeBySignatureCommand,
  StoredIdentityRow,
  StoredDeviceRow,
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
const MAX_DEVICE_REQUEST_LIFETIME_SECONDS = 300;
const MAX_DEVICE_ACTIVATION_WINDOW_SECONDS = 30 * 24 * 60 * 60;
const MAX_DEVICE_AUTHORIZATION_LIFETIME_SECONDS = 366 * 24 * 60 * 60;

interface EventPayloadRow {
  [key: string]: SqlStorageValue;
  payload_jcs: string;
}

interface DeviceLedgerRow {
  [key: string]: SqlStorageValue;
  sequence: number;
}

interface PendingOutboxRow extends StoredOutboxRow {
  kind: 'identity' | 'device';
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
      migrateSchema(this.ctx);
      this.#kickOutbox();
      return succeed(this.#statusFromRow(row));
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }

  async activateDevice(
    input: DeviceActivationRequestV2,
  ): Promise<RegistryResult<DeviceRegistryMutationV2>> {
    return await this.ctx.blockConcurrencyWhile(async () => await this.#activateDevice(input));
  }

  deviceStatus(input: {
    deviceId: NexusDeviceIdV2;
    authorizationId: NexusDeviceAuthorizationIdV2;
  }): RegistryResult<AuthoritativeDeviceStatusV2> {
    try {
      const initial = this.#readIdentity();
      if (initial === null) {
        return fail('IDENTITY_NOT_FOUND');
      }
      migrateSchema(this.ctx);
      const row = this.#readDevice(input.deviceId);
      this.#kickOutbox();
      return succeed(
        this.#deviceStatusFromRow(initial, row, input.deviceId, input.authorizationId),
      );
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }

  async revokeDeviceSelf(
    input: DeviceSelfRevokeRequestV2,
  ): Promise<RegistryResult<DeviceRegistryMutationV2>> {
    return await this.ctx.blockConcurrencyWhile(async () => await this.#revokeDeviceSelf(input));
  }

  async revokeDeviceRoot(
    input: DeviceRootRevokeRequestV2,
  ): Promise<RegistryResult<DeviceRegistryMutationV2>> {
    return await this.ctx.blockConcurrencyWhile(async () => await this.#revokeDeviceRoot(input));
  }

  async #activateDevice(
    input: DeviceActivationRequestV2,
  ): Promise<RegistryResult<DeviceRegistryMutationV2>> {
    const parsed = deviceActivationRequestV2Schema.safeParse(input);
    if (!parsed.success) return fail('BAD_REQUEST');

    try {
      const identity = this.#readIdentity();
      if (identity === null) return fail('IDENTITY_NOT_FOUND');
      migrateSchema(this.ctx);

      const verified = await this.#verifyAuthorization(identity, parsed.data.authorization);
      if (!verified.ok) return verified;
      const { authorizationId, deviceId } = verified.value;
      const payload = parsed.data.payload;
      if (
        payload.subject !== identity.subject ||
        payload.deviceId !== deviceId ||
        payload.authorizationId !== authorizationId
      ) {
        return fail('BAD_REQUEST');
      }
      if (
        !(await this.#verifyDeviceSignature(
          parsed.data.authorization,
          payload,
          parsed.data.deviceSignature,
        ))
      ) {
        return fail('INVALID_SIGNATURE');
      }
      if (identity.state === 'revoked') return fail('IDENTITY_REVOKED');
      const existing = this.#readDevice(deviceId);
      if (existing?.state === 'revoked') return fail('DEVICE_REVOKED');
      if (existing !== null && existing.authorization_id !== authorizationId) {
        return fail('DEVICE_AUTHORIZATION_CONFLICT');
      }
      const operationId = await deriveDeviceOperationIdV2(payload);
      const replay = this.#readDeviceOperation(operationId);
      if (replay !== null) {
        const row = this.#readDevice(deviceId);
        if (row === null) throw new Error('Device operation target is missing.');
        this.#kickOutbox();
        return succeed(this.#deviceMutationFromEvent(identity, row, replay.event_id));
      }
      const now = nowSeconds();
      const authorization = parsed.data.authorization.payload;
      if (
        authorization.validFrom > authorization.activationDeadline ||
        authorization.activationDeadline > authorization.expiresAt ||
        authorization.activationDeadline - authorization.validFrom >
          MAX_DEVICE_ACTIVATION_WINDOW_SECONDS ||
        authorization.expiresAt - authorization.validFrom >
          MAX_DEVICE_AUTHORIZATION_LIFETIME_SECONDS ||
        now + MAX_CLOCK_SKEW_SECONDS < authorization.validFrom ||
        now - MAX_CLOCK_SKEW_SECONDS > authorization.activationDeadline ||
        now >= authorization.expiresAt ||
        payload.iat > payload.exp ||
        payload.exp - payload.iat > MAX_DEVICE_REQUEST_LIFETIME_SECONDS ||
        now + MAX_CLOCK_SKEW_SECONDS < payload.iat ||
        now - MAX_CLOCK_SKEW_SECONDS > payload.exp
      ) {
        return fail('BAD_REQUEST');
      }
      if (existing !== null) {
        if (existing.activation_event_id === null)
          throw new Error('Active device lacks activation event.');
        this.#kickOutbox();
        return succeed(
          this.#deviceMutationFromEvent(identity, existing, existing.activation_event_id),
        );
      }

      const acceptedAt = now;
      const nextSequence = this.#readDeviceLedgerSequence() + 1;
      const actionHash = await signedDeviceActionHash(payload);
      const materialized = await materializeDeviceRegistryEvent({
        protocol: 'nexus.device-registry-event.v2',
        operationId,
        eventType: 'activated',
        subject: identity.subject,
        genesisHash: encodeBase64Url(new Uint8Array(identity.genesis_hash)) as Base64Url32,
        identitySequence: identity.sequence,
        identityState: 'active',
        deviceLedgerSequence: nextSequence,
        deviceId,
        authorizationId,
        deviceState: 'active',
        authorizationExpiresAt: authorization.expiresAt,
        acceptedAt,
        actionHash,
      });

      const result = this.ctx.storage.transactionSync<RegistryResult<DeviceRegistryMutationV2>>(
        () => {
          const currentIdentity = this.#readIdentity();
          if (currentIdentity === null) return fail('IDENTITY_NOT_FOUND');
          if (currentIdentity.state === 'revoked') return fail('IDENTITY_REVOKED');
          const current = this.#readDevice(deviceId);
          if (current?.state === 'revoked') return fail('DEVICE_REVOKED');
          if (current !== null) {
            if (current.authorization_id !== authorizationId)
              return fail('DEVICE_AUTHORIZATION_CONFLICT');
            if (current.activation_event_id === null)
              throw new Error('Active device lacks activation event.');
            return succeed(
              this.#deviceMutationFromEvent(currentIdentity, current, current.activation_event_id),
            );
          }
          if (this.#readDeviceLedgerSequence() + 1 !== nextSequence)
            return fail('SEQUENCE_CONFLICT');

          this.ctx.storage.sql.exec(
            `INSERT INTO device_state (
             device_id, authorization_id, authorization_jcs, signing_public_key, state,
             authorization_expires_at, activated_at, revoked_at, revoked_by,
             activation_event_id, revocation_event_id
           ) VALUES (?, ?, ?, ?, 'active', ?, ?, NULL, NULL, ?, NULL)`,
            deviceId,
            authorizationId,
            canonicalize(parsed.data.authorization),
            copyBuffer(decodeBase64UrlExact(authorization.signingKey.publicKey, 32)),
            authorization.expiresAt,
            acceptedAt,
            materialized.event.eventId,
          );
          this.#writeDeviceLedgerSequence(nextSequence);
          this.#insertDeviceOperationAndOutbox(
            operationId,
            'activate',
            deviceId,
            authorizationId,
            materialized.event.eventId,
            materialized.eventHash,
            acceptedAt,
            materialized.payloadJcs,
          );
          const inserted = this.#readDevice(deviceId);
          if (inserted === null) throw new Error('Activated device was not persisted.');
          return succeed(
            this.#deviceMutationFromEvent(currentIdentity, inserted, materialized.event.eventId),
          );
        },
      );
      this.#kickOutbox();
      return result;
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }

  async #revokeDeviceSelf(
    input: DeviceSelfRevokeRequestV2,
  ): Promise<RegistryResult<DeviceRegistryMutationV2>> {
    const parsed = deviceSelfRevokeRequestV2Schema.safeParse(input);
    if (!parsed.success) return fail('BAD_REQUEST');
    try {
      const identity = this.#readIdentity();
      if (identity === null) return fail('IDENTITY_NOT_FOUND');
      migrateSchema(this.ctx);
      const verified = await this.#verifyAuthorization(identity, parsed.data.authorization);
      if (!verified.ok) return verified;
      const payload = parsed.data.payload;
      if (
        payload.subject !== identity.subject ||
        payload.genesisHash !== encodeBase64Url(new Uint8Array(identity.genesis_hash)) ||
        payload.deviceId !== verified.value.deviceId ||
        payload.authorizationId !== verified.value.authorizationId
      )
        return fail('BAD_REQUEST');
      if (
        !(await this.#verifyDeviceSignature(
          parsed.data.authorization,
          payload,
          parsed.data.deviceSignature,
        ))
      ) {
        return fail('INVALID_SIGNATURE');
      }
      if (identity.state === 'revoked') return fail('IDENTITY_REVOKED');
      const operationId = await deriveDeviceOperationIdV2(payload);
      const replay = this.#readDeviceOperation(operationId);
      if (replay !== null) {
        const row = this.#readDevice(payload.deviceId);
        if (row === null) throw new Error('Device operation target is missing.');
        this.#kickOutbox();
        return succeed(this.#deviceMutationFromEvent(identity, row, replay.event_id));
      }
      const now = nowSeconds();
      if (
        payload.issuedAt > now + MAX_CLOCK_SKEW_SECONDS ||
        now - payload.issuedAt > MAX_REVOCATION_AGE_SECONDS
      )
        return fail('BAD_REQUEST');
      return await this.#commitDeviceRevocation({
        identity,
        deviceId: verified.value.deviceId,
        authorizationId: verified.value.authorizationId,
        authorization: parsed.data.authorization,
        payload,
        revokedBy: 'device',
      });
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }

  async #revokeDeviceRoot(
    input: DeviceRootRevokeRequestV2,
  ): Promise<RegistryResult<DeviceRegistryMutationV2>> {
    const parsed = deviceRootRevokeRequestV2Schema.safeParse(input);
    if (!parsed.success) return fail('BAD_REQUEST');
    try {
      const identity = this.#readIdentity();
      if (identity === null) return fail('IDENTITY_NOT_FOUND');
      migrateSchema(this.ctx);
      const payload = parsed.data.payload;
      if (
        payload.subject !== identity.subject ||
        payload.genesisHash !== encodeBase64Url(new Uint8Array(identity.genesis_hash))
      )
        return fail('BAD_REQUEST');
      const rootKey = await getDefaultCryptoProvider().importEd25519PublicKey(
        new Uint8Array(identity.signing_public_key),
      );
      if (!(await verifyProtocolPayload(payload, parsed.data.rootSignature, rootKey))) {
        return fail('INVALID_SIGNATURE');
      }
      if (identity.state === 'revoked') return fail('IDENTITY_REVOKED');
      const operationId = await deriveDeviceOperationIdV2(payload);
      const replay = this.#readDeviceOperation(operationId);
      if (replay !== null) {
        const row = this.#readDevice(payload.deviceId);
        if (row === null) throw new Error('Device operation target is missing.');
        this.#kickOutbox();
        return succeed(this.#deviceMutationFromEvent(identity, row, replay.event_id));
      }
      const now = nowSeconds();
      if (
        payload.issuedAt > now + MAX_CLOCK_SKEW_SECONDS ||
        now - payload.issuedAt > MAX_REVOCATION_AGE_SECONDS
      )
        return fail('BAD_REQUEST');
      return await this.#commitDeviceRevocation({
        identity,
        deviceId: payload.deviceId,
        authorizationId: null,
        authorization: null,
        payload,
        revokedBy: 'root',
      });
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
      migrateSchema(this.ctx);
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

  async #verifyAuthorization(
    identity: StoredIdentityRow,
    authorization: DeviceAuthorizationV2,
  ): Promise<
    RegistryResult<{
      authorizationId: NexusDeviceAuthorizationIdV2;
      deviceId: NexusDeviceIdV2;
    }>
  > {
    const payload = authorization.payload;
    const genesisHash = encodeBase64Url(new Uint8Array(identity.genesis_hash));
    const signingPublicKey = decodeBase64UrlExact(payload.signingKey.publicKey, 32);
    if (
      payload.subject !== identity.subject ||
      payload.genesisHash !== genesisHash ||
      constantTimeEqual(signingPublicKey, new Uint8Array(identity.signing_public_key))
    ) {
      return fail('BAD_REQUEST');
    }
    const deviceId = await deriveDeviceIdV2({
      subject: identity.subject,
      signingKey: payload.signingKey,
    });
    const authorizationId = await deriveDeviceAuthorizationIdV2(payload);
    if (payload.deviceId !== deviceId) return fail('BAD_REQUEST');
    const rootKey = await getDefaultCryptoProvider().importEd25519PublicKey(
      new Uint8Array(identity.signing_public_key),
    );
    if (!(await verifyProtocolPayload(payload, authorization.rootSignature, rootKey))) {
      return fail('INVALID_SIGNATURE');
    }
    return succeed({ authorizationId, deviceId });
  }

  async #verifyDeviceSignature(
    authorization: DeviceAuthorizationV2,
    payload: { readonly protocol: string },
    signature: string,
  ): Promise<boolean> {
    const publicKey = await getDefaultCryptoProvider().importEd25519PublicKey(
      decodeBase64UrlExact(authorization.payload.signingKey.publicKey, 32),
    );
    return await verifyProtocolPayload(payload, signature, publicKey);
  }

  async #commitDeviceRevocation(input: {
    identity: StoredIdentityRow;
    deviceId: NexusDeviceIdV2;
    authorizationId: NexusDeviceAuthorizationIdV2 | null;
    authorization: DeviceAuthorizationV2 | null;
    payload: DeviceOperationPayloadV2;
    revokedBy: 'root' | 'device';
  }): Promise<RegistryResult<DeviceRegistryMutationV2>> {
    const existing = this.#readDevice(input.deviceId);
    if (existing?.state === 'revoked') {
      if (existing.revocation_event_id === null) throw new Error('Revoked device lacks event.');
      this.#kickOutbox();
      return succeed(
        this.#deviceMutationFromEvent(input.identity, existing, existing.revocation_event_id),
      );
    }
    if (
      input.revokedBy === 'device' &&
      existing !== null &&
      existing.authorization_id !== input.authorizationId
    ) {
      return fail('DEVICE_AUTHORIZATION_CONFLICT');
    }

    const operationId = await deriveDeviceOperationIdV2(input.payload);
    const previous = this.#readDeviceOperation(operationId);
    if (previous !== null) {
      const row = this.#readDevice(input.deviceId);
      if (row === null) throw new Error('Device operation target is missing.');
      return succeed(this.#deviceMutationFromEvent(input.identity, row, previous.event_id));
    }

    const acceptedAt = nowSeconds();
    const nextSequence = this.#readDeviceLedgerSequence() + 1;
    const effectiveAuthorizationId =
      (existing?.authorization_id as NexusDeviceAuthorizationIdV2 | null | undefined) ??
      input.authorizationId;
    const expiresAt =
      existing?.authorization_expires_at ?? input.authorization?.payload.expiresAt ?? null;
    const actionHash = await signedDeviceActionHash(input.payload);
    const materialized = await materializeDeviceRegistryEvent({
      protocol: 'nexus.device-registry-event.v2',
      operationId,
      eventType: 'revoked',
      subject: input.identity.subject as NexusSubject,
      genesisHash: encodeBase64Url(new Uint8Array(input.identity.genesis_hash)) as Base64Url32,
      identitySequence: input.identity.sequence,
      identityState: 'active',
      deviceLedgerSequence: nextSequence,
      deviceId: input.deviceId,
      ...(effectiveAuthorizationId === null ? {} : { authorizationId: effectiveAuthorizationId }),
      deviceState: 'revoked',
      ...(expiresAt === null ? {} : { authorizationExpiresAt: expiresAt }),
      acceptedAt,
      actionHash,
      revokedBy: input.revokedBy,
    });

    const result = this.ctx.storage.transactionSync<RegistryResult<DeviceRegistryMutationV2>>(
      () => {
        const identity = this.#readIdentity();
        if (identity === null) return fail('IDENTITY_NOT_FOUND');
        if (identity.state === 'revoked') return fail('IDENTITY_REVOKED');
        const current = this.#readDevice(input.deviceId);
        if (current?.state === 'revoked') {
          if (current.revocation_event_id === null) throw new Error('Revoked device lacks event.');
          return succeed(
            this.#deviceMutationFromEvent(identity, current, current.revocation_event_id),
          );
        }
        if (
          input.revokedBy === 'device' &&
          current !== null &&
          current.authorization_id !== input.authorizationId
        )
          return fail('DEVICE_AUTHORIZATION_CONFLICT');
        if (this.#readDeviceLedgerSequence() + 1 !== nextSequence) return fail('SEQUENCE_CONFLICT');

        if (current === null) {
          this.ctx.storage.sql.exec(
            `INSERT INTO device_state (
             device_id, authorization_id, authorization_jcs, signing_public_key, state,
             authorization_expires_at, activated_at, revoked_at, revoked_by,
             activation_event_id, revocation_event_id
           ) VALUES (?, ?, ?, ?, 'revoked', ?, NULL, ?, ?, NULL, ?)`,
            input.deviceId,
            input.authorizationId,
            input.authorization === null ? null : canonicalize(input.authorization),
            input.authorization === null
              ? null
              : copyBuffer(
                  decodeBase64UrlExact(input.authorization.payload.signingKey.publicKey, 32),
                ),
            expiresAt,
            acceptedAt,
            input.revokedBy,
            materialized.event.eventId,
          );
        } else {
          this.ctx.storage.sql.exec(
            `UPDATE device_state
              SET state = 'revoked', revoked_at = ?, revoked_by = ?, revocation_event_id = ?
            WHERE device_id = ? AND state = 'active'`,
            acceptedAt,
            input.revokedBy,
            materialized.event.eventId,
            input.deviceId,
          );
        }
        this.#writeDeviceLedgerSequence(nextSequence);
        this.#insertDeviceOperationAndOutbox(
          operationId,
          input.revokedBy === 'root' ? 'revoke-root' : 'revoke-self',
          input.deviceId,
          effectiveAuthorizationId,
          materialized.event.eventId,
          materialized.eventHash,
          acceptedAt,
          materialized.payloadJcs,
        );
        const revoked = this.#readDevice(input.deviceId);
        if (revoked === null) throw new Error('Revoked device was not persisted.');
        return succeed(
          this.#deviceMutationFromEvent(identity, revoked, materialized.event.eventId),
        );
      },
    );
    this.#kickOutbox();
    return result;
  }

  #readDevice(deviceId: string): StoredDeviceRow | null {
    if (!this.#hasDeviceSchema()) return null;
    return (
      this.ctx.storage.sql
        .exec<StoredDeviceRow>('SELECT * FROM device_state WHERE device_id = ?', deviceId)
        .toArray()[0] ?? null
    );
  }

  #readDeviceOperation(operationId: string): { event_id: string } | null {
    if (!this.#hasDeviceSchema()) return null;
    return (
      this.ctx.storage.sql
        .exec<{ event_id: string }>(
          'SELECT event_id FROM device_operations WHERE operation_id = ?',
          operationId,
        )
        .toArray()[0] ?? null
    );
  }

  #readDeviceLedgerSequence(): number {
    return this.ctx.storage.sql
      .exec<DeviceLedgerRow>('SELECT sequence FROM device_ledger WHERE singleton = 1')
      .one().sequence;
  }

  #writeDeviceLedgerSequence(sequence: number): void {
    this.ctx.storage.sql.exec(
      'UPDATE device_ledger SET sequence = ? WHERE singleton = 1',
      sequence,
    );
  }

  #hasDeviceSchema(): boolean {
    return (
      this.ctx.storage.sql
        .exec<{ present: number }>(
          `SELECT COUNT(*) AS present FROM sqlite_master WHERE type = 'table' AND name = 'device_state'`,
        )
        .one().present === 1
    );
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

  #deviceStatusFromRow(
    identity: StoredIdentityRow,
    row: StoredDeviceRow | null,
    deviceId: NexusDeviceIdV2,
    authorizationId: NexusDeviceAuthorizationIdV2,
  ): AuthoritativeDeviceStatusV2 {
    const authorizationMatches = row?.authorization_id === authorizationId;
    const state =
      identity.state === 'revoked'
        ? 'revoked'
        : row?.state === 'revoked'
          ? 'revoked'
          : row === null || !authorizationMatches
            ? 'unknown'
            : row.authorization_expires_at !== null && nowSeconds() >= row.authorization_expires_at
              ? 'expired'
              : 'active';
    return {
      subject: identity.subject as NexusSubject,
      genesisHash: encodeBase64Url(new Uint8Array(identity.genesis_hash)) as Base64Url32,
      identityState: identity.state,
      identitySequence: identity.sequence,
      deviceLedgerSequence: this.#readDeviceLedgerSequence(),
      deviceId,
      authorizationId,
      deviceState: state,
      activatedAt: authorizationMatches ? (row?.activated_at ?? null) : null,
      revokedAt:
        identity.state === 'revoked'
          ? identity.revoked_at
          : row?.state === 'revoked'
            ? (row?.revoked_at ?? null)
            : null,
      authorizationExpiresAt: authorizationMatches ? (row?.authorization_expires_at ?? null) : null,
    };
  }

  #deviceEvent(eventId: string): DeviceRegistryEventV2 {
    const row = this.ctx.storage.sql
      .exec<EventPayloadRow>('SELECT payload_jcs FROM device_outbox WHERE event_id = ?', eventId)
      .toArray()[0];
    if (row === undefined) throw new Error('Device event is missing.');
    return deviceRegistryEventV2Schema.parse(JSON.parse(row.payload_jcs));
  }

  #deviceMutationFromEvent(
    identity: StoredIdentityRow,
    row: StoredDeviceRow,
    eventId: string,
  ): DeviceRegistryMutationV2 {
    const event = this.#deviceEvent(eventId);
    return {
      subject: identity.subject as NexusSubject,
      genesisHash: encodeBase64Url(new Uint8Array(identity.genesis_hash)) as Base64Url32,
      identityState: event.identityState,
      identitySequence: event.identitySequence,
      deviceLedgerSequence: event.deviceLedgerSequence,
      deviceId: event.deviceId,
      authorizationId: event.authorizationId ?? null,
      deviceState: event.deviceState,
      activatedAt: event.eventType === 'activated' ? event.acceptedAt : row.activated_at,
      revokedAt: event.eventType === 'revoked' ? event.acceptedAt : null,
      authorizationExpiresAt: event.authorizationExpiresAt ?? null,
      operationId: event.operationId,
      eventId: event.eventId,
      eventType: event.eventType,
      acceptedAt: event.acceptedAt,
      event,
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

  #insertDeviceOperationAndOutbox(
    operationId: NexusDeviceOperationIdV2,
    operationType: 'activate' | 'revoke-root' | 'revoke-self',
    deviceId: NexusDeviceIdV2,
    authorizationId: NexusDeviceAuthorizationIdV2 | null,
    eventId: string,
    eventHash: Uint8Array,
    acceptedAt: number,
    payloadJcs: string,
  ): void {
    this.ctx.storage.sql.exec(
      `INSERT INTO device_operations (
         operation_id, event_id, operation_type, device_id, authorization_id, event_hash, accepted_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      operationId,
      eventId,
      operationType,
      deviceId,
      authorizationId,
      copyBuffer(eventHash),
      acceptedAt,
    );
    this.ctx.storage.sql.exec(
      `INSERT INTO device_outbox (event_id, payload_jcs, created_at, published_at, attempt_count)
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
        .exec<PendingOutboxRow>(
          `SELECT kind, event_id, payload_jcs, created_at, published_at, attempt_count
             FROM (
               SELECT 'identity' AS kind, event_id, payload_jcs, created_at, published_at, attempt_count
                 FROM outbox
                WHERE published_at IS NULL
               UNION ALL
               SELECT 'device' AS kind, event_id, payload_jcs, created_at, published_at, attempt_count
                 FROM device_outbox
                WHERE published_at IS NULL
             )
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
            `SELECT
               (SELECT COUNT(*) FROM outbox WHERE published_at IS NULL) +
               (SELECT COUNT(*) FROM device_outbox WHERE published_at IS NULL) AS pending`,
          )
          .one().pending;
        if (remaining === 0) {
          return;
        }
        await this.#ensureAlarm(Date.now() + BASE_RETRY_DELAY_MS);
        continue;
      }

      const attempt = this.ctx.storage.transactionSync<number>(() => {
        const table = pending.kind === 'identity' ? 'outbox' : 'device_outbox';
        this.ctx.storage.sql.exec(
          `UPDATE ${table} SET attempt_count = attempt_count + 1 WHERE event_id = ?`,
          pending.event_id,
        );
        return this.ctx.storage.sql
          .exec<{ attempt_count: number }>(
            `SELECT attempt_count FROM ${table} WHERE event_id = ?`,
            pending.event_id,
          )
          .one().attempt_count;
      });

      try {
        if (pending.kind === 'identity') {
          await this.env.REGISTRY_EVENTS.send(
            registryEventV1Schema.parse(JSON.parse(pending.payload_jcs)),
          );
        } else {
          await this.env.REGISTRY_DEVICE_EVENTS.send(
            deviceRegistryEventV2Schema.parse(JSON.parse(pending.payload_jcs)),
          );
        }
      } catch {
        const exponent = Math.min(attempt - 1, 20);
        const delay = Math.min(MAX_RETRY_DELAY_MS, BASE_RETRY_DELAY_MS * 2 ** exponent);
        await this.ctx.storage.setAlarm(Date.now() + delay);
        return;
      }

      // A crash after send and before this write can duplicate the queue event;
      // this is intentional at-least-once behavior and eventId is stable.
      this.ctx.storage.transactionSync(() => {
        const table = pending.kind === 'identity' ? 'outbox' : 'device_outbox';
        this.ctx.storage.sql.exec(
          `UPDATE ${table}
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
