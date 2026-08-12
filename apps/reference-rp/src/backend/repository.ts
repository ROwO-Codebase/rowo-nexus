import type {
  Base64Url32,
  NexusDeviceAuthorizationIdV2,
  NexusDeviceIdV2,
  NexusSubject,
  VerificationExpectation,
  VerificationExpectationV2,
} from '@nexus/protocol';
import {
  OWNERSHIP_PROOF_PROTOCOL_V1,
  OWNERSHIP_PROOF_PROTOCOL_V2,
  audienceOriginSchema,
  ownershipProofV1Schema,
  ownershipProofV2Schema,
} from '@nexus/protocol';
import { verifyRpOperation, verifyRpOperationV2 } from '@nexus/verifier';
import type { DeviceLifecycleProvider, LifecycleProvider } from '@nexus/verifier';

import type {
  ApplicationReceipt,
  AcceptedProofProtocol,
  AcceptedProofProtocols,
  AuthorizationMethod,
  IssuedChallenge,
  NoteDraft,
  NoteView,
  ReplyView,
  SessionOperationInput,
  SessionOperationResult,
  SessionStartResult,
  SessionStatus,
  StartSessionOperation,
  SubmitProofInput,
} from '../shared/contracts.js';
import { HashOnlyChallengeStore, asNonce } from './challenges.js';
import { canonicalSha256, constantTimeTextEqual, secureToken, sha256Base64Url } from './digests.js';
import { RpError } from './errors.js';

const CHALLENGE_TTL_SECONDS = 60;
const SESSION_TTL_SECONDS = 5 * 60;
const MAX_CLOCK_SKEW_SECONDS = 30;
const SESSION_RESOURCE = 'urn:rowo:nexus-notes:session';
const SESSION_POLICY = Object.freeze({
  actions: [
    'note.create',
    'note.edit',
    'note.delete',
    'reply.create',
    'reply.delete',
    'note.like',
    'note.unlike',
    'profile.set-name',
  ],
  resourcePolicy: 'public-notes-and-private-notes-owned-by-session-subject',
  ttlSeconds: SESSION_TTL_SECONDS,
});
const ACCEPTED_PROOF_PROTOCOLS: AcceptedProofProtocols = Object.freeze([
  OWNERSHIP_PROOF_PROTOCOL_V2,
  OWNERSHIP_PROOF_PROTOCOL_V1,
]);

interface StoredNote {
  readonly id: string;
  readonly resource: string;
  readonly authorSubject: NexusSubject;
  readonly createdAt: number;
  readonly title: string;
  readonly body: string;
  readonly visibility: 'public' | 'private';
  readonly updatedAt: number;
  readonly version: number;
  readonly acceptedProofHash: string;
  readonly authorization: AuthorizationMethod;
}

interface StoredReply {
  readonly id: string;
  readonly noteId: string;
  readonly authorSubject: NexusSubject;
  readonly body: string;
  readonly createdAt: number;
}

interface StoredSession {
  readonly tokenHash: string;
  readonly subject: NexusSubject;
  readonly expiresAt: number;
  readonly proofHash: string;
  readonly proofProtocol?: AcceptedProofProtocol;
  readonly deviceId?: NexusDeviceIdV2;
  readonly authorizationId?: NexusDeviceAuthorizationIdV2;
}

interface StoredProfile {
  readonly subject: NexusSubject;
  readonly friendlyName: string;
  readonly nameKey: string;
  readonly updatedAt: number;
}

interface ActiveSession {
  readonly stored: StoredSession;
  readonly status: SessionStatus;
}

export interface StartedLocalSession {
  readonly token: string;
  readonly result: SessionStartResult;
}

export interface ReferenceRpRepositoryOptions {
  audience: string;
  lifecycle: LifecycleProvider;
  deviceLifecycle?: DeviceLifecycleProvider;
  now?: () => number;
  seed?: boolean;
}

export class ReferenceRpRepository {
  public readonly lifecycle: LifecycleProvider;
  public readonly deviceLifecycle: DeviceLifecycleProvider | undefined;
  public readonly challenges = new HashOnlyChallengeStore();

  readonly #audience: string;
  readonly #now: () => number;
  readonly #notes = new Map<string, StoredNote>();
  readonly #replies = new Map<string, StoredReply>();
  readonly #likes = new Map<string, Map<NexusSubject, number>>();
  readonly #receipts = new Map<string, ApplicationReceipt>();
  readonly #sessions = new Map<string, StoredSession>();
  readonly #profiles = new Map<NexusSubject, StoredProfile>();
  #exclusive: Promise<void> = Promise.resolve();

  public constructor(options: ReferenceRpRepositoryOptions) {
    const audience = audienceOriginSchema.safeParse(options.audience);
    if (!audience.success) {
      throw new TypeError('Reference RP audience must be one exact HTTPS origin.');
    }
    this.#audience = audience.data;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.lifecycle = options.lifecycle;
    this.deviceLifecycle = options.deviceLifecycle;
    if (options.seed !== false) this.#seedNotes();
  }

  public async listNotes(token?: string): Promise<NoteView[]> {
    const subject = await this.#optionalSubject(token);
    return [...this.#notes.values()]
      .filter((note) => note.visibility === 'public' || note.authorSubject === subject)
      .sort((left, right) => right.updatedAt - left.updatedAt)
      .map((note) => this.#toNoteView(note, subject));
  }

  public async getNote(id: string, token?: string): Promise<NoteView> {
    const subject = await this.#optionalSubject(token);
    return this.#toNoteView(this.#requireVisibleNote(id, subject), subject);
  }

  public issueChallenge(value: unknown): IssuedChallenge {
    const operation = parseStartSessionOperation(value);
    const now = this.#now();
    const contextHash = canonicalSha256({
      action: operation.action,
      policy: SESSION_POLICY,
      acceptedProofProtocols: ACCEPTED_PROOF_PROTOCOLS,
    });
    const challenge: IssuedChallenge = {
      challengeId: secureToken(16),
      action: operation.action,
      resource: SESSION_RESOURCE,
      nonce: asNonce(secureToken(32)),
      expiresAt: now + CHALLENGE_TTL_SECONDS,
      contextHash: contextHash as Base64Url32,
      acceptedProofProtocols: ACCEPTED_PROOF_PROTOCOLS,
    };
    this.challenges.insert(challenge);
    return challenge;
  }

  public startSession(value: unknown): Promise<StartedLocalSession> {
    const input = parseSubmitProof(value);
    return this.#runExclusive(async () => this.#verifyAndStartSession(input));
  }

  public executeSessionOperation(value: unknown, token: string): Promise<SessionOperationResult> {
    const operation = parseSessionOperation(value);
    return this.#runExclusive(async () => {
      const session = await this.#activeSession(token);
      return this.#mutateWithSession(operation, session);
    });
  }

  public async getSession(token: string): Promise<SessionStatus> {
    return (await this.#activeSession(token)).status;
  }

  public endSession(token: string): void {
    if (token.length < 20) return;
    this.#sessions.delete(sha256Base64Url(token));
  }

  public debugSnapshot(): {
    notes: readonly Readonly<StoredNote>[];
    replies: readonly Readonly<StoredReply>[];
    likes: readonly { readonly noteId: string; readonly subject: NexusSubject }[];
    receipts: readonly Readonly<ApplicationReceipt>[];
    sessions: readonly Readonly<StoredSession>[];
    profiles: readonly Readonly<StoredProfile>[];
    challenges: ReturnType<HashOnlyChallengeStore['debugSnapshot']>;
  } {
    return {
      notes: [...this.#notes.values()].map((note) => ({ ...note })),
      replies: [...this.#replies.values()].map((reply) => ({ ...reply })),
      likes: [...this.#likes.entries()].flatMap(([noteId, likes]) =>
        [...likes.keys()].map((subject) => ({ noteId, subject })),
      ),
      receipts: [...this.#receipts.values()].map((receipt) => ({ ...receipt })),
      sessions: [...this.#sessions.values()].map((session) => ({ ...session })),
      profiles: [...this.#profiles.values()].map((profile) => ({ ...profile })),
      challenges: this.challenges.debugSnapshot(),
    };
  }

  async #verifyAndStartSession(input: SubmitProofInput): Promise<StartedLocalSession> {
    const challenge = this.challenges.getById(input.challengeId);
    if (challenge === null || challenge.consumedAt !== null || challenge.expiresAt <= this.#now()) {
      throw new RpError(
        'CHALLENGE_EXPIRED',
        'This proof challenge has expired or was already used.',
        409,
      );
    }

    const acceptedProofProtocols = challenge.acceptedProofProtocols;
    const contextHash = canonicalSha256({
      action: input.operation.action,
      policy: SESSION_POLICY,
      acceptedProofProtocols,
    });
    if (
      challenge.action !== input.operation.action ||
      challenge.resource !== SESSION_RESOURCE ||
      !constantTimeTextEqual(challenge.contextHash, contextHash)
    ) {
      throw new RpError('CHALLENGE_MISMATCH', 'The session policy has changed.', 409);
    }
    if (!acceptedProofProtocols.includes(input.proofProtocol)) {
      throw new RpError(
        'UNSUPPORTED_PROOF_PROTOCOL',
        'This challenge did not authorize the submitted proof protocol.',
        403,
      );
    }
    const payload = input.proof.payload;
    if (
      sha256Base64Url(payload.nonce) !== challenge.nonceHash ||
      payload.contextHash === undefined ||
      !constantTimeTextEqual(payload.contextHash, challenge.contextHash)
    ) {
      throw new RpError(
        'CHALLENGE_MISMATCH',
        'The proof is not bound to this exact Notes session.',
        403,
      );
    }

    const expected: VerificationExpectation = {
      audience: this.#audience,
      action: challenge.action,
      resource: challenge.resource,
      nonce: payload.nonce,
      now: this.#now(),
      maxClockSkewSeconds: MAX_CLOCK_SKEW_SECONDS,
    };
    let subject: NexusSubject;
    let deviceBinding:
      | {
          proofProtocol: typeof OWNERSHIP_PROOF_PROTOCOL_V2;
          deviceId: NexusDeviceIdV2;
          authorizationId: NexusDeviceAuthorizationIdV2;
        }
      | undefined;
    if (input.proofProtocol === OWNERSHIP_PROOF_PROTOCOL_V2) {
      const expectedV2: VerificationExpectationV2 = {
        ...expected,
        contextHash: challenge.contextHash as Base64Url32,
      };
      const verified = await verifyRpOperationV2(
        input.proof,
        expectedV2,
        this.challenges,
        this.lifecycle,
        this.#requireDeviceLifecycle(),
      );
      subject = verified.subject;
      deviceBinding = {
        proofProtocol: OWNERSHIP_PROOF_PROTOCOL_V2,
        deviceId: verified.deviceId,
        authorizationId: verified.authorizationId,
      };
    } else {
      const verified = await verifyRpOperation(
        input.proof,
        expected,
        this.challenges,
        this.lifecycle,
      );
      subject = verified.subject;
    }
    const proofHash = canonicalSha256(input.proof);
    const token = secureToken(32);
    const stored: StoredSession = {
      tokenHash: sha256Base64Url(token),
      subject,
      expiresAt: this.#now() + SESSION_TTL_SECONDS,
      proofHash,
      ...(deviceBinding ?? {}),
    };
    this.#sessions.set(stored.tokenHash, stored);
    const lifecycle = await this.lifecycle.getAuthoritativeStatus(subject);
    if (lifecycle.state !== 'active') {
      this.#sessions.delete(stored.tokenHash);
      throw new RpError('SESSION_INVALID', 'The identity is no longer active.', 401);
    }
    const receipt = this.#recordReceipt({
      operation: 'session.start',
      resource: SESSION_RESOURCE,
      subject,
      authorization: 'wallet-proof',
      proofHash,
      resultingVersion: null,
    });
    return {
      token,
      result: {
        receipt,
        session: {
          subject,
          friendlyName: this.#profiles.get(subject)?.friendlyName ?? null,
          state: 'active',
          sequence: lifecycle.sequence,
          expiresAt: stored.expiresAt,
          checkedAt: this.#now(),
          ...(stored.proofProtocol === OWNERSHIP_PROOF_PROTOCOL_V2
            ? {
                proofProtocol: stored.proofProtocol,
                deviceId: stored.deviceId,
                authorizationId: stored.authorizationId,
              }
            : {}),
        },
      },
    };
  }

  async #activeSession(token: string): Promise<ActiveSession> {
    if (token.length < 20) {
      throw new RpError('SESSION_INVALID', 'The RP session is missing or invalid.', 401);
    }
    const stored = this.#sessions.get(sha256Base64Url(token));
    const now = this.#now();
    if (stored === undefined || stored.expiresAt <= now) {
      throw new RpError('SESSION_INVALID', 'The RP session has expired.', 401);
    }
    const lifecycle = await this.lifecycle.getAuthoritativeStatus(stored.subject);
    if (lifecycle.state !== 'active') {
      throw new RpError('SESSION_INVALID', 'The identity is no longer active.', 401);
    }
    if (
      stored.proofProtocol === OWNERSHIP_PROOF_PROTOCOL_V2 &&
      stored.deviceId !== undefined &&
      stored.authorizationId !== undefined
    ) {
      const device = await this.#requireDeviceLifecycle().getAuthoritativeDeviceStatus(
        stored.subject,
        stored.deviceId,
        stored.authorizationId,
      );
      if (
        device.state !== 'active' ||
        device.identityState !== 'active' ||
        (device.authorizationExpiresAt !== undefined && now >= device.authorizationExpiresAt)
      ) {
        throw new RpError('SESSION_INVALID', 'The Nexus device is no longer active.', 401);
      }
    }
    return {
      stored,
      status: {
        subject: stored.subject,
        friendlyName: this.#profiles.get(stored.subject)?.friendlyName ?? null,
        state: 'active',
        sequence: lifecycle.sequence,
        expiresAt: stored.expiresAt,
        checkedAt: now,
        ...(stored.proofProtocol === OWNERSHIP_PROOF_PROTOCOL_V2
          ? {
              proofProtocol: stored.proofProtocol,
              deviceId: stored.deviceId,
              authorizationId: stored.authorizationId,
            }
          : {}),
      },
    };
  }

  #requireDeviceLifecycle(): DeviceLifecycleProvider {
    if (this.deviceLifecycle === undefined) {
      throw new RpError(
        'SERVICE_UNAVAILABLE',
        'Authoritative Nexus device status is unavailable.',
        503,
      );
    }
    return this.deviceLifecycle;
  }

  async #optionalSubject(token?: string): Promise<NexusSubject | undefined> {
    if (token === undefined || token.length === 0) return undefined;
    try {
      return (await this.#activeSession(token)).status.subject;
    } catch {
      return undefined;
    }
  }

  #mutateWithSession(
    operation: SessionOperationInput,
    session: ActiveSession,
  ): SessionOperationResult {
    const subject = session.status.subject;
    const now = this.#now();
    let note: StoredNote | null;
    let resource: string;
    let resultingVersion: number | null;

    if (operation.action === 'profile.set-name') {
      const nameKey = friendlyNameKey(operation.friendlyName);
      const claimed = [...this.#profiles.values()].find((profile) => profile.nameKey === nameKey);
      if (claimed !== undefined && claimed.subject !== subject) {
        throw new RpError('NAME_TAKEN', 'That friendly name is already in use.', 409);
      }
      this.#profiles.set(
        subject,
        Object.freeze({
          subject,
          friendlyName: operation.friendlyName,
          nameKey,
          updatedAt: now,
        }),
      );
      resource = `profile:${subject}`;
      note = null;
      resultingVersion = null;
    } else if (operation.action === 'note.create') {
      const id = `nt_${secureToken(9)}`;
      resource = `note:${id}`;
      note = Object.freeze({
        id,
        resource,
        authorSubject: subject,
        title: operation.draft.title,
        body: operation.draft.body,
        visibility: operation.draft.visibility,
        createdAt: now,
        updatedAt: now,
        version: 1,
        acceptedProofHash: session.stored.proofHash,
        authorization: 'rp-session',
      });
      this.#notes.set(id, note);
      resultingVersion = 1;
    } else if (operation.action === 'note.edit' || operation.action === 'note.delete') {
      const current = this.#requireOwnedNote(operation.noteId, subject);
      if (current.version !== operation.expectedVersion) {
        throw new RpError(
          'VERSION_CONFLICT',
          'The note was updated in another view. Refresh and try again.',
          409,
        );
      }
      resource = current.resource;
      if (operation.action === 'note.delete') {
        this.#notes.delete(current.id);
        for (const [id, reply] of this.#replies) {
          if (reply.noteId === current.id) this.#replies.delete(id);
        }
        this.#likes.delete(current.id);
        note = null;
        resultingVersion = null;
      } else {
        note = Object.freeze({
          ...current,
          title: operation.draft.title,
          body: operation.draft.body,
          visibility: operation.draft.visibility,
          updatedAt: now,
          version: current.version + 1,
          acceptedProofHash: session.stored.proofHash,
          authorization: 'rp-session',
        });
        this.#notes.set(note.id, note);
        resultingVersion = note.version;
      }
    } else if (operation.action === 'reply.create') {
      const current = this.#requireVisibleNote(operation.noteId, subject);
      const reply: StoredReply = Object.freeze({
        id: `rpy_${secureToken(12)}`,
        noteId: current.id,
        authorSubject: subject,
        body: operation.body,
        createdAt: now,
      });
      this.#replies.set(reply.id, reply);
      resource = `${current.resource}#reply:${reply.id}`;
      note = current;
      resultingVersion = current.version;
    } else if (operation.action === 'reply.delete') {
      const current = this.#requireVisibleNote(operation.noteId, subject);
      const reply = this.#replies.get(operation.replyId);
      if (reply === undefined || reply.noteId !== current.id) {
        throw new RpError('NOT_FOUND', 'The requested reply does not exist.', 404);
      }
      if (reply.authorSubject !== subject && current.authorSubject !== subject) {
        throw new RpError(
          'AUTHOR_MISMATCH',
          'Only the reply author or note author can remove this reply.',
          403,
        );
      }
      this.#replies.delete(reply.id);
      resource = `${current.resource}#reply:${reply.id}`;
      note = current;
      resultingVersion = current.version;
    } else {
      const current = this.#requireNote(operation.noteId);
      if (current.visibility !== 'public') {
        throw new RpError('OPERATION_NOT_ALLOWED', 'Private notes cannot be liked.', 403);
      }
      const likes = this.#likes.get(current.id) ?? new Map<NexusSubject, number>();
      if (operation.action === 'note.like') likes.set(subject, now);
      else likes.delete(subject);
      this.#likes.set(current.id, likes);
      resource = current.resource;
      note = current;
      resultingVersion = current.version;
    }

    const receipt = this.#recordReceipt({
      operation: operation.action,
      resource,
      subject,
      authorization: 'rp-session',
      proofHash: session.stored.proofHash,
      resultingVersion,
    });
    return {
      note: note === null ? null : this.#toNoteView(note, subject),
      receipt,
      ...(operation.action === 'profile.set-name'
        ? {
            session: {
              ...session.status,
              friendlyName: operation.friendlyName,
              checkedAt: now,
            },
          }
        : {}),
    };
  }

  #recordReceipt(input: Omit<ApplicationReceipt, 'acceptedAt' | 'receiptId'>): ApplicationReceipt {
    const acceptedAt = this.#now();
    const receiptId = `rpr_${secureToken(18)}`;
    const receipt = Object.freeze({ ...input, acceptedAt, receiptId });
    this.#receipts.set(receiptId, receipt);
    return receipt;
  }

  #requireNote(id: string): StoredNote {
    const note = this.#notes.get(id);
    if (note === undefined) {
      throw new RpError('NOT_FOUND', 'The requested note does not exist.', 404);
    }
    return note;
  }

  #requireOwnedNote(id: string, subject: NexusSubject): StoredNote {
    const note = this.#requireNote(id);
    if (note.authorSubject !== subject) {
      throw new RpError('AUTHOR_MISMATCH', 'This session did not create the note.', 403);
    }
    return note;
  }

  #requireVisibleNote(id: string, subject?: NexusSubject): StoredNote {
    const note = this.#requireNote(id);
    if (note.visibility === 'private' && note.authorSubject !== subject) {
      throw new RpError('NOT_FOUND', 'The requested note does not exist.', 404);
    }
    return note;
  }

  #toNoteView(note: StoredNote, viewer?: NexusSubject): NoteView {
    const replies = [...this.#replies.values()]
      .filter((reply) => reply.noteId === note.id)
      .sort((left, right) => left.createdAt - right.createdAt)
      .map((reply) => this.#toReplyView(reply));
    const likes = this.#likes.get(note.id);
    return {
      id: note.id,
      resource: note.resource,
      authorSubject: note.authorSubject,
      authorFriendlyName: this.#profiles.get(note.authorSubject)?.friendlyName ?? null,
      title: note.title,
      body: note.body,
      visibility: note.visibility,
      createdAt: note.createdAt,
      updatedAt: note.updatedAt,
      version: note.version,
      authorization: note.authorization,
      proofFingerprint: note.acceptedProofHash.slice(0, 12),
      likeCount: likes?.size ?? 0,
      likedByViewer: viewer !== undefined && (likes?.has(viewer) ?? false),
      replies,
    };
  }

  #toReplyView(reply: StoredReply): ReplyView {
    return {
      id: reply.id,
      noteId: reply.noteId,
      authorSubject: reply.authorSubject,
      authorFriendlyName: this.#profiles.get(reply.authorSubject)?.friendlyName ?? null,
      body: reply.body,
      createdAt: reply.createdAt,
    };
  }

  #runExclusive<T>(work: () => Promise<T>): Promise<T> {
    const result = this.#exclusive.then(work, work);
    this.#exclusive = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  #seedNotes(): void {
    const rows = [
      {
        id: 'nt_field-notes',
        title: 'Lanterns after the rain',
        body: 'The path behind the old library is quiet again. Someone left three paper lanterns under the cedar, each with a tiny constellation drawn inside.',
        age: 1_420,
        author: 'field-observer',
      },
      {
        id: 'nt_small-things',
        title: 'A list of small things worth keeping',
        body: 'Warm tea before sunrise. A page with generous margins. The exact blue the sky becomes just before the streetlights switch off.',
        age: 8_740,
        author: 'paper-moon',
      },
      {
        id: 'nt_station-window',
        title: 'From the last train window',
        body: 'Every lit apartment became a one-second story. None of the people inside needed a name for the scene to feel complete.',
        age: 25_680,
        author: 'night-train',
      },
    ];
    for (const row of rows) {
      const timestamp = this.#now() - row.age;
      const proofHash = sha256Base64Url(`seed-proof:${row.id}`);
      const note: StoredNote = Object.freeze({
        id: row.id,
        resource: `note:${row.id}`,
        authorSubject: seedSubject(row.author),
        title: row.title,
        body: row.body,
        visibility: 'public',
        createdAt: timestamp,
        updatedAt: timestamp,
        version: 1,
        acceptedProofHash: proofHash,
        authorization: 'wallet-proof',
      });
      this.#notes.set(note.id, note);
    }
  }
}

function parseSubmitProof(value: unknown): SubmitProofInput {
  if (!isRecord(value)) throw new RpError('BAD_REQUEST', 'Request body must be an object.', 400);
  const legacyV1 = !Object.hasOwn(value, 'proofProtocol');
  const record = requireRecord(
    value,
    legacyV1
      ? ['challengeId', 'operation', 'proof']
      : ['challengeId', 'operation', 'proof', 'proofProtocol'],
  );
  if (typeof record['challengeId'] !== 'string' || record['challengeId'].length < 20) {
    throw new RpError('BAD_REQUEST', 'challengeId is invalid.', 400);
  }
  const common = {
    challengeId: record['challengeId'],
    operation: parseStartSessionOperation(record['operation']),
  };
  if (record['proofProtocol'] === OWNERSHIP_PROOF_PROTOCOL_V1 || legacyV1) {
    const proof = ownershipProofV1Schema.safeParse(record['proof']);
    if (!proof.success) throw new RpError('BAD_REQUEST', 'proof is invalid.', 400);
    return { ...common, proofProtocol: OWNERSHIP_PROOF_PROTOCOL_V1, proof: proof.data };
  }
  if (record['proofProtocol'] === OWNERSHIP_PROOF_PROTOCOL_V2) {
    const proof = ownershipProofV2Schema.safeParse(record['proof']);
    if (!proof.success) throw new RpError('BAD_REQUEST', 'proof is invalid.', 400);
    return { ...common, proofProtocol: OWNERSHIP_PROOF_PROTOCOL_V2, proof: proof.data };
  }
  throw new RpError('BAD_REQUEST', 'proofProtocol is not supported.', 400);
}

function parseStartSessionOperation(value: unknown): StartSessionOperation {
  const record = requireRecord(value, ['action']);
  if (record['action'] !== 'session.start') {
    throw new RpError('BAD_REQUEST', 'Only an explicit session.start proof is accepted.', 400);
  }
  return { action: 'session.start' };
}

function parseSessionOperation(value: unknown): SessionOperationInput {
  if (!isRecord(value) || typeof value['action'] !== 'string') {
    throw new RpError('BAD_REQUEST', 'A note session action is required.', 400);
  }
  if (value['action'] === 'note.create') {
    const record = requireRecord(value, ['action', 'draft']);
    return { action: 'note.create', draft: parseDraft(record['draft']) };
  }
  if (value['action'] === 'note.edit') {
    const record = requireRecord(value, ['action', 'draft', 'expectedVersion', 'noteId']);
    return {
      action: 'note.edit',
      noteId: parseNoteId(record['noteId']),
      expectedVersion: parseVersion(record['expectedVersion']),
      draft: parseDraft(record['draft']),
    };
  }
  if (value['action'] === 'note.delete') {
    const record = requireRecord(value, ['action', 'expectedVersion', 'noteId']);
    return {
      action: 'note.delete',
      noteId: parseNoteId(record['noteId']),
      expectedVersion: parseVersion(record['expectedVersion']),
    };
  }
  if (value['action'] === 'reply.create') {
    const record = requireRecord(value, ['action', 'body', 'noteId']);
    return {
      action: 'reply.create',
      noteId: parseNoteId(record['noteId']),
      body: parseReplyBody(record['body']),
    };
  }
  if (value['action'] === 'reply.delete') {
    const record = requireRecord(value, ['action', 'noteId', 'replyId']);
    return {
      action: 'reply.delete',
      noteId: parseNoteId(record['noteId']),
      replyId: parseReplyId(record['replyId']),
    };
  }
  if (value['action'] === 'note.like' || value['action'] === 'note.unlike') {
    const record = requireRecord(value, ['action', 'noteId']);
    return { action: value['action'], noteId: parseNoteId(record['noteId']) };
  }
  if (value['action'] === 'profile.set-name') {
    const record = requireRecord(value, ['action', 'friendlyName']);
    return { action: 'profile.set-name', friendlyName: parseFriendlyName(record['friendlyName']) };
  }
  throw new RpError('BAD_REQUEST', 'The requested note session action is unsupported.', 400);
}

function parseFriendlyName(value: unknown): string {
  const name = typeof value === 'string' ? value.trim() : '';
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{2,23}$/u.test(name) || name.toLowerCase().startsWith('nx1_')) {
    throw new RpError(
      'BAD_REQUEST',
      'Friendly name must be 3–24 letters, numbers, underscores, or hyphens and cannot start with nx1_.',
      400,
    );
  }
  return name;
}

function parseDraft(value: unknown): NoteDraft {
  const record = requireRecord(value, ['body', 'title', 'visibility']);
  const title = typeof record['title'] === 'string' ? record['title'].trim() : '';
  const body = typeof record['body'] === 'string' ? record['body'].trim() : '';
  if (title.length < 1 || title.length > 80) {
    throw new RpError('BAD_REQUEST', 'Note title must be between 1 and 80 characters.', 400);
  }
  if (body.length < 1 || body.length > 4_000) {
    throw new RpError('BAD_REQUEST', 'Note body must be between 1 and 4,000 characters.', 400);
  }
  if (record['visibility'] !== 'public' && record['visibility'] !== 'private') {
    throw new RpError('BAD_REQUEST', 'visibility must be public or private.', 400);
  }
  return { title, body, visibility: record['visibility'] };
}

function parseReplyBody(value: unknown): string {
  const body = typeof value === 'string' ? value.trim() : '';
  if (body.length < 1 || body.length > 1_000) {
    throw new RpError('BAD_REQUEST', 'Reply body must be between 1 and 1,000 characters.', 400);
  }
  return body;
}

function parseNoteId(value: unknown): string {
  if (typeof value !== 'string' || !/^nt_[A-Za-z0-9_-]{3,80}$/u.test(value)) {
    throw new RpError('BAD_REQUEST', 'noteId is invalid.', 400);
  }
  return value;
}

function parseReplyId(value: unknown): string {
  if (typeof value !== 'string' || !/^rpy_[A-Za-z0-9_-]{12,80}$/u.test(value)) {
    throw new RpError('BAD_REQUEST', 'replyId is invalid.', 400);
  }
  return value;
}

function parseVersion(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new RpError('BAD_REQUEST', 'expectedVersion must be a positive integer.', 400);
  }
  return value as number;
}

function requireRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!isRecord(value)) throw new RpError('BAD_REQUEST', 'Request body must be an object.', 400);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new RpError('BAD_REQUEST', 'Request contains missing or unknown fields.', 400);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function seedSubject(label: string): NexusSubject {
  return `nx1_${sha256Base64Url(`seed-subject:${label}`)}`;
}

function friendlyNameKey(name: string): string {
  return name.toLowerCase();
}
