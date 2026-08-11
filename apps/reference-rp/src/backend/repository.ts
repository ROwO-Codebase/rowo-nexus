import type {
  Base64Url32,
  NexusSubject,
  OwnershipProofV1,
  VerificationExpectation,
} from '@nexus/protocol';
import { audienceOriginSchema } from '@nexus/protocol';
import { verifyRpOperation } from '@nexus/verifier';
import type { LifecycleProvider } from '@nexus/verifier';

import type {
  ApplicationReceipt,
  IssueChallengeInput,
  IssuedChallenge,
  NoteDraft,
  NoteView,
  OperationResult,
  RpSession,
  SessionStatus,
  SubmitOperationInput,
} from '../shared/contracts.js';
import { HashOnlyChallengeStore, asNonce } from './challenges.js';
import { canonicalSha256, constantTimeTextEqual, secureToken, sha256Base64Url } from './digests.js';
import { RpError } from './errors.js';

const CHALLENGE_TTL_SECONDS = 60;
const SESSION_TTL_SECONDS = 5 * 60;
const MAX_CLOCK_SKEW_SECONDS = 30;

interface StoredNote {
  readonly id: string;
  readonly resource: string;
  readonly authorSubject: NexusSubject;
  readonly createdAt: number;
  readonly title: string;
  readonly body: string;
  readonly updatedAt: number;
  readonly version: number;
  readonly acceptedProofHash: string;
}

interface StoredSession {
  tokenHash: string;
  subject: NexusSubject;
  expiresAt: number;
}

export interface ReferenceRpRepositoryOptions {
  audience: string;
  lifecycle: LifecycleProvider;
  now?: () => number;
  seed?: boolean;
}

export class ReferenceRpRepository {
  public readonly lifecycle: LifecycleProvider;
  public readonly challenges = new HashOnlyChallengeStore();

  readonly #audience: string;
  readonly #now: () => number;
  readonly #notes = new Map<string, StoredNote>();
  readonly #receipts = new Map<string, ApplicationReceipt>();
  readonly #sessions = new Map<string, StoredSession>();
  #exclusive: Promise<void> = Promise.resolve();

  public constructor(options: ReferenceRpRepositoryOptions) {
    const audience = audienceOriginSchema.safeParse(options.audience);
    if (!audience.success) {
      throw new TypeError('Reference RP audience must be one exact HTTPS origin.');
    }
    this.#audience = audience.data;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.lifecycle = options.lifecycle;
    if (options.seed !== false) this.#seedNotes();
  }

  public listNotes(): NoteView[] {
    return [...this.#notes.values()]
      .sort((left, right) => right.updatedAt - left.updatedAt)
      .map((note) => toNoteView(note));
  }

  public getNote(id: string): NoteView {
    return toNoteView(this.#requireNote(id));
  }

  public issueChallenge(value: unknown): IssuedChallenge {
    const operation = parseOperation(value);
    const now = this.#now();
    const { resource, contextHash } = this.#operationBinding(operation, true);
    const challenge: IssuedChallenge = {
      challengeId: secureToken(16),
      action: operation.action,
      resource,
      nonce: asNonce(secureToken(32)),
      expiresAt: now + CHALLENGE_TTL_SECONDS,
      contextHash: contextHash as Base64Url32,
    };
    this.challenges.insert(challenge);
    return challenge;
  }

  public submitOperation(value: unknown): Promise<OperationResult> {
    const input = parseSubmitOperation(value);
    return this.#runExclusive(async () => this.#authorizeAndMutate(input));
  }

  public async getSession(token: string): Promise<SessionStatus> {
    if (token.length < 20)
      throw new RpError('SESSION_INVALID', 'The RP session is missing or invalid.', 401);
    const session = this.#sessions.get(sha256Base64Url(token));
    const now = this.#now();
    if (session === undefined || session.expiresAt <= now) {
      throw new RpError('SESSION_INVALID', 'The RP session has expired.', 401);
    }

    const lifecycle = await this.lifecycle.getAuthoritativeStatus(session.subject);
    if (lifecycle.state === 'not-found') {
      throw new RpError('SESSION_INVALID', 'The identity is no longer registered.', 401);
    }
    return {
      subject: session.subject,
      state: lifecycle.state,
      sequence: lifecycle.sequence,
      expiresAt: session.expiresAt,
      checkedAt: now,
    };
  }

  public debugSnapshot(): {
    notes: readonly Readonly<StoredNote>[];
    receipts: readonly Readonly<ApplicationReceipt>[];
    sessions: readonly Readonly<StoredSession>[];
    challenges: ReturnType<HashOnlyChallengeStore['debugSnapshot']>;
  } {
    return {
      notes: [...this.#notes.values()].map((note) => ({ ...note })),
      receipts: [...this.#receipts.values()].map((receipt) => ({ ...receipt })),
      sessions: [...this.#sessions.values()].map((session) => ({ ...session })),
      challenges: this.challenges.debugSnapshot(),
    };
  }

  async #authorizeAndMutate(input: SubmitOperationInput): Promise<OperationResult> {
    const challenge = this.challenges.getById(input.challengeId);
    if (challenge === null || challenge.consumedAt !== null || challenge.expiresAt <= this.#now()) {
      throw new RpError(
        'CHALLENGE_EXPIRED',
        'This proof challenge has expired or was already used.',
        409,
      );
    }

    const { resource, contextHash } = this.#operationBinding(
      input.operation,
      false,
      challenge.resource,
    );
    if (
      challenge.action !== input.operation.action ||
      challenge.resource !== resource ||
      !constantTimeTextEqual(challenge.contextHash, contextHash)
    ) {
      throw new RpError(
        'CHALLENGE_MISMATCH',
        'The note changed after this challenge was issued.',
        409,
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
        'The proof is not bound to this exact note change.',
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
    const verified = await verifyRpOperation(
      input.proof,
      expected,
      this.challenges,
      this.lifecycle,
    );

    const proofHash = canonicalSha256(input.proof);
    let note: StoredNote | null;
    let resultingVersion: number | null;

    if (input.operation.action === 'note.create') {
      const id = noteIdFromResource(challenge.resource);
      if (this.#notes.has(id)) {
        throw new RpError('VERSION_CONFLICT', 'A note already exists for this resource.', 409);
      }
      const now = this.#now();
      note = Object.freeze({
        id,
        resource: challenge.resource,
        authorSubject: verified.subject,
        title: input.operation.draft.title,
        body: input.operation.draft.body,
        createdAt: now,
        updatedAt: now,
        version: 1,
        acceptedProofHash: proofHash,
      });
      this.#notes.set(id, note);
      resultingVersion = note.version;
    } else {
      const current = this.#requireNote(input.operation.noteId);
      if (current.authorSubject !== verified.subject) {
        throw new RpError('AUTHOR_MISMATCH', 'This identity did not create the note.', 403);
      }
      if (current.version !== input.operation.expectedVersion) {
        throw new RpError(
          'VERSION_CONFLICT',
          'The note was updated in another view. Refresh and try again.',
          409,
        );
      }

      if (input.operation.action === 'note.delete') {
        this.#notes.delete(current.id);
        note = null;
        resultingVersion = null;
      } else {
        note = Object.freeze({
          ...current,
          title: input.operation.draft.title,
          body: input.operation.draft.body,
          updatedAt: this.#now(),
          version: current.version + 1,
          acceptedProofHash: proofHash,
        });
        this.#notes.set(note.id, note);
        resultingVersion = note.version;
      }
    }

    const receipt = this.#recordReceipt({
      operation: input.operation.action,
      resource: challenge.resource,
      subject: verified.subject,
      proofHash,
      resultingVersion,
    });
    const session = this.#issueSession(verified.subject);
    return { note: note === null ? null : toNoteView(note), receipt, session };
  }

  #operationBinding(
    operation: IssueChallengeInput,
    requireCurrentVersion: boolean,
    existingCreateResource?: string,
  ): {
    resource: string;
    contextHash: string;
  } {
    if (operation.action === 'note.create') {
      const resource = existingCreateResource ?? `note:nt_${secureToken(9)}`;
      return {
        resource,
        contextHash: canonicalSha256({ action: operation.action, draft: operation.draft }),
      };
    }

    const note = this.#requireNote(operation.noteId);
    if (requireCurrentVersion && note.version !== operation.expectedVersion) {
      throw new RpError(
        'VERSION_CONFLICT',
        'The note was updated in another view. Refresh and try again.',
        409,
      );
    }
    const context =
      operation.action === 'note.edit'
        ? {
            action: operation.action,
            expectedVersion: operation.expectedVersion,
            draft: operation.draft,
          }
        : { action: operation.action, expectedVersion: operation.expectedVersion };
    return { resource: note.resource, contextHash: canonicalSha256(context) };
  }

  #recordReceipt(input: Omit<ApplicationReceipt, 'acceptedAt' | 'receiptId'>): ApplicationReceipt {
    const acceptedAt = this.#now();
    const receiptId = `rpr_${canonicalSha256({ ...input, acceptedAt })}`;
    const receipt = Object.freeze({ ...input, acceptedAt, receiptId });
    this.#receipts.set(receiptId, receipt);
    return receipt;
  }

  #issueSession(subject: NexusSubject): RpSession {
    const token = secureToken(32);
    const session: StoredSession = {
      tokenHash: sha256Base64Url(token),
      subject,
      expiresAt: this.#now() + SESSION_TTL_SECONDS,
    };
    this.#sessions.set(session.tokenHash, session);
    return { token, subject, expiresAt: session.expiresAt };
  }

  #requireNote(id: string): StoredNote {
    const note = this.#notes.get(id);
    if (note === undefined)
      throw new RpError('NOT_FOUND', 'The requested note does not exist.', 404);
    return note;
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
        createdAt: timestamp,
        updatedAt: timestamp,
        version: 1,
        acceptedProofHash: proofHash,
      });
      this.#notes.set(note.id, note);
    }
  }
}

function parseSubmitOperation(value: unknown): SubmitOperationInput {
  const record = requireRecord(value, ['challengeId', 'operation', 'proof']);
  if (typeof record['challengeId'] !== 'string' || record['challengeId'].length < 20) {
    throw new RpError('BAD_REQUEST', 'challengeId is invalid.', 400);
  }
  if (!isRecord(record['proof'])) throw new RpError('BAD_REQUEST', 'proof is required.', 400);
  return {
    challengeId: record['challengeId'],
    operation: parseOperation(record['operation']),
    proof: record['proof'] as unknown as OwnershipProofV1,
  };
}

function parseOperation(value: unknown): IssueChallengeInput {
  if (!isRecord(value) || typeof value['action'] !== 'string') {
    throw new RpError('BAD_REQUEST', 'A note action is required.', 400);
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
  throw new RpError('BAD_REQUEST', 'The requested note action is unsupported.', 400);
}

function parseDraft(value: unknown): NoteDraft {
  const record = requireRecord(value, ['body', 'title']);
  const title = typeof record['title'] === 'string' ? record['title'].trim() : '';
  const body = typeof record['body'] === 'string' ? record['body'].trim() : '';
  if (title.length < 1 || title.length > 80) {
    throw new RpError('BAD_REQUEST', 'Note title must be between 1 and 80 characters.', 400);
  }
  if (body.length < 1 || body.length > 4_000) {
    throw new RpError('BAD_REQUEST', 'Note body must be between 1 and 4,000 characters.', 400);
  }
  return { title, body };
}

function parseNoteId(value: unknown): string {
  if (typeof value !== 'string' || !/^nt_[A-Za-z0-9_-]{3,80}$/u.test(value)) {
    throw new RpError('BAD_REQUEST', 'noteId is invalid.', 400);
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

function noteIdFromResource(resource: string): string {
  if (!resource.startsWith('note:'))
    throw new RpError('INTERNAL_ERROR', 'Invalid note resource.', 500);
  return resource.slice('note:'.length);
}

function seedSubject(label: string): NexusSubject {
  return `nx1_${sha256Base64Url(`seed-subject:${label}`)}`;
}

function toNoteView(note: StoredNote): NoteView {
  return {
    id: note.id,
    resource: note.resource,
    authorSubject: note.authorSubject,
    title: note.title,
    body: note.body,
    createdAt: note.createdAt,
    updatedAt: note.updatedAt,
    version: note.version,
    proofFingerprint: note.acceptedProofHash.slice(0, 12),
  };
}
