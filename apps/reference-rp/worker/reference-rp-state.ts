import { DurableObject } from 'cloudflare:workers';

import { audienceOriginSchema } from '@nexus/protocol';
import type { Base64Url32, NexusSubject, VerificationExpectation } from '@nexus/protocol';
import { verifyOwnershipProof } from '@nexus/verifier';

import type {
  ApplicationReceipt,
  AuthorizationMethod,
  IssuedChallenge,
  NoteVisibility,
  NoteView,
  ReplyView,
  SessionOperationInput,
  SessionOperationResult,
  SessionStartResult,
  SessionStatus,
  StartSessionOperation,
  SubmitProofInput,
} from '../src/shared/contracts';
import { canonicalSha256, constantTimeTextEqual, secureToken, sha256Base64Url } from './crypto';
import { RpWorkerError, toSafeWorkerError } from './errors';
import { getAuthoritativeLifecycle, type LifecycleEnv } from './lifecycle';
import {
  parseNoteId,
  parseSessionOperation,
  parseStartSessionOperation,
  parseSubmitProof,
} from './validation';

const CHALLENGE_TTL_SECONDS = 60;
const SESSION_TTL_SECONDS = 5 * 60;
const MAX_CLOCK_SKEW_SECONDS = 30;
const MAX_BODY_BYTES = 64 * 1024;
const MAX_OUTSTANDING_CHALLENGES = 512;
const MAX_TOTAL_CHALLENGES = 2_048;
const SESSION_COOKIE_NAME = '__Host-nexus_notes_session';
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

export interface ReferenceRpEnv extends LifecycleEnv {
  readonly RP_AUDIENCE: string;
}

interface ChallengeRow extends Record<string, SqlStorageValue> {
  challenge_id: string;
  nonce_hash: string;
  action: string;
  resource: string;
  context_hash: string;
  expires_at: number;
  consumed_at: number | null;
}

interface NoteRow extends Record<string, SqlStorageValue> {
  id: string;
  resource: string;
  author_subject: string;
  title: string;
  body: string;
  visibility: string;
  created_at: number;
  updated_at: number;
  version: number;
  accepted_proof_hash: string;
  accepted_authorization: string;
}

interface SessionRow extends Record<string, SqlStorageValue> {
  token_hash: string;
  subject: string;
  expires_at: number;
  proof_hash: string;
}

interface RestrictionPresenceRow extends Record<string, SqlStorageValue> {
  present: number;
}

interface ReplyRow extends Record<string, SqlStorageValue> {
  id: string;
  note_id: string;
  author_subject: string;
  body: string;
  created_at: number;
}

interface ProfileRow extends Record<string, SqlStorageValue> {
  subject: string;
  friendly_name: string;
  name_key: string;
  updated_at: number;
}

interface StartedSession {
  readonly token: string;
  readonly result: SessionStartResult;
}

interface ActiveSession {
  readonly tokenHash: string;
  readonly proofHash: string;
  readonly status: SessionStatus;
}

export class ReferenceRpState extends DurableObject<ReferenceRpEnv> {
  public constructor(ctx: DurableObjectState, env: ReferenceRpEnv) {
    super(ctx, env);
    void this.ctx.blockConcurrencyWhile(() => {
      this.#migrate();
      this.#seedNotes();
      return Promise.resolve();
    });
  }

  public override async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (request.method === 'GET' && url.pathname === '/api/health') {
        return jsonResponse({ ok: true });
      }
      if (request.method === 'GET' && url.pathname === '/api/notes') {
        const session = await this.#optionalSession(request);
        return jsonResponse({ notes: this.#listNotes(session?.status.subject) });
      }
      if (request.method === 'GET' && url.pathname.startsWith('/api/notes/')) {
        let decoded: string;
        try {
          decoded = decodeURIComponent(url.pathname.slice('/api/notes/'.length));
        } catch {
          throw new RpWorkerError('BAD_REQUEST', 'noteId is invalid.', 400);
        }
        const session = await this.#optionalSession(request);
        return jsonResponse({ note: this.#getNote(parseNoteId(decoded), session?.status.subject) });
      }
      if (request.method === 'POST' && url.pathname === '/api/challenges') {
        const operation = parseStartSessionOperation(await readStrictJson(request));
        return jsonResponse({ challenge: await this.#issueChallenge(operation) }, 201);
      }
      if (request.method === 'POST' && url.pathname === '/api/operations') {
        const input = parseSubmitProof(await readStrictJson(request));
        const started = await this.#startSession(input);
        return jsonResponse(started.result, 200, {
          'Set-Cookie': createSessionCookie(started.token),
        });
      }
      if (request.method === 'POST' && url.pathname === '/api/session-operations') {
        assertSessionMutationRequest(request);
        const session = await this.#requireSession(request);
        const operation = parseSessionOperation(await readStrictJson(request));
        return jsonResponse(this.#commitSessionOperation(operation, session));
      }
      if (request.method === 'GET' && url.pathname === '/api/session') {
        return jsonResponse({ session: (await this.#requireSession(request)).status });
      }
      if (request.method === 'DELETE' && url.pathname === '/api/session') {
        assertSessionMutationRequest(request);
        await this.#endSession(request);
        return jsonResponse({ ok: true }, 200, { 'Set-Cookie': clearSessionCookie() });
      }
      throw new RpWorkerError('NOT_FOUND', 'API route not found.', 404);
    } catch (error) {
      const safe = toSafeWorkerError(error);
      return jsonResponse({ error: { code: safe.code, message: safe.message } }, safe.status);
    }
  }

  async #issueChallenge(operation: StartSessionOperation): Promise<IssuedChallenge> {
    const now = nowSeconds();
    const contextHash = await canonicalSha256({ action: operation.action, policy: SESSION_POLICY });
    const nonce = secureToken(32);
    const challenge: IssuedChallenge = {
      challengeId: secureToken(16),
      action: operation.action,
      resource: SESSION_RESOURCE,
      nonce: nonce as IssuedChallenge['nonce'],
      expiresAt: now + CHALLENGE_TTL_SECONDS,
      contextHash: contextHash as Base64Url32,
    };
    const nonceHash = await sha256Base64Url(nonce);

    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec('DELETE FROM challenges WHERE expires_at <= ?', now);
      const counts = this.ctx.storage.sql
        .exec<{ outstanding: number; total: number }>(
          `SELECT COUNT(*) AS total,
                  COALESCE(SUM(CASE WHEN consumed_at IS NULL THEN 1 ELSE 0 END), 0) AS outstanding
             FROM challenges`,
        )
        .one();
      if (
        counts.total >= MAX_TOTAL_CHALLENGES ||
        counts.outstanding >= MAX_OUTSTANDING_CHALLENGES
      ) {
        throw new RpWorkerError(
          'RATE_LIMITED',
          'The reference service is temporarily at capacity. Try again shortly.',
          429,
        );
      }
      this.ctx.storage.sql.exec(
        `INSERT INTO challenges
          (challenge_id, nonce_hash, action, resource, context_hash, expires_at, consumed_at)
         VALUES (?, ?, ?, ?, ?, ?, NULL)`,
        challenge.challengeId,
        nonceHash,
        challenge.action,
        challenge.resource,
        contextHash,
        challenge.expiresAt,
      );
    });
    return challenge;
  }

  async #startSession(input: SubmitProofInput): Promise<StartedSession> {
    const initial = this.#readChallenge(input.challengeId);
    const initialNow = nowSeconds();
    this.#assertChallengeUsable(initial, initialNow);
    const contextHash = await canonicalSha256({
      action: input.operation.action,
      policy: SESSION_POLICY,
    });
    if (
      initial.action !== input.operation.action ||
      initial.resource !== SESSION_RESOURCE ||
      !constantTimeTextEqual(initial.context_hash, contextHash)
    ) {
      throw new RpWorkerError(
        'CHALLENGE_MISMATCH',
        'The session policy changed after this challenge was issued.',
        409,
      );
    }

    const payload = input.proof.payload;
    const nonceHash = await sha256Base64Url(payload.nonce);
    if (
      !constantTimeTextEqual(nonceHash, initial.nonce_hash) ||
      payload.contextHash === undefined ||
      !constantTimeTextEqual(payload.contextHash, initial.context_hash)
    ) {
      throw new RpWorkerError(
        'CHALLENGE_MISMATCH',
        'The proof is not bound to this exact Notes session.',
        403,
      );
    }

    const audience = validatedAudience(this.env.RP_AUDIENCE);
    const expected: VerificationExpectation = {
      audience,
      action: initial.action,
      resource: initial.resource,
      nonce: payload.nonce,
      now: initialNow,
      maxClockSkewSeconds: MAX_CLOCK_SKEW_SECONDS,
    };
    const verified = await verifyOwnershipProof(input.proof, expected);
    const lifecycle = await getAuthoritativeLifecycle(this.env, verified.subject);
    if (lifecycle.state === 'not-found') {
      throw new RpWorkerError(
        'IDENTITY_NOT_FOUND',
        'This Nexus identity is not active in the authoritative registry.',
        403,
      );
    }
    if (lifecycle.state !== 'active') {
      throw new RpWorkerError(
        'IDENTITY_REVOKED',
        'This Nexus identity is revoked and cannot change notes.',
        403,
      );
    }

    const proofHash = await canonicalSha256(input.proof);
    const token = secureToken(32);
    const tokenHash = await sha256Base64Url(token);
    const receiptId = `rpr_${secureToken(18)}`;
    return this.#commitStartedSession({
      input,
      expectedChallenge: initial,
      subject: verified.subject,
      proofHash,
      token,
      tokenHash,
      receiptId,
      sequence: lifecycle.sequence,
    });
  }

  #commitStartedSession(prepared: {
    input: SubmitProofInput;
    expectedChallenge: ChallengeRow;
    subject: NexusSubject;
    proofHash: string;
    token: string;
    tokenHash: string;
    receiptId: string;
    sequence: number;
  }): StartedSession {
    return this.ctx.storage.transactionSync<StartedSession>(() => {
      const now = nowSeconds();
      const currentChallenge = this.#readChallenge(prepared.input.challengeId);
      this.#assertChallengeUsable(currentChallenge, now);
      if (
        currentChallenge.nonce_hash !== prepared.expectedChallenge.nonce_hash ||
        currentChallenge.action !== prepared.expectedChallenge.action ||
        currentChallenge.resource !== prepared.expectedChallenge.resource ||
        currentChallenge.context_hash !== prepared.expectedChallenge.context_hash
      ) {
        throw new RpWorkerError(
          'CHALLENGE_MISMATCH',
          'The proof challenge no longer matches this operation.',
          409,
        );
      }

      if (this.#isSubjectRestricted(prepared.subject, now)) {
        throw new RpWorkerError(
          'SUBJECT_RESTRICTED',
          'This Nexus subject is restricted from starting a Notes session.',
          403,
        );
      }

      this.ctx.storage.sql.exec(
        `UPDATE challenges SET consumed_at = ?
          WHERE challenge_id = ? AND consumed_at IS NULL AND expires_at > ?`,
        now,
        currentChallenge.challenge_id,
        now,
      );
      const changed = this.ctx.storage.sql
        .exec<{ changed: number }>('SELECT changes() AS changed')
        .one();
      if (changed.changed !== 1) {
        throw new RpWorkerError(
          'CHALLENGE_EXPIRED',
          'This proof challenge has expired or was already used.',
          409,
        );
      }

      const receipt: ApplicationReceipt = {
        receiptId: prepared.receiptId,
        operation: prepared.input.operation.action,
        resource: currentChallenge.resource,
        subject: prepared.subject,
        authorization: 'wallet-proof',
        proofHash: prepared.proofHash,
        acceptedAt: now,
        resultingVersion: null,
      };
      this.#insertReceipt(receipt);

      const session: SessionStatus = {
        subject: prepared.subject,
        friendlyName: this.#friendlyName(prepared.subject),
        state: 'active',
        sequence: prepared.sequence,
        expiresAt: now + SESSION_TTL_SECONDS,
        checkedAt: now,
      };
      this.ctx.storage.sql.exec('DELETE FROM sessions WHERE expires_at <= ?', now);
      this.ctx.storage.sql.exec(
        `INSERT INTO sessions (token_hash, subject, expires_at, proof_hash)
         VALUES (?, ?, ?, ?)`,
        prepared.tokenHash,
        prepared.subject,
        session.expiresAt,
        prepared.proofHash,
      );
      return { token: prepared.token, result: { receipt, session } };
    });
  }

  async #activeSession(token: string): Promise<ActiveSession> {
    if (token.length < 20) {
      throw new RpWorkerError('SESSION_INVALID', 'The RP session is missing or invalid.', 401);
    }
    const tokenHash = await sha256Base64Url(token);
    const row = this.ctx.storage.sql
      .exec<SessionRow>(
        'SELECT token_hash, subject, expires_at, proof_hash FROM sessions WHERE token_hash = ?',
        tokenHash,
      )
      .toArray()[0];
    const now = nowSeconds();
    if (row === undefined || row.expires_at <= now) {
      throw new RpWorkerError('SESSION_INVALID', 'The RP session has expired.', 401);
    }
    const subject = row.subject as NexusSubject;
    const lifecycle = await getAuthoritativeLifecycle(this.env, subject);
    if (lifecycle.state === 'not-found') {
      throw new RpWorkerError('SESSION_INVALID', 'The identity is no longer registered.', 401);
    }
    if (lifecycle.state !== 'active') {
      throw new RpWorkerError('SESSION_INVALID', 'The Nexus identity is revoked.', 401);
    }
    if (this.#isSubjectRestricted(subject, now)) {
      this.ctx.storage.sql.exec('DELETE FROM sessions WHERE token_hash = ?', tokenHash);
      throw new RpWorkerError('SESSION_INVALID', 'The RP session is no longer permitted.', 401);
    }
    return {
      tokenHash,
      proofHash: row.proof_hash,
      status: {
        subject,
        friendlyName: this.#friendlyName(subject),
        state: 'active',
        sequence: lifecycle.sequence,
        expiresAt: row.expires_at,
        checkedAt: now,
      },
    };
  }

  async #requireSession(request: Request): Promise<ActiveSession> {
    return this.#activeSession(readSessionToken(request.headers.get('Cookie')));
  }

  async #optionalSession(request: Request): Promise<ActiveSession | null> {
    const token = readSessionToken(request.headers.get('Cookie'));
    if (token.length === 0) return null;
    try {
      return await this.#activeSession(token);
    } catch {
      return null;
    }
  }

  async #endSession(request: Request): Promise<void> {
    const token = readSessionToken(request.headers.get('Cookie'));
    if (token.length === 0) return;
    const tokenHash = await sha256Base64Url(token);
    this.ctx.storage.sql.exec('DELETE FROM sessions WHERE token_hash = ?', tokenHash);
  }

  #commitSessionOperation(
    operation: SessionOperationInput,
    session: ActiveSession,
  ): SessionOperationResult {
    return this.ctx.storage.transactionSync<SessionOperationResult>(() => {
      const now = nowSeconds();
      const persisted = this.ctx.storage.sql
        .exec<{ present: number }>(
          'SELECT COUNT(*) AS present FROM sessions WHERE token_hash = ? AND expires_at > ?',
          session.tokenHash,
          now,
        )
        .one();
      if (persisted.present !== 1) {
        throw new RpWorkerError('SESSION_INVALID', 'The RP session has expired.', 401);
      }

      const subject = session.status.subject;
      let note: NoteView | null;
      let resource: string;
      let resultingVersion: number | null;

      if (operation.action === 'profile.set-name') {
        const nameKey = friendlyNameKey(operation.friendlyName);
        const claimed = this.ctx.storage.sql
          .exec<ProfileRow>(
            'SELECT subject, friendly_name, name_key, updated_at FROM profiles WHERE name_key = ?',
            nameKey,
          )
          .toArray()[0];
        if (claimed !== undefined && claimed.subject !== subject) {
          throw new RpWorkerError('NAME_TAKEN', 'That friendly name is already in use.', 409);
        }
        this.ctx.storage.sql.exec(
          `INSERT INTO profiles (subject, friendly_name, name_key, updated_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(subject) DO UPDATE SET
             friendly_name = excluded.friendly_name,
             name_key = excluded.name_key,
             updated_at = excluded.updated_at`,
          subject,
          operation.friendlyName,
          nameKey,
          now,
        );
        resource = `profile:${subject}`;
        note = null;
        resultingVersion = null;
      } else if (operation.action === 'note.create') {
        const id = `nt_${secureToken(9)}`;
        resource = `note:${id}`;
        this.ctx.storage.sql.exec(
          `INSERT INTO notes
            (id, resource, author_subject, title, body, visibility, created_at, updated_at,
             version, accepted_proof_hash, accepted_authorization)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 'rp-session')`,
          id,
          resource,
          subject,
          operation.draft.title,
          operation.draft.body,
          operation.draft.visibility,
          now,
          now,
          session.proofHash,
        );
        note = this.#getNote(id, subject);
        resultingVersion = 1;
      } else if (operation.action === 'note.edit' || operation.action === 'note.delete') {
        const current = this.#requireOwnedNote(operation.noteId, subject);
        if (current.version !== operation.expectedVersion) {
          throw new RpWorkerError(
            'VERSION_CONFLICT',
            'The note was updated in another view. Refresh and try again.',
            409,
          );
        }
        resource = current.resource;
        if (operation.action === 'note.delete') {
          this.ctx.storage.sql.exec('DELETE FROM note_likes WHERE note_id = ?', current.id);
          this.ctx.storage.sql.exec('DELETE FROM replies WHERE note_id = ?', current.id);
          this.ctx.storage.sql.exec(
            'DELETE FROM notes WHERE id = ? AND version = ?',
            current.id,
            current.version,
          );
          note = null;
          resultingVersion = null;
        } else {
          this.ctx.storage.sql.exec(
            `UPDATE notes
                SET title = ?, body = ?, visibility = ?, updated_at = ?, version = version + 1,
                    accepted_proof_hash = ?, accepted_authorization = 'rp-session'
              WHERE id = ? AND version = ?`,
            operation.draft.title,
            operation.draft.body,
            operation.draft.visibility,
            now,
            session.proofHash,
            current.id,
            current.version,
          );
          note = this.#getNote(current.id, subject);
          resultingVersion = current.version + 1;
        }
      } else if (operation.action === 'reply.create') {
        const current = this.#requireVisibleNote(operation.noteId, subject);
        const replyId = `rpy_${secureToken(12)}`;
        this.ctx.storage.sql.exec(
          `INSERT INTO replies (id, note_id, author_subject, body, created_at)
           VALUES (?, ?, ?, ?, ?)`,
          replyId,
          current.id,
          subject,
          operation.body,
          now,
        );
        resource = `${current.resource}#reply:${replyId}`;
        note = this.#getNote(current.id, subject);
        resultingVersion = current.version;
      } else if (operation.action === 'reply.delete') {
        const current = this.#requireVisibleNote(operation.noteId, subject);
        const reply = this.#requireReply(operation.replyId, current.id);
        if (reply.author_subject !== subject && current.author_subject !== subject) {
          throw new RpWorkerError(
            'AUTHOR_MISMATCH',
            'Only the reply author or note author can remove this reply.',
            403,
          );
        }
        this.ctx.storage.sql.exec(
          'DELETE FROM replies WHERE id = ? AND note_id = ?',
          reply.id,
          current.id,
        );
        resource = `${current.resource}#reply:${reply.id}`;
        note = this.#getNote(current.id, subject);
        resultingVersion = current.version;
      } else {
        const current = this.#requireNoteRow(operation.noteId);
        if (current.visibility !== 'public') {
          throw new RpWorkerError('OPERATION_NOT_ALLOWED', 'Private notes cannot be liked.', 403);
        }
        if (operation.action === 'note.like') {
          this.ctx.storage.sql.exec(
            'INSERT OR IGNORE INTO note_likes (note_id, subject, created_at) VALUES (?, ?, ?)',
            current.id,
            subject,
            now,
          );
        } else {
          this.ctx.storage.sql.exec(
            'DELETE FROM note_likes WHERE note_id = ? AND subject = ?',
            current.id,
            subject,
          );
        }
        resource = current.resource;
        note = this.#getNote(current.id, subject);
        resultingVersion = current.version;
      }

      const receipt: ApplicationReceipt = {
        receiptId: `rpr_${secureToken(18)}`,
        operation: operation.action,
        resource,
        subject,
        authorization: 'rp-session',
        proofHash: session.proofHash,
        acceptedAt: now,
        resultingVersion,
      };
      this.#insertReceipt(receipt);
      return {
        note,
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
    });
  }

  #insertReceipt(receipt: ApplicationReceipt): void {
    this.ctx.storage.sql.exec(
      `INSERT INTO receipts
        (receipt_id, operation, resource, subject, authorization, proof_hash, accepted_at,
         resulting_version)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      receipt.receiptId,
      receipt.operation,
      receipt.resource,
      receipt.subject,
      receipt.authorization,
      receipt.proofHash,
      receipt.acceptedAt,
      receipt.resultingVersion,
    );
  }

  #requireOwnedNote(id: string, subject: NexusSubject): NoteRow {
    const note = this.#requireNoteRow(id);
    if (note.author_subject !== subject) {
      throw new RpWorkerError('AUTHOR_MISMATCH', 'This session did not create the note.', 403);
    }
    return note;
  }

  #requireVisibleNote(id: string, subject: NexusSubject): NoteRow {
    const note = this.#requireNoteRow(id);
    if (note.visibility === 'private' && note.author_subject !== subject) {
      throw new RpWorkerError('NOT_FOUND', 'The requested note does not exist.', 404);
    }
    return note;
  }

  #requireReply(id: string, noteId: string): ReplyRow {
    const reply = this.ctx.storage.sql
      .exec<ReplyRow>(
        `SELECT id, note_id, author_subject, body, created_at
           FROM replies WHERE id = ? AND note_id = ?`,
        id,
        noteId,
      )
      .toArray()[0];
    if (reply === undefined) {
      throw new RpWorkerError('NOT_FOUND', 'The requested reply does not exist.', 404);
    }
    return reply;
  }

  #listNotes(viewerSubject?: NexusSubject): NoteView[] {
    return this.ctx.storage.sql
      .exec<NoteRow>(
        `SELECT id, resource, author_subject, title, body, visibility, created_at, updated_at,
                version, accepted_proof_hash, accepted_authorization
           FROM notes
          WHERE visibility = 'public' OR author_subject = ?
          ORDER BY updated_at DESC, id`,
        viewerSubject ?? '',
      )
      .toArray()
      .map((note) => this.#toNoteView(note, viewerSubject));
  }

  #getNote(id: string, viewerSubject?: NexusSubject): NoteView {
    const note = this.#requireNoteRow(id);
    if (note.visibility === 'private' && note.author_subject !== viewerSubject) {
      throw new RpWorkerError('NOT_FOUND', 'The requested note does not exist.', 404);
    }
    return this.#toNoteView(note, viewerSubject);
  }

  #requireNoteRow(id: string): NoteRow {
    const note = this.#findNote(id);
    if (note === null) {
      throw new RpWorkerError('NOT_FOUND', 'The requested note does not exist.', 404);
    }
    return note;
  }

  #findNote(id: string): NoteRow | null {
    return (
      this.ctx.storage.sql
        .exec<NoteRow>(
          `SELECT id, resource, author_subject, title, body, visibility, created_at, updated_at,
                  version, accepted_proof_hash, accepted_authorization
             FROM notes WHERE id = ?`,
          id,
        )
        .toArray()[0] ?? null
    );
  }

  #toNoteView(note: NoteRow, viewerSubject?: NexusSubject): NoteView {
    const replies = this.ctx.storage.sql
      .exec<ReplyRow>(
        `SELECT id, note_id, author_subject, body, created_at
           FROM replies WHERE note_id = ? ORDER BY created_at, id`,
        note.id,
      )
      .toArray()
      .map((reply) => this.#toReplyView(reply));
    const likeCount = this.ctx.storage.sql
      .exec<{ count: number }>(
        'SELECT COUNT(*) AS count FROM note_likes WHERE note_id = ?',
        note.id,
      )
      .one().count;
    const likedByViewer =
      viewerSubject !== undefined &&
      this.ctx.storage.sql
        .exec<{ count: number }>(
          'SELECT COUNT(*) AS count FROM note_likes WHERE note_id = ? AND subject = ?',
          note.id,
          viewerSubject,
        )
        .one().count === 1;
    return {
      id: note.id,
      resource: note.resource,
      authorSubject: note.author_subject as NexusSubject,
      authorFriendlyName: this.#friendlyName(note.author_subject as NexusSubject),
      title: note.title,
      body: note.body,
      visibility: parseStoredVisibility(note.visibility),
      createdAt: note.created_at,
      updatedAt: note.updated_at,
      version: note.version,
      authorization: parseStoredAuthorization(note.accepted_authorization),
      proofFingerprint: note.accepted_proof_hash.slice(0, 12),
      likeCount,
      likedByViewer,
      replies,
    };
  }

  #toReplyView(reply: ReplyRow): ReplyView {
    const subject = reply.author_subject as NexusSubject;
    return {
      id: reply.id,
      noteId: reply.note_id,
      authorSubject: subject,
      authorFriendlyName: this.#friendlyName(subject),
      body: reply.body,
      createdAt: reply.created_at,
    };
  }

  #friendlyName(subject: NexusSubject): string | null {
    return (
      this.ctx.storage.sql
        .exec<ProfileRow>(
          'SELECT subject, friendly_name, name_key, updated_at FROM profiles WHERE subject = ?',
          subject,
        )
        .toArray()[0]?.friendly_name ?? null
    );
  }

  #isSubjectRestricted(subject: NexusSubject, now: number): boolean {
    return (
      this.ctx.storage.sql
        .exec<RestrictionPresenceRow>(
          `SELECT EXISTS (
             SELECT 1
               FROM subject_restrictions
              WHERE subject = ?
                AND lifted_at IS NULL
                AND (expires_at IS NULL OR expires_at > ?)
           ) AS present`,
          subject,
          now,
        )
        .one().present === 1
    );
  }

  #readChallenge(challengeId: string): ChallengeRow {
    const challenge = this.ctx.storage.sql
      .exec<ChallengeRow>(
        `SELECT challenge_id, nonce_hash, action, resource, context_hash, expires_at, consumed_at
           FROM challenges WHERE challenge_id = ?`,
        challengeId,
      )
      .toArray()[0];
    if (challenge === undefined) {
      throw new RpWorkerError(
        'CHALLENGE_EXPIRED',
        'This proof challenge has expired or was already used.',
        409,
      );
    }
    return challenge;
  }

  #assertChallengeUsable(challenge: ChallengeRow, now: number): void {
    if (challenge.consumed_at !== null || challenge.expires_at <= now) {
      throw new RpWorkerError(
        'CHALLENGE_EXPIRED',
        'This proof challenge has expired or was already used.',
        409,
      );
    }
  }

  #migrate(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS schema_meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        version INTEGER NOT NULL,
        seeded INTEGER NOT NULL CHECK (seeded IN (0, 1))
      );
      INSERT OR IGNORE INTO schema_meta (singleton, version, seeded) VALUES (1, 4, 0);
      CREATE TABLE IF NOT EXISTS challenges (
        challenge_id TEXT PRIMARY KEY,
        nonce_hash TEXT NOT NULL UNIQUE,
        action TEXT NOT NULL,
        resource TEXT NOT NULL,
        context_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS challenges_expiry ON challenges (expires_at);
      CREATE TABLE IF NOT EXISTS notes (
        id TEXT PRIMARY KEY,
        resource TEXT NOT NULL UNIQUE,
        author_subject TEXT NOT NULL,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        visibility TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'private')),
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        version INTEGER NOT NULL CHECK (version >= 1),
        accepted_proof_hash TEXT NOT NULL,
        accepted_authorization TEXT NOT NULL DEFAULT 'wallet-proof'
          CHECK (accepted_authorization IN ('wallet-proof', 'rp-session'))
      );
      CREATE TRIGGER IF NOT EXISTS notes_immutable_identity
      BEFORE UPDATE OF id, resource, author_subject, created_at ON notes
      BEGIN
        SELECT RAISE(ABORT, 'immutable note identity');
      END;
      CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        subject TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        proof_hash TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions (expires_at);
      CREATE TABLE IF NOT EXISTS receipts (
        receipt_id TEXT PRIMARY KEY,
        operation TEXT NOT NULL,
        resource TEXT NOT NULL,
        subject TEXT NOT NULL,
        authorization TEXT NOT NULL DEFAULT 'wallet-proof'
          CHECK (authorization IN ('wallet-proof', 'rp-session')),
        proof_hash TEXT NOT NULL,
        accepted_at INTEGER NOT NULL,
        resulting_version INTEGER
      );
      CREATE TABLE IF NOT EXISTS replies (
        id TEXT PRIMARY KEY,
        note_id TEXT NOT NULL,
        author_subject TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS replies_note ON replies (note_id, created_at);
      CREATE TRIGGER IF NOT EXISTS replies_immutable_identity
      BEFORE UPDATE OF id, note_id, author_subject, created_at ON replies
      BEGIN
        SELECT RAISE(ABORT, 'immutable reply identity');
      END;
      CREATE TABLE IF NOT EXISTS note_likes (
        note_id TEXT NOT NULL,
        subject TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (note_id, subject)
      );
      CREATE INDEX IF NOT EXISTS note_likes_note ON note_likes (note_id);
      CREATE TABLE IF NOT EXISTS profiles (
        subject TEXT PRIMARY KEY,
        friendly_name TEXT NOT NULL,
        name_key TEXT NOT NULL UNIQUE,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS subject_restrictions (
        restriction_id TEXT PRIMARY KEY,
        subject TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('ban', 'hold', 'suspect')),
        created_at INTEGER NOT NULL,
        expires_at INTEGER,
        lifted_at INTEGER,
        CHECK (
          (kind = 'ban' AND expires_at IS NULL) OR
          (kind IN ('hold', 'suspect') AND expires_at IS NOT NULL)
        ),
        CHECK (expires_at IS NULL OR expires_at > created_at),
        CHECK (lifted_at IS NULL OR lifted_at >= created_at)
      );
      CREATE INDEX IF NOT EXISTS subject_restrictions_lookup
        ON subject_restrictions (subject, lifted_at, expires_at);
    `);
    let version = this.ctx.storage.sql
      .exec<{ version: number }>('SELECT version FROM schema_meta WHERE singleton = 1')
      .one().version;
    if (version === 1) {
      this.ctx.storage.sql.exec(`
        ALTER TABLE notes ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public'
          CHECK (visibility IN ('public', 'private'));
        ALTER TABLE notes ADD COLUMN accepted_authorization TEXT NOT NULL DEFAULT 'wallet-proof'
          CHECK (accepted_authorization IN ('wallet-proof', 'rp-session'));
        ALTER TABLE sessions ADD COLUMN proof_hash TEXT NOT NULL DEFAULT '';
        DELETE FROM sessions;
        ALTER TABLE receipts ADD COLUMN authorization TEXT NOT NULL DEFAULT 'wallet-proof'
          CHECK (authorization IN ('wallet-proof', 'rp-session'));
        UPDATE schema_meta SET version = 2 WHERE singleton = 1;
      `);
      version = 2;
    }
    if (version === 2) {
      this.ctx.storage.sql.exec('UPDATE schema_meta SET version = 3 WHERE singleton = 1');
      version = 3;
    }
    if (version === 3) {
      this.ctx.storage.sql.exec('UPDATE schema_meta SET version = 4 WHERE singleton = 1');
      version = 4;
    }
    if (version !== 4) throw new Error('Reference RP schema version is unsupported.');
  }

  #seedNotes(): void {
    const seeded = this.ctx.storage.sql
      .exec<{ seeded: number }>('SELECT seeded FROM schema_meta WHERE singleton = 1')
      .one().seeded;
    if (seeded === 1) return;
    const now = nowSeconds();
    const seeds = [
      [
        'nt_field-notes',
        'Lanterns after the rain',
        'The path behind the old library is quiet again. Someone left three paper lanterns under the cedar, each with a tiny constellation drawn inside.',
        1_420,
        'A',
      ],
      [
        'nt_small-things',
        'A list of small things worth keeping',
        'Warm tea before sunrise. A page with generous margins. The exact blue the sky becomes just before the streetlights switch off.',
        8_740,
        'B',
      ],
      [
        'nt_station-window',
        'From the last train window',
        'Every lit apartment became a one-second story. None of the people inside needed a name for the scene to feel complete.',
        25_680,
        'C',
      ],
    ] as const;
    this.ctx.storage.transactionSync(() => {
      for (const [id, title, body, age, marker] of seeds) {
        const timestamp = now - age;
        this.ctx.storage.sql.exec(
          `INSERT INTO notes
            (id, resource, author_subject, title, body, created_at, updated_at, version, accepted_proof_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`,
          id,
          `note:${id}`,
          `nx1_${marker.repeat(43)}`,
          title,
          body,
          timestamp,
          timestamp,
          marker.repeat(43),
        );
      }
      this.ctx.storage.sql.exec('UPDATE schema_meta SET seeded = 1 WHERE singleton = 1');
    });
  }
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1_000);
}

function validatedAudience(value: string): string {
  const audience = audienceOriginSchema.safeParse(value);
  if (!audience.success) {
    throw new RpWorkerError('INTERNAL_ERROR', 'The RP audience is not configured.', 500);
  }
  return audience.data;
}

function parseStoredVisibility(value: string): NoteVisibility {
  if (value !== 'public' && value !== 'private') {
    throw new RpWorkerError('INTERNAL_ERROR', 'Stored note visibility is invalid.', 500);
  }
  return value;
}

function parseStoredAuthorization(value: string): AuthorizationMethod {
  if (value !== 'wallet-proof' && value !== 'rp-session') {
    throw new RpWorkerError('INTERNAL_ERROR', 'Stored authorization method is invalid.', 500);
  }
  return value;
}

function friendlyNameKey(name: string): string {
  return name.toLowerCase();
}

function readSessionToken(header: string | null): string {
  if (header === null) return '';
  for (const segment of header.split(';')) {
    const [rawName, ...rawValue] = segment.trim().split('=');
    if (rawName !== SESSION_COOKIE_NAME) continue;
    const token = rawValue.join('=');
    return /^[A-Za-z0-9_-]{43}$/u.test(token) ? token : '';
  }
  return '';
}

function createSessionCookie(token: string): string {
  return `${SESSION_COOKIE_NAME}=${token}; Path=/; Max-Age=${String(SESSION_TTL_SECONDS)}; Secure; HttpOnly; SameSite=Strict`;
}

function clearSessionCookie(): string {
  return `${SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`;
}

function assertSessionMutationRequest(request: Request): void {
  if (request.headers.get('X-Nexus-Notes-Session') !== '1') {
    throw new RpWorkerError('BAD_REQUEST', 'The session request marker is missing.', 400);
  }
}

async function readStrictJson(request: Request): Promise<unknown> {
  const contentType = request.headers.get('Content-Type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') {
    throw new RpWorkerError('BAD_REQUEST', 'Requests must use application/json.', 415);
  }
  const declaredLength = request.headers.get('Content-Length');
  if (declaredLength !== null && Number(declaredLength) > MAX_BODY_BYTES) {
    throw new RpWorkerError('BAD_REQUEST', 'Request body is too large.', 413);
  }
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_BODY_BYTES) {
    throw new RpWorkerError('BAD_REQUEST', 'Request body is empty or too large.', 413);
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new RpWorkerError('BAD_REQUEST', 'Request body is not valid UTF-8.', 400);
  }
  try {
    return parseJsonWithUniqueKeys(text);
  } catch {
    throw new RpWorkerError('BAD_REQUEST', 'Request body is not valid JSON.', 400);
  }
}

function parseJsonWithUniqueKeys(text: string): unknown {
  let cursor = 0;
  const whitespace = (character: string): boolean =>
    character === ' ' || character === '\t' || character === '\n' || character === '\r';
  const skipWhitespace = (): void => {
    while (cursor < text.length && whitespace(text[cursor] ?? '')) cursor += 1;
  };
  const readString = (): string => {
    const start = cursor;
    if (text[cursor] !== '"') throw new SyntaxError('Expected a JSON string.');
    cursor += 1;
    let escaped = false;
    while (cursor < text.length) {
      const character = text[cursor];
      cursor += 1;
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') return JSON.parse(text.slice(start, cursor)) as string;
    }
    throw new SyntaxError('Unterminated JSON string.');
  };
  const scanValue = (): void => {
    skipWhitespace();
    const initial = text[cursor];
    if (initial === '{') {
      cursor += 1;
      skipWhitespace();
      const keys = new Set<string>();
      if (text[cursor] === '}') {
        cursor += 1;
        return;
      }
      while (true) {
        skipWhitespace();
        const key = readString();
        if (keys.has(key)) throw new SyntaxError('Duplicate JSON object key.');
        keys.add(key);
        skipWhitespace();
        if (text[cursor] !== ':') throw new SyntaxError('Expected a JSON property value.');
        cursor += 1;
        scanValue();
        skipWhitespace();
        if (text[cursor] === '}') {
          cursor += 1;
          return;
        }
        if (text[cursor] !== ',') throw new SyntaxError('Expected another JSON property.');
        cursor += 1;
      }
    }
    if (initial === '[') {
      cursor += 1;
      skipWhitespace();
      if (text[cursor] === ']') {
        cursor += 1;
        return;
      }
      while (true) {
        scanValue();
        skipWhitespace();
        if (text[cursor] === ']') {
          cursor += 1;
          return;
        }
        if (text[cursor] !== ',') throw new SyntaxError('Expected another JSON value.');
        cursor += 1;
      }
    }
    if (initial === '"') {
      readString();
      return;
    }
    const start = cursor;
    while (
      cursor < text.length &&
      !whitespace(text[cursor] ?? '') &&
      text[cursor] !== ',' &&
      text[cursor] !== ']' &&
      text[cursor] !== '}'
    ) {
      cursor += 1;
    }
    if (start === cursor) throw new SyntaxError('Expected a JSON value.');
  };

  scanValue();
  skipWhitespace();
  if (cursor !== text.length) throw new SyntaxError('Unexpected JSON input.');
  return JSON.parse(text) as unknown;
}

function jsonResponse(value: unknown, status = 200, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(extraHeaders);
  headers.set('Cache-Control', 'no-store');
  headers.set('Content-Type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(value), {
    status,
    headers,
  });
}
