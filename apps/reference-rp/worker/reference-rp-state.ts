import { DurableObject } from 'cloudflare:workers';

import { audienceOriginSchema } from '@nexus/protocol';
import type { Base64Url32, NexusSubject, VerificationExpectation } from '@nexus/protocol';
import { verifyOwnershipProof } from '@nexus/verifier';

import type {
  ApplicationReceipt,
  IssueChallengeInput,
  IssuedChallenge,
  NoteView,
  OperationResult,
  RpSession,
  SessionStatus,
  SubmitOperationInput,
} from '../src/shared/contracts';
import { canonicalSha256, constantTimeTextEqual, secureToken, sha256Base64Url } from './crypto';
import { RpWorkerError, toSafeWorkerError } from './errors';
import { getAuthoritativeLifecycle, type LifecycleEnv } from './lifecycle';
import { parseNoteId, parseOperation, parseSubmitOperation } from './validation';

const CHALLENGE_TTL_SECONDS = 60;
const SESSION_TTL_SECONDS = 5 * 60;
const MAX_CLOCK_SKEW_SECONDS = 30;
const MAX_BODY_BYTES = 64 * 1024;
const MAX_OUTSTANDING_CHALLENGES = 512;
const MAX_TOTAL_CHALLENGES = 2_048;

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
  created_at: number;
  updated_at: number;
  version: number;
  accepted_proof_hash: string;
}

interface SessionRow extends Record<string, SqlStorageValue> {
  token_hash: string;
  subject: string;
  expires_at: number;
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
        return jsonResponse({ notes: this.#listNotes() });
      }
      if (request.method === 'GET' && url.pathname.startsWith('/api/notes/')) {
        let decoded: string;
        try {
          decoded = decodeURIComponent(url.pathname.slice('/api/notes/'.length));
        } catch {
          throw new RpWorkerError('BAD_REQUEST', 'noteId is invalid.', 400);
        }
        return jsonResponse({ note: this.#getNote(parseNoteId(decoded)) });
      }
      if (request.method === 'POST' && url.pathname === '/api/challenges') {
        const operation = parseOperation(await readStrictJson(request));
        return jsonResponse({ challenge: await this.#issueChallenge(operation) }, 201);
      }
      if (request.method === 'POST' && url.pathname === '/api/operations') {
        const input = parseSubmitOperation(await readStrictJson(request));
        return jsonResponse(await this.#submitOperation(input));
      }
      if (request.method === 'GET' && url.pathname === '/api/session') {
        const token = readSessionToken(request.headers.get('Authorization'));
        return jsonResponse({ session: await this.#getSession(token) });
      }
      throw new RpWorkerError('NOT_FOUND', 'API route not found.', 404);
    } catch (error) {
      const safe = toSafeWorkerError(error);
      return jsonResponse({ error: { code: safe.code, message: safe.message } }, safe.status);
    }
  }

  async #issueChallenge(operation: IssueChallengeInput): Promise<IssuedChallenge> {
    const now = nowSeconds();
    const { resource, contextHash } = await this.#operationBinding(operation, true);
    const nonce = secureToken(32);
    const challenge: IssuedChallenge = {
      challengeId: secureToken(16),
      action: operation.action,
      resource,
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

  async #submitOperation(input: SubmitOperationInput): Promise<OperationResult> {
    const initial = this.#readChallenge(input.challengeId);
    const initialNow = nowSeconds();
    this.#assertChallengeUsable(initial, initialNow);
    const { resource, contextHash } = await this.#operationBinding(
      input.operation,
      false,
      initial.resource,
    );
    if (
      initial.action !== input.operation.action ||
      initial.resource !== resource ||
      !constantTimeTextEqual(initial.context_hash, contextHash)
    ) {
      throw new RpWorkerError(
        'CHALLENGE_MISMATCH',
        'The note changed after this challenge was issued.',
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
        'The proof is not bound to this exact note change.',
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
    return this.#commitVerifiedOperation({
      input,
      expectedChallenge: initial,
      subject: verified.subject,
      proofHash,
      token,
      tokenHash,
      receiptId,
    });
  }

  #commitVerifiedOperation(prepared: {
    input: SubmitOperationInput;
    expectedChallenge: ChallengeRow;
    subject: NexusSubject;
    proofHash: string;
    token: string;
    tokenHash: string;
    receiptId: string;
  }): OperationResult {
    return this.ctx.storage.transactionSync<OperationResult>(() => {
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

      let note: NoteView | null;
      let resultingVersion: number | null;
      const operation = prepared.input.operation;
      if (operation.action === 'note.create') {
        const id = noteIdFromResource(currentChallenge.resource);
        if (this.#findNote(id) !== null) {
          throw new RpWorkerError(
            'VERSION_CONFLICT',
            'A note already exists for this resource.',
            409,
          );
        }
        this.ctx.storage.sql.exec(
          `INSERT INTO notes
            (id, resource, author_subject, title, body, created_at, updated_at, version, accepted_proof_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`,
          id,
          currentChallenge.resource,
          prepared.subject,
          operation.draft.title,
          operation.draft.body,
          now,
          now,
          prepared.proofHash,
        );
        note = this.#getNote(id);
        resultingVersion = 1;
      } else {
        const current = this.#requireNoteRow(operation.noteId);
        if (current.author_subject !== prepared.subject) {
          throw new RpWorkerError('AUTHOR_MISMATCH', 'This identity did not create the note.', 403);
        }
        if (current.version !== operation.expectedVersion) {
          throw new RpWorkerError(
            'VERSION_CONFLICT',
            'The note was updated in another view. Refresh and try again.',
            409,
          );
        }
        if (operation.action === 'note.delete') {
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
                SET title = ?, body = ?, updated_at = ?, version = version + 1,
                    accepted_proof_hash = ?
              WHERE id = ? AND version = ?`,
            operation.draft.title,
            operation.draft.body,
            now,
            prepared.proofHash,
            current.id,
            current.version,
          );
          note = this.#getNote(current.id);
          resultingVersion = current.version + 1;
        }
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
        operation: operation.action,
        resource: currentChallenge.resource,
        subject: prepared.subject,
        proofHash: prepared.proofHash,
        acceptedAt: now,
        resultingVersion,
      };
      this.ctx.storage.sql.exec(
        `INSERT INTO receipts
          (receipt_id, operation, resource, subject, proof_hash, accepted_at, resulting_version)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        receipt.receiptId,
        receipt.operation,
        receipt.resource,
        receipt.subject,
        receipt.proofHash,
        receipt.acceptedAt,
        receipt.resultingVersion,
      );

      const session: RpSession = {
        token: prepared.token,
        subject: prepared.subject,
        expiresAt: now + SESSION_TTL_SECONDS,
      };
      this.ctx.storage.sql.exec('DELETE FROM sessions WHERE expires_at <= ?', now);
      this.ctx.storage.sql.exec(
        'INSERT INTO sessions (token_hash, subject, expires_at) VALUES (?, ?, ?)',
        prepared.tokenHash,
        prepared.subject,
        session.expiresAt,
      );
      return { note, receipt, session };
    });
  }

  async #getSession(token: string): Promise<SessionStatus> {
    if (token.length < 20) {
      throw new RpWorkerError('SESSION_INVALID', 'The RP session is missing or invalid.', 401);
    }
    const tokenHash = await sha256Base64Url(token);
    const row = this.ctx.storage.sql
      .exec<SessionRow>(
        'SELECT token_hash, subject, expires_at FROM sessions WHERE token_hash = ?',
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
    return {
      subject,
      state: lifecycle.state,
      sequence: lifecycle.sequence,
      expiresAt: row.expires_at,
      checkedAt: now,
    };
  }

  async #operationBinding(
    operation: IssueChallengeInput,
    requireCurrentVersion: boolean,
    existingCreateResource?: string,
  ): Promise<{ resource: string; contextHash: string }> {
    if (operation.action === 'note.create') {
      return {
        resource: existingCreateResource ?? `note:nt_${secureToken(9)}`,
        contextHash: await canonicalSha256({ action: operation.action, draft: operation.draft }),
      };
    }
    const note = this.#requireNoteRow(operation.noteId);
    if (requireCurrentVersion && note.version !== operation.expectedVersion) {
      throw new RpWorkerError(
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
    return { resource: note.resource, contextHash: await canonicalSha256(context) };
  }

  #listNotes(): NoteView[] {
    return this.ctx.storage.sql
      .exec<NoteRow>(
        `SELECT id, resource, author_subject, title, body, created_at, updated_at,
                version, accepted_proof_hash
           FROM notes ORDER BY updated_at DESC, id`,
      )
      .toArray()
      .map(toNoteView);
  }

  #getNote(id: string): NoteView {
    return toNoteView(this.#requireNoteRow(id));
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
          `SELECT id, resource, author_subject, title, body, created_at, updated_at,
                  version, accepted_proof_hash
             FROM notes WHERE id = ?`,
          id,
        )
        .toArray()[0] ?? null
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
      INSERT OR IGNORE INTO schema_meta (singleton, version, seeded) VALUES (1, 1, 0);
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
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        version INTEGER NOT NULL CHECK (version >= 1),
        accepted_proof_hash TEXT NOT NULL
      );
      CREATE TRIGGER IF NOT EXISTS notes_immutable_identity
      BEFORE UPDATE OF id, resource, author_subject, created_at ON notes
      BEGIN
        SELECT RAISE(ABORT, 'immutable note identity');
      END;
      CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        subject TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions (expires_at);
      CREATE TABLE IF NOT EXISTS receipts (
        receipt_id TEXT PRIMARY KEY,
        operation TEXT NOT NULL,
        resource TEXT NOT NULL,
        subject TEXT NOT NULL,
        proof_hash TEXT NOT NULL,
        accepted_at INTEGER NOT NULL,
        resulting_version INTEGER
      );
    `);
    const version = this.ctx.storage.sql
      .exec<{ version: number }>('SELECT version FROM schema_meta WHERE singleton = 1')
      .one().version;
    if (version !== 1) throw new Error('Reference RP schema version is unsupported.');
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

function noteIdFromResource(resource: string): string {
  if (!resource.startsWith('note:')) {
    throw new RpWorkerError('INTERNAL_ERROR', 'Invalid note resource.', 500);
  }
  return resource.slice('note:'.length);
}

function toNoteView(note: NoteRow): NoteView {
  return {
    id: note.id,
    resource: note.resource,
    authorSubject: note.author_subject as NexusSubject,
    title: note.title,
    body: note.body,
    createdAt: note.created_at,
    updatedAt: note.updated_at,
    version: note.version,
    proofFingerprint: note.accepted_proof_hash.slice(0, 12),
  };
}

function readSessionToken(header: string | null): string {
  if (header === null || !header.startsWith('NexusSession ')) return '';
  const token = header.slice('NexusSession '.length);
  return token.includes(' ') ? '' : token;
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

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'application/json; charset=utf-8',
    },
  });
}
