import { ownershipProofV1Schema } from '@nexus/protocol';

import type {
  NoteDraft,
  NoteVisibility,
  SessionOperationInput,
  StartSessionOperation,
  SubmitProofInput,
} from '../src/shared/contracts';
import { RpWorkerError } from './errors';

export function parseSubmitProof(value: unknown): SubmitProofInput {
  const record = requireRecord(value, ['challengeId', 'operation', 'proof']);
  if (typeof record['challengeId'] !== 'string' || record['challengeId'].length < 20) {
    throw badRequest('challengeId is invalid.');
  }
  const proof = ownershipProofV1Schema.safeParse(record['proof']);
  if (!proof.success) throw badRequest('proof is invalid.');
  return {
    challengeId: record['challengeId'],
    operation: parseStartSessionOperation(record['operation']),
    proof: proof.data,
  };
}

export function parseStartSessionOperation(value: unknown): StartSessionOperation {
  const record = requireRecord(value, ['action']);
  if (record['action'] !== 'session.start') {
    throw badRequest('Only an explicit session.start proof is accepted.');
  }
  return { action: 'session.start' };
}

export function parseSessionOperation(value: unknown): SessionOperationInput {
  if (!isRecord(value) || typeof value['action'] !== 'string') {
    throw badRequest('A note session action is required.');
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
  throw badRequest('The requested note session action is unsupported.');
}

function parseFriendlyName(value: unknown): string {
  const name = typeof value === 'string' ? value.trim() : '';
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{2,23}$/u.test(name) || name.toLowerCase().startsWith('nx1_')) {
    throw badRequest(
      'Friendly name must be 3–24 letters, numbers, underscores, or hyphens and cannot start with nx1_.',
    );
  }
  return name;
}

export function parseNoteId(value: unknown): string {
  if (typeof value !== 'string' || !/^nt_[A-Za-z0-9_-]{3,80}$/u.test(value)) {
    throw badRequest('noteId is invalid.');
  }
  return value;
}

function parseReplyId(value: unknown): string {
  if (typeof value !== 'string' || !/^rpy_[A-Za-z0-9_-]{12,80}$/u.test(value)) {
    throw badRequest('replyId is invalid.');
  }
  return value;
}

function parseDraft(value: unknown): NoteDraft {
  const record = requireRecord(value, ['body', 'title', 'visibility']);
  const title = typeof record['title'] === 'string' ? record['title'].trim() : '';
  const body = typeof record['body'] === 'string' ? record['body'].trim() : '';
  const visibility = parseVisibility(record['visibility']);
  if (title.length < 1 || title.length > 80) {
    throw badRequest('Note title must be between 1 and 80 characters.');
  }
  if (body.length < 1 || body.length > 4_000) {
    throw badRequest('Note body must be between 1 and 4,000 characters.');
  }
  return { title, body, visibility };
}

function parseVisibility(value: unknown): NoteVisibility {
  if (value !== 'public' && value !== 'private') {
    throw badRequest('visibility must be public or private.');
  }
  return value;
}

function parseReplyBody(value: unknown): string {
  const body = typeof value === 'string' ? value.trim() : '';
  if (body.length < 1 || body.length > 1_000) {
    throw badRequest('Reply body must be between 1 and 1,000 characters.');
  }
  return body;
}

function parseVersion(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw badRequest('expectedVersion must be a positive integer.');
  }
  return value as number;
}

function requireRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!isRecord(value)) throw badRequest('Request body must be an object.');
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw badRequest('Request contains missing or unknown fields.');
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function badRequest(message: string): RpWorkerError {
  return new RpWorkerError('BAD_REQUEST', message, 400);
}
