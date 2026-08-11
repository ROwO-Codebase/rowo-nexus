import { ownershipProofV1Schema } from '@nexus/protocol';

import type { IssueChallengeInput, NoteDraft, SubmitOperationInput } from '../src/shared/contracts';
import { RpWorkerError } from './errors';

export function parseSubmitOperation(value: unknown): SubmitOperationInput {
  const record = requireRecord(value, ['challengeId', 'operation', 'proof']);
  if (typeof record['challengeId'] !== 'string' || record['challengeId'].length < 20) {
    throw badRequest('challengeId is invalid.');
  }
  const proof = ownershipProofV1Schema.safeParse(record['proof']);
  if (!proof.success) throw badRequest('proof is invalid.');
  return {
    challengeId: record['challengeId'],
    operation: parseOperation(record['operation']),
    proof: proof.data,
  };
}

export function parseOperation(value: unknown): IssueChallengeInput {
  if (!isRecord(value) || typeof value['action'] !== 'string') {
    throw badRequest('A note action is required.');
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
  throw badRequest('The requested note action is unsupported.');
}

export function parseNoteId(value: unknown): string {
  if (typeof value !== 'string' || !/^nt_[A-Za-z0-9_-]{3,80}$/u.test(value)) {
    throw badRequest('noteId is invalid.');
  }
  return value;
}

function parseDraft(value: unknown): NoteDraft {
  const record = requireRecord(value, ['body', 'title']);
  const title = typeof record['title'] === 'string' ? record['title'].trim() : '';
  const body = typeof record['body'] === 'string' ? record['body'].trim() : '';
  if (title.length < 1 || title.length > 80) {
    throw badRequest('Note title must be between 1 and 80 characters.');
  }
  if (body.length < 1 || body.length > 4_000) {
    throw badRequest('Note body must be between 1 and 4,000 characters.');
  }
  return { title, body };
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
