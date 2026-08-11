import type {
  IssueChallengeInput,
  IssuedChallenge,
  NoteView,
  OperationResult,
  SessionStatus,
  SubmitOperationInput,
} from './shared/contracts.js';

export class ReferenceRpApiError extends Error {
  public constructor(
    public readonly code: string,
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = 'ReferenceRpApiError';
  }
}

export async function listNotes(): Promise<NoteView[]> {
  const response = await apiRequest<{ notes: NoteView[] }>('/api/notes');
  return response.notes;
}

export async function getNote(id: string): Promise<NoteView> {
  const response = await apiRequest<{ note: NoteView }>(`/api/notes/${encodeURIComponent(id)}`);
  return response.note;
}

export async function issueChallenge(operation: IssueChallengeInput): Promise<IssuedChallenge> {
  const response = await apiRequest<{ challenge: IssuedChallenge }>('/api/challenges', {
    method: 'POST',
    body: JSON.stringify(operation),
  });
  return response.challenge;
}

export function submitOperation(input: SubmitOperationInput): Promise<OperationResult> {
  return apiRequest<OperationResult>('/api/operations', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function getSession(token: string): Promise<SessionStatus> {
  const response = await apiRequest<{ session: SessionStatus }>('/api/session', {
    headers: { Authorization: `NexusSession ${token}` },
  });
  return response.session;
}

async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, { ...init, headers, credentials: 'same-origin' });
  const payload = (await response.json()) as unknown;
  if (!response.ok) {
    const error = readApiError(payload);
    throw new ReferenceRpApiError(error.code, error.message, response.status);
  }
  return payload as T;
}

function readApiError(value: unknown): { code: string; message: string } {
  if (
    typeof value === 'object' &&
    value !== null &&
    'error' in value &&
    typeof value.error === 'object' &&
    value.error !== null &&
    'code' in value.error &&
    typeof value.error.code === 'string' &&
    'message' in value.error &&
    typeof value.error.message === 'string'
  ) {
    return { code: value.error.code, message: value.error.message };
  }
  return {
    code: 'REQUEST_FAILED',
    message: 'The reference service returned an unreadable response.',
  };
}
