import type { NexusSubject, OwnershipProofV1, ProofRequest } from '@nexus/protocol';

export type NoteAction = 'note.create' | 'note.edit' | 'note.delete';

export interface NoteDraft {
  title: string;
  body: string;
}

export interface NoteView {
  id: string;
  resource: string;
  authorSubject: NexusSubject;
  title: string;
  body: string;
  createdAt: number;
  updatedAt: number;
  version: number;
  proofFingerprint: string;
}

export type IssueChallengeInput =
  | { action: 'note.create'; draft: NoteDraft }
  | { action: 'note.edit'; noteId: string; expectedVersion: number; draft: NoteDraft }
  | { action: 'note.delete'; noteId: string; expectedVersion: number };

export interface IssuedChallenge extends ProofRequest {
  challengeId: string;
  expiresAt: number;
}

export interface SubmitOperationInput {
  challengeId: string;
  proof: OwnershipProofV1;
  operation: IssueChallengeInput;
}

export interface ApplicationReceipt {
  receiptId: string;
  operation: NoteAction;
  resource: string;
  subject: NexusSubject;
  proofHash: string;
  acceptedAt: number;
  resultingVersion: number | null;
}

export interface RpSession {
  token: string;
  subject: NexusSubject;
  expiresAt: number;
}

export interface OperationResult {
  note: NoteView | null;
  receipt: ApplicationReceipt;
  session: RpSession;
}

export interface SessionStatus {
  subject: NexusSubject;
  state: 'active' | 'revoked';
  sequence: number;
  expiresAt: number;
  checkedAt: number;
}

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
  };
}
