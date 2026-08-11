import type { NexusSubject, OwnershipProofV1, ProofRequest } from '@nexus/protocol';

export type NoteVisibility = 'public' | 'private';
export type AuthorizationMethod = 'wallet-proof' | 'rp-session';

export type ProofAction = 'session.start';
export type SessionAction =
  | 'note.create'
  | 'note.edit'
  | 'note.delete'
  | 'reply.create'
  | 'reply.delete'
  | 'note.like'
  | 'note.unlike'
  | 'profile.set-name';
export type NotesAction = ProofAction | SessionAction;

export interface NoteDraft {
  title: string;
  body: string;
  visibility: NoteVisibility;
}

export interface ReplyView {
  id: string;
  noteId: string;
  authorSubject: NexusSubject;
  authorFriendlyName: string | null;
  body: string;
  createdAt: number;
}

export interface NoteView {
  id: string;
  resource: string;
  authorSubject: NexusSubject;
  authorFriendlyName: string | null;
  title: string;
  body: string;
  visibility: NoteVisibility;
  createdAt: number;
  updatedAt: number;
  version: number;
  authorization: AuthorizationMethod;
  proofFingerprint: string;
  likeCount: number;
  likedByViewer: boolean;
  replies: ReplyView[];
}

export interface StartSessionOperation {
  action: ProofAction;
}

export interface IssuedChallenge extends ProofRequest {
  challengeId: string;
  expiresAt: number;
}

export interface SubmitProofInput {
  challengeId: string;
  proof: OwnershipProofV1;
  operation: StartSessionOperation;
}

export type SessionOperationInput =
  | { action: 'note.create'; draft: NoteDraft }
  | { action: 'note.edit'; noteId: string; expectedVersion: number; draft: NoteDraft }
  | { action: 'note.delete'; noteId: string; expectedVersion: number }
  | { action: 'reply.create'; noteId: string; body: string }
  | { action: 'reply.delete'; noteId: string; replyId: string }
  | { action: 'note.like'; noteId: string }
  | { action: 'note.unlike'; noteId: string }
  | { action: 'profile.set-name'; friendlyName: string };

export interface ApplicationReceipt {
  receiptId: string;
  operation: NotesAction;
  resource: string;
  subject: NexusSubject;
  authorization: AuthorizationMethod;
  proofHash: string;
  acceptedAt: number;
  resultingVersion: number | null;
}

export interface SessionStatus {
  subject: NexusSubject;
  friendlyName: string | null;
  state: 'active' | 'revoked';
  sequence: number;
  expiresAt: number;
  checkedAt: number;
}

export interface SessionStartResult {
  receipt: ApplicationReceipt;
  session: SessionStatus;
}

export interface SessionOperationResult {
  note: NoteView | null;
  receipt: ApplicationReceipt;
  session?: SessionStatus;
}

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
  };
}
