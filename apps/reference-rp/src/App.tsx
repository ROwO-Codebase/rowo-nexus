import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { FormEvent, MouseEvent as ReactMouseEvent } from 'react';

import type { ProofRequest } from '@nexus/protocol';
import { createNexusClient, NexusClientError } from '@nexus/sdk-browser';
import {
  AlertTriangle,
  ArrowLeft,
  BadgeCheck,
  BookOpenText,
  Check,
  CheckCircle2,
  ChevronRight,
  Circle,
  Copy,
  FileKey2,
  Fingerprint,
  Info,
  KeyRound,
  Loader2,
  LockKeyhole,
  PenLine,
  Plus,
  ReceiptText,
  RefreshCw,
  ShieldCheck,
  Trash2,
  UserRoundX,
  X,
  XCircle,
} from 'lucide-react';
import { motion } from 'motion/react';

import {
  ReferenceRpApiError,
  getSession,
  issueChallenge,
  listNotes,
  submitOperation,
} from './api.js';
import type {
  ApplicationReceipt,
  IssueChallengeInput,
  NoteDraft,
  NoteView,
  SessionStatus,
} from './shared/contracts.js';

const walletUrl = import.meta.env.VITE_NEXUS_WALLET_URL ?? 'https://wallet.rowo.link';
const nexus = createNexusClient({
  walletUrl,
  allowInsecureLocalhost: import.meta.env.DEV,
});

type AppView = 'feed' | 'detail' | 'create' | 'edit' | 'security';
type ProofStage =
  'idle' | 'challenge' | 'wallet' | 'verifying' | 'approved' | 'cancelled' | 'error';

interface ProofFlow {
  stage: ProofStage;
  title: string;
  message: string;
  code?: string;
}

const IDLE_PROOF: ProofFlow = {
  stage: 'idle',
  title: 'Proof ready',
  message: 'Protected changes ask your Nexus wallet for a short-lived ownership proof.',
};

export function App(): React.ReactElement {
  const [notes, setNotes] = useState<NoteView[]>([]);
  const [selectedNote, setSelectedNote] = useState<NoteView | null>(null);
  const [view, setView] = useState<AppView>('feed');
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [proof, setProof] = useState<ProofFlow>(IDLE_PROOF);
  const [session, setSession] = useState<SessionStatus | null>(null);
  const [receipts, setReceipts] = useState<ApplicationReceipt[]>([]);
  const [deleteTarget, setDeleteTarget] = useState<NoteView | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const refreshNotes = useCallback(async (showLoading = true): Promise<NoteView[]> => {
    if (showLoading) setLoading(true);
    setLoadError(null);
    try {
      const next = await listNotes();
      setNotes(next);
      return next;
    } catch (error) {
      setLoadError(readErrorMessage(error));
      return [];
    } finally {
      if (showLoading) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshNotes();
  }, [refreshNotes]);

  const runProtectedOperation = useCallback(
    async (operation: IssueChallengeInput): Promise<void> => {
      const controller = new AbortController();
      abortRef.current = controller;
      setProof({
        stage: 'challenge',
        title: 'Preparing one-time challenge',
        message: 'Binding the exact action, note, content, and this RP origin.',
      });
      try {
        const challenge = await issueChallenge(operation);
        const request: ProofRequest = {
          action: challenge.action,
          resource: challenge.resource,
          nonce: challenge.nonce,
          expiresAt: challenge.expiresAt,
          ...(challenge.contextHash === undefined ? {} : { contextHash: challenge.contextHash }),
        };

        setProof({
          stage: 'wallet',
          title: 'Waiting for your approval',
          message: 'Review the origin, action, and resource in the Nexus wallet popup.',
        });
        const result = await nexus.requestProof(request, { signal: controller.signal });

        setProof({
          stage: 'verifying',
          title: 'Verifying proof',
          message: 'Checking signature, live identity status, and one-time challenge use.',
        });
        const operationResult = await submitOperation({
          challengeId: challenge.challengeId,
          proof: result.proof,
          operation,
        });
        setReceipts((current) => [operationResult.receipt, ...current].slice(0, 4));

        try {
          setSession(await getSession(operationResult.session.token));
        } catch {
          setSession({
            subject: operationResult.session.subject,
            state: 'active',
            sequence: 0,
            expiresAt: operationResult.session.expiresAt,
            checkedAt: Math.floor(Date.now() / 1000),
          });
        }

        setProof({
          stage: 'approved',
          title: 'Proof approved',
          message: `Receipt ${shortReceipt(operationResult.receipt.receiptId)} records the accepted proof hash.`,
        });
        const refreshed = await refreshNotes(false);
        if (operationResult.note === null) {
          setSelectedNote(null);
          setView('feed');
        } else {
          const current = refreshed.find((note) => note.id === operationResult.note?.id);
          setSelectedNote(current ?? operationResult.note);
          setView('detail');
        }
      } catch (error) {
        if (
          error instanceof NexusClientError &&
          (error.code === 'USER_CANCELLED' || error.code === 'POPUP_CLOSED')
        ) {
          setProof({
            stage: 'cancelled',
            title: 'Approval cancelled',
            message: 'Nothing was changed and the challenge will expire automatically.',
            code: error.code,
          });
        } else {
          setProof({
            stage: 'error',
            title: 'Proof rejected',
            message: readErrorMessage(error),
            code: readErrorCode(error),
          });
        }
      } finally {
        abortRef.current = null;
      }
    },
    [refreshNotes],
  );

  const isBusy =
    proof.stage === 'challenge' || proof.stage === 'wallet' || proof.stage === 'verifying';
  const ownNoteCount = useMemo(
    () => notes.filter((note) => note.authorSubject === session?.subject).length,
    [notes, session?.subject],
  );

  const openFeed = (): void => {
    setView('feed');
    setSelectedNote(null);
  };

  const openNote = (note: NoteView): void => {
    setSelectedNote(note);
    setView('detail');
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <Header
        view={view}
        onNotes={openFeed}
        onSecurity={() => setView('security')}
        onCreate={() => {
          setProof(IDLE_PROOF);
          setView('create');
        }}
      />

      <main className="mx-auto w-full max-w-6xl px-4 py-6 sm:px-6 sm:py-8 lg:px-8">
        <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-indigo-100 bg-indigo-50 px-3 py-1 text-xs font-medium text-indigo-700">
              <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
              Anonymous by design · proof-gated by Nexus
            </div>
            <h1 className="text-2xl font-semibold tracking-tight text-slate-950 sm:text-3xl">
              {view === 'security' ? 'How ownership stays private' : 'Notes without accounts'}
            </h1>
            <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-500">
              {view === 'security'
                ? 'The app can verify who controls a note without learning a real name or creating a Nexus account record.'
                : 'A small anonymous publishing demo where a cryptographic subject—not a user profile—owns each note.'}
            </p>
          </div>
          {view !== 'security' && view !== 'create' ? (
            <button
              type="button"
              onClick={() => {
                setProof(IDLE_PROOF);
                setView('create');
              }}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-indigo-700 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
            >
              <Plus className="h-4 w-4" aria-hidden="true" />
              Write a note
            </button>
          ) : null}
        </div>

        {view === 'security' ? (
          <SecurityView />
        ) : (
          <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
            <section className="min-w-0" aria-label="Anonymous notes">
              <>
                {view === 'feed' ? (
                  <FeedView
                    key="feed"
                    notes={notes}
                    loading={loading}
                    error={loadError}
                    session={session}
                    onOpen={openNote}
                    onRetry={() => void refreshNotes()}
                  />
                ) : null}
                {view === 'detail' && selectedNote !== null ? (
                  <DetailView
                    key={selectedNote.id}
                    note={selectedNote}
                    owned={selectedNote.authorSubject === session?.subject}
                    busy={isBusy}
                    onBack={openFeed}
                    onEdit={() => setView('edit')}
                    onDelete={() => setDeleteTarget(selectedNote)}
                  />
                ) : null}
                {view === 'create' ? (
                  <Composer
                    key="create"
                    title="Write anonymously"
                    description="Your wallet will choose a local identity and approve a proof for this exact content."
                    submitLabel="Continue with Nexus"
                    busy={isBusy}
                    onCancel={openFeed}
                    onSubmit={(draft) =>
                      void runProtectedOperation({ action: 'note.create', draft })
                    }
                  />
                ) : null}
                {view === 'edit' && selectedNote !== null ? (
                  <Composer
                    key={`edit-${selectedNote.id}`}
                    title="Edit note"
                    description="Only the immutable author subject can approve this update."
                    submitLabel="Prove & save"
                    initial={selectedNote}
                    busy={isBusy}
                    onCancel={() => setView('detail')}
                    onSubmit={(draft) =>
                      void runProtectedOperation({
                        action: 'note.edit',
                        noteId: selectedNote.id,
                        expectedVersion: selectedNote.version,
                        draft,
                      })
                    }
                  />
                ) : null}
              </>
            </section>

            <aside className="space-y-4 lg:sticky lg:top-24" aria-label="Nexus proof status">
              <IdentityCard session={session} ownNoteCount={ownNoteCount} />
              <ProofCard
                flow={proof}
                onCancel={() => abortRef.current?.abort()}
                onDismiss={() => setProof(IDLE_PROOF)}
              />
              <ReceiptCard receipts={receipts} />
            </aside>
          </div>
        )}
      </main>

      <Footer />

      {deleteTarget !== null ? (
        <DeleteDialog
          note={deleteTarget}
          busy={isBusy}
          onCancel={() => setDeleteTarget(null)}
          onConfirm={() => {
            const target = deleteTarget;
            setDeleteTarget(null);
            void runProtectedOperation({
              action: 'note.delete',
              noteId: target.id,
              expectedVersion: target.version,
            });
          }}
        />
      ) : null}
    </div>
  );
}

function Header({
  view,
  onNotes,
  onSecurity,
  onCreate,
}: {
  view: AppView;
  onNotes: () => void;
  onSecurity: () => void;
  onCreate: () => void;
}): React.ReactElement {
  return (
    <header className="sticky top-0 z-30 border-b border-slate-200/90 bg-white/95 backdrop-blur">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <button
          type="button"
          onClick={onNotes}
          className="flex items-center gap-2.5 rounded-xl text-left"
        >
          <img src="/logo.png" alt="" className="h-8 w-8 rounded-xl object-cover" />
          <div className="leading-none">
            <div className="text-[11px] font-medium uppercase tracking-[0.16em] text-indigo-600">
              ROwO Nexus
            </div>
            <div className="mt-1 text-sm font-semibold tracking-tight text-slate-800">Notes</div>
          </div>
        </button>

        <nav className="flex items-center gap-1" aria-label="Primary navigation">
          <button
            type="button"
            onClick={onNotes}
            className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
              view !== 'security'
                ? 'bg-indigo-50 text-indigo-700'
                : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
            }`}
          >
            <BookOpenText className="h-4 w-4" aria-hidden="true" />
            <span className="hidden sm:inline">Notes</span>
          </button>
          <button
            type="button"
            onClick={onSecurity}
            className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
              view === 'security'
                ? 'bg-indigo-50 text-indigo-700'
                : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
            }`}
          >
            <ShieldCheck className="h-4 w-4" aria-hidden="true" />
            <span className="hidden sm:inline">Security</span>
          </button>
          <button
            type="button"
            onClick={onCreate}
            aria-label="Write a note"
            className="ml-1 rounded-lg bg-indigo-600 p-2 text-white transition-colors hover:bg-indigo-700 sm:hidden"
          >
            <Plus className="h-4 w-4" />
          </button>
        </nav>
      </div>
    </header>
  );
}

function FeedView({
  notes,
  loading,
  error,
  session,
  onOpen,
  onRetry,
}: {
  notes: NoteView[];
  loading: boolean;
  error: string | null;
  session: SessionStatus | null;
  onOpen: (note: NoteView) => void;
  onRetry: () => void;
}): React.ReactElement {
  if (loading) {
    return (
      <div className="rounded-3xl border border-slate-200 bg-white p-10 text-center shadow-sm">
        <Loader2 className="mx-auto h-5 w-5 animate-spin text-indigo-600" />
        <p className="mt-3 text-sm text-slate-500">Opening the notebook…</p>
      </div>
    );
  }
  if (error !== null) {
    return (
      <EmptyState
        icon={AlertTriangle}
        title="Notes are unavailable"
        body={error}
        action="Try again"
        onAction={onRetry}
      />
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 5 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -4 }}
      transition={{ duration: 0.18 }}
      className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-sm"
    >
      <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4 sm:px-6">
        <div>
          <h2 className="text-sm font-semibold text-slate-900">Public notebook</h2>
          <p className="mt-0.5 text-xs text-slate-500">{notes.length} proof-backed notes</p>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-medium text-emerald-700">
          <Circle className="h-2 w-2 fill-current" aria-hidden="true" />
          Live demo
        </span>
      </div>
      <div className="divide-y divide-slate-100">
        {notes.map((note) => {
          const owned = note.authorSubject === session?.subject;
          return (
            <button
              type="button"
              key={note.id}
              onClick={() => onOpen(note)}
              className="group block w-full px-5 py-5 text-left transition-colors hover:bg-slate-50/80 focus-visible:bg-indigo-50/60 focus-visible:outline-none sm:px-6"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="mb-2 flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[11px] text-slate-400">
                      {shortSubject(note.authorSubject)}
                    </span>
                    {owned ? (
                      <span className="rounded-full bg-indigo-50 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-indigo-700">
                        Yours
                      </span>
                    ) : null}
                  </div>
                  <h3 className="text-base font-semibold tracking-tight text-slate-900 group-hover:text-indigo-700">
                    {note.title}
                  </h3>
                  <p className="mt-2 line-clamp-2 max-w-2xl text-sm leading-6 text-slate-600">
                    {note.body}
                  </p>
                  <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
                    <span>{relativeTime(note.updatedAt)}</span>
                    <span className="inline-flex items-center gap-1">
                      <BadgeCheck className="h-3.5 w-3.5 text-emerald-500" aria-hidden="true" />
                      proof {note.proofFingerprint}
                    </span>
                  </div>
                </div>
                <ChevronRight className="mt-7 h-4 w-4 shrink-0 text-slate-300 transition-transform group-hover:translate-x-0.5 group-hover:text-indigo-500" />
              </div>
            </button>
          );
        })}
      </div>
    </motion.div>
  );
}

function DetailView({
  note,
  owned,
  busy,
  onBack,
  onEdit,
  onDelete,
}: {
  note: NoteView;
  owned: boolean;
  busy: boolean;
  onBack: () => void;
  onEdit: () => void;
  onDelete: () => void;
}): React.ReactElement {
  return (
    <motion.article
      initial={{ opacity: 0, y: 5 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -4 }}
      transition={{ duration: 0.18 }}
      className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm sm:p-8"
    >
      <button
        type="button"
        onClick={onBack}
        className="mb-7 inline-flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-xs font-medium text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-800"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        All notes
      </button>
      <div className="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <span className="rounded-full bg-slate-100 px-2.5 py-1 font-mono text-[11px] text-slate-600">
              {shortSubject(note.authorSubject)}
            </span>
            {owned ? (
              <span className="inline-flex items-center gap-1 rounded-full bg-indigo-50 px-2.5 py-1 text-[11px] font-medium text-indigo-700">
                <Check className="h-3 w-3" /> Your current subject
              </span>
            ) : null}
          </div>
          <h2 className="text-2xl font-semibold tracking-tight text-slate-950 sm:text-3xl">
            {note.title}
          </h2>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <button
            type="button"
            onClick={onEdit}
            disabled={busy}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3.5 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-50 disabled:opacity-50"
          >
            <PenLine className="h-4 w-4" /> Edit
          </button>
          <button
            type="button"
            onClick={onDelete}
            disabled={busy}
            className="inline-flex items-center gap-2 rounded-xl border border-red-100 bg-red-50 px-3.5 py-2 text-sm font-medium text-red-700 transition-colors hover:bg-red-100 disabled:opacity-50"
          >
            <Trash2 className="h-4 w-4" /> Delete
          </button>
        </div>
      </div>

      <p className="mt-8 whitespace-pre-wrap text-[15px] leading-7 text-slate-700">{note.body}</p>

      <div className="mt-10 grid gap-3 border-t border-slate-100 pt-5 text-xs sm:grid-cols-3">
        <Meta label="Created" value={formatDate(note.createdAt)} />
        <Meta label="Resource" value={note.resource} mono />
        <Meta label="Accepted proof" value={note.proofFingerprint} mono />
      </div>
      {!owned ? (
        <div className="mt-6 flex items-start gap-2.5 rounded-2xl border border-amber-100 bg-amber-50 p-4 text-sm leading-5 text-amber-900">
          <KeyRound className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
          <p>Editing is allowed only when the wallet proves the same immutable author subject.</p>
        </div>
      ) : null}
    </motion.article>
  );
}

function Composer({
  title,
  description,
  submitLabel,
  initial,
  busy,
  onCancel,
  onSubmit,
}: {
  title: string;
  description: string;
  submitLabel: string;
  initial?: NoteView;
  busy: boolean;
  onCancel: () => void;
  onSubmit: (draft: NoteDraft) => void;
}): React.ReactElement {
  const [noteTitle, setNoteTitle] = useState(initial?.title ?? '');
  const [body, setBody] = useState(initial?.body ?? '');

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const draft = { title: noteTitle.trim(), body: body.trim() };
    if (draft.title.length > 0 && draft.body.length > 0) onSubmit(draft);
  };

  return (
    <motion.form
      initial={{ opacity: 0, y: 5 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -4 }}
      transition={{ duration: 0.18 }}
      onSubmit={submit}
      className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm sm:p-8"
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold tracking-tight text-slate-950">{title}</h2>
          <p className="mt-1 text-sm leading-6 text-slate-500">{description}</p>
        </div>
        <button
          type="button"
          onClick={onCancel}
          disabled={busy}
          aria-label="Close editor"
          className="rounded-lg p-2 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-700 disabled:opacity-50"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="mt-7 space-y-5">
        <label className="block">
          <span className="mb-1.5 block text-xs font-medium text-slate-700">Title</span>
          <input
            value={noteTitle}
            onChange={(event) => setNoteTitle(event.target.value)}
            maxLength={80}
            required
            autoFocus
            placeholder="A small observation"
            className="block w-full rounded-xl border border-slate-300 bg-white px-4 py-3 text-sm text-slate-900 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100"
          />
          <span className="mt-1 block text-right text-[11px] text-slate-400">
            {noteTitle.length}/80
          </span>
        </label>
        <label className="block">
          <span className="mb-1.5 block text-xs font-medium text-slate-700">Note</span>
          <textarea
            value={body}
            onChange={(event) => setBody(event.target.value)}
            maxLength={4_000}
            required
            rows={10}
            placeholder="Write what should remain…"
            className="block w-full resize-y rounded-xl border border-slate-300 bg-white px-4 py-3 text-sm leading-6 text-slate-900 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100"
          />
          <span className="mt-1 block text-right text-[11px] text-slate-400">
            {body.length}/4,000
          </span>
        </label>
      </div>

      <div className="mt-6 flex flex-col-reverse gap-2 border-t border-slate-100 pt-5 sm:flex-row sm:justify-end">
        <button
          type="button"
          onClick={onCancel}
          disabled={busy}
          className="rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-50 disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={busy || noteTitle.trim().length === 0 || body.trim().length === 0}
          className="inline-flex items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-indigo-300"
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
          {busy ? 'Waiting for proof…' : submitLabel}
        </button>
      </div>
    </motion.form>
  );
}

function IdentityCard({
  session,
  ownNoteCount,
}: {
  session: SessionStatus | null;
  ownNoteCount: number;
}): React.ReactElement {
  const [copied, setCopied] = useState(false);
  const copySubject = (): void => {
    if (session === null) return;
    void navigator.clipboard.writeText(session.subject).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1_500);
    });
  };

  return (
    <div className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Fingerprint className="h-4 w-4 text-indigo-600" />
          <h2 className="text-sm font-semibold text-slate-900">Identity status</h2>
        </div>
        <span
          className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-medium ${
            session === null
              ? 'bg-slate-100 text-slate-600'
              : session.state === 'active'
                ? 'bg-emerald-50 text-emerald-700'
                : 'bg-red-50 text-red-700'
          }`}
        >
          <Circle className="h-2 w-2 fill-current" />
          {session === null ? 'Not proven' : session.state === 'active' ? 'Active' : 'Revoked'}
        </span>
      </div>

      {session === null ? (
        <div className="mt-5 rounded-2xl border border-dashed border-slate-200 bg-slate-50 p-4 text-center">
          <UserRoundX className="mx-auto h-5 w-5 text-slate-400" />
          <p className="mt-2 text-xs leading-5 text-slate-500">
            There is no sign-in. Your subject appears here only after an approved proof.
          </p>
        </div>
      ) : (
        <div className="mt-5">
          <div className="rounded-2xl bg-slate-950 p-4 text-white">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-slate-400">
                Current subject
              </span>
              <button
                type="button"
                onClick={copySubject}
                className="rounded-md p-1 text-slate-400 transition hover:bg-white/10 hover:text-white"
                aria-label="Copy subject"
              >
                {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              </button>
            </div>
            <p className="mt-2 truncate font-mono text-xs text-slate-200">{session.subject}</p>
          </div>
          <div className="mt-3 grid grid-cols-2 gap-2">
            <MiniStat label="Notes" value={String(ownNoteCount)} />
            <MiniStat label="Session" value={expiresIn(session.expiresAt)} />
          </div>
          <p className="mt-3 text-[11px] leading-4 text-slate-400">
            Status checked against the lifecycle authority · sequence {session.sequence}
          </p>
        </div>
      )}
    </div>
  );
}

function ProofCard({
  flow,
  onCancel,
  onDismiss,
}: {
  flow: ProofFlow;
  onCancel: () => void;
  onDismiss: () => void;
}): React.ReactElement {
  const busy = flow.stage === 'challenge' || flow.stage === 'wallet' || flow.stage === 'verifying';
  const tone = proofTone(flow.stage);
  return (
    <div className={`rounded-3xl border bg-white p-5 shadow-sm ${tone.border}`} aria-live="polite">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <LockKeyhole className={`h-4 w-4 ${tone.icon}`} />
          <h2 className="text-sm font-semibold text-slate-900">Nexus proof</h2>
        </div>
        {flow.stage !== 'idle' && !busy ? (
          <button
            type="button"
            onClick={onDismiss}
            className="rounded-lg p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
            aria-label="Dismiss proof status"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        ) : null}
      </div>
      <div className={`mt-4 rounded-2xl p-4 ${tone.panel}`}>
        <div className="flex items-start gap-3">
          <ProofStageIcon stage={flow.stage} className={`mt-0.5 h-4 w-4 shrink-0 ${tone.icon}`} />
          <div className="min-w-0">
            <h3 className="text-xs font-semibold text-slate-900">{flow.title}</h3>
            <p className="mt-1 text-xs leading-5 text-slate-600">{flow.message}</p>
            {flow.code !== undefined ? (
              <p className="mt-2 font-mono text-[10px] uppercase tracking-wide text-slate-400">
                {flow.code}
              </p>
            ) : null}
          </div>
        </div>
      </div>
      {busy ? (
        <button
          type="button"
          onClick={onCancel}
          className="mt-3 w-full rounded-xl border border-slate-200 px-3 py-2 text-xs font-medium text-slate-600 transition-colors hover:bg-slate-50"
        >
          Cancel request
        </button>
      ) : null}
      <div className="mt-4 grid grid-cols-3 gap-1" aria-hidden="true">
        {['Challenge', 'Approve', 'Verify'].map((label, index) => (
          <div key={label} className="text-center">
            <div
              className={`mx-auto h-1 rounded-full ${proofProgress(flow.stage, index) ? 'bg-indigo-500' : 'bg-slate-100'}`}
            />
            <span className="mt-1.5 block text-[9px] uppercase tracking-wide text-slate-400">
              {label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ReceiptCard({ receipts }: { receipts: ApplicationReceipt[] }): React.ReactElement {
  return (
    <div className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex items-center gap-2">
        <ReceiptText className="h-4 w-4 text-indigo-600" />
        <h2 className="text-sm font-semibold text-slate-900">Acceptance receipts</h2>
      </div>
      {receipts.length === 0 ? (
        <p className="mt-3 text-xs leading-5 text-slate-500">
          Successful changes produce an app receipt containing a proof hash, never the raw proof.
        </p>
      ) : (
        <div className="mt-3 space-y-2">
          {receipts.map((receipt) => (
            <div
              key={receipt.receiptId}
              className="rounded-xl border border-slate-100 bg-slate-50 px-3 py-2.5"
            >
              <div className="flex items-center justify-between gap-3">
                <span className="text-[11px] font-medium text-slate-700">
                  {receiptLabel(receipt.operation)}
                </span>
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
              </div>
              <p className="mt-1 truncate font-mono text-[10px] text-slate-400">
                {shortReceipt(receipt.receiptId)}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SecurityView(): React.ReactElement {
  const steps = [
    {
      icon: FileKey2,
      title: '1. Challenge',
      body: 'The RP creates 256 random bits and stores only its SHA-256 hash.',
    },
    {
      icon: KeyRound,
      title: '2. Wallet approval',
      body: 'The popup shows the real origin, exact action, resource, and content binding.',
    },
    {
      icon: ShieldCheck,
      title: '3. Verification',
      body: 'Signature and self-certifying subject are checked with @nexus/verifier.',
    },
    {
      icon: ReceiptText,
      title: '4. Atomic acceptance',
      body: 'Lifecycle is checked, the nonce is consumed once, then the mutation and receipt land.',
    },
  ];
  return (
    <motion.div
      initial={{ opacity: 0, y: 5 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.18 }}
    >
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {steps.map(({ icon: Icon, title, body }) => (
          <div key={title} className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-50 text-indigo-600">
              <Icon className="h-4 w-4" />
            </div>
            <h2 className="mt-4 text-sm font-semibold text-slate-900">{title}</h2>
            <p className="mt-1.5 text-xs leading-5 text-slate-500">{body}</p>
          </div>
        ))}
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm sm:p-8">
          <div className="flex items-center gap-2">
            <Fingerprint className="h-5 w-5 text-indigo-600" />
            <h2 className="text-lg font-semibold text-slate-900">What this app stores</h2>
          </div>
          <div className="mt-5 space-y-3">
            <StorageRow
              allowed
              label="Immutable author_subject"
              detail="A self-certifying nx1_ subject on each note."
            />
            <StorageRow
              allowed
              label="Proof hash"
              detail="Enough to identify the accepted proof without retaining it."
            />
            <StorageRow
              allowed
              label="Hashed nonce & session token"
              detail="Raw challenge and session secrets are not persisted."
            />
            <StorageRow
              label="No user or controller table"
              detail="No email, phone, wallet installation ID, or civil identity mapping."
            />
            <StorageRow
              label="No raw ownership proof"
              detail="The proof is verified in memory and replaced by its hash."
            />
          </div>
        </div>

        <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm sm:p-8">
          <div className="flex items-center gap-2">
            <LockKeyhole className="h-5 w-5 text-indigo-600" />
            <h2 className="text-lg font-semibold text-slate-900">Every proof is narrowly bound</h2>
          </div>
          <div className="mt-5 overflow-hidden rounded-2xl border border-slate-200">
            <BindingRow label="Audience" value="Exact configured HTTPS origin" />
            <BindingRow label="Action" value="note.create / edit / delete" />
            <BindingRow label="Resource" value="One provisional or existing note" />
            <BindingRow label="Context" value="SHA-256 of content + version" />
            <BindingRow label="Lifetime" value="60 seconds, single-use" />
            <BindingRow label="Lifecycle" value="Authoritative active status" />
          </div>
          <div className="mt-5 flex items-start gap-2.5 rounded-2xl border border-amber-100 bg-amber-50 p-4 text-xs leading-5 text-amber-900">
            <Info className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
            <p>
              Pseudonymity is not network anonymity. The browser, host, and network can still expose
              metadata such as timing or IP address.
            </p>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

function DeleteDialog({
  note,
  busy,
  onCancel,
  onConfirm,
}: {
  note: NoteView;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}): React.ReactElement {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/40 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="delete-title"
      onMouseDown={(event: ReactMouseEvent<HTMLDivElement>) => {
        if (event.target === event.currentTarget && !busy) onCancel();
      }}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.98, y: 8 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.98, y: 8 }}
        transition={{ duration: 0.16 }}
        className="w-full max-w-md rounded-3xl border border-slate-200 bg-white p-6 shadow-xl"
      >
        <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-red-50 text-red-600">
          <Trash2 className="h-5 w-5" />
        </div>
        <h2 id="delete-title" className="mt-4 text-lg font-semibold text-slate-950">
          Delete this note?
        </h2>
        <p className="mt-2 text-sm leading-6 text-slate-600">
          “{note.title}” will be removed only after the wallet proves the original author subject.
        </p>
        <div className="mt-6 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            Keep note
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={busy}
            className="inline-flex items-center gap-2 rounded-xl bg-red-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
          >
            <KeyRound className="h-4 w-4" /> Prove & delete
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}

function Footer(): React.ReactElement {
  return (
    <footer className="mt-10 border-t border-slate-200 bg-white">
      <div className="mx-auto flex max-w-6xl flex-col gap-2 px-4 py-6 text-xs text-slate-400 sm:flex-row sm:items-center sm:justify-between sm:px-6 lg:px-8">
        <span>ROwO Nexus reference relying party · anonymous notes demo</span>
        <span>Proof of control, not proof of personhood.</span>
      </div>
    </footer>
  );
}

function EmptyState({
  icon: Icon,
  title,
  body,
  action,
  onAction,
}: {
  icon: typeof AlertTriangle;
  title: string;
  body: string;
  action: string;
  onAction: () => void;
}): React.ReactElement {
  return (
    <div className="rounded-3xl border border-slate-200 bg-white p-10 text-center shadow-sm">
      <div className="mx-auto flex h-10 w-10 items-center justify-center rounded-2xl bg-red-50 text-red-600">
        <Icon className="h-5 w-5" />
      </div>
      <h2 className="mt-4 text-sm font-semibold text-slate-900">{title}</h2>
      <p className="mx-auto mt-1 max-w-md text-xs leading-5 text-slate-500">{body}</p>
      <button
        type="button"
        onClick={onAction}
        className="mt-5 inline-flex items-center gap-2 rounded-xl border border-slate-200 px-3.5 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50"
      >
        <RefreshCw className="h-3.5 w-3.5" /> {action}
      </button>
    </div>
  );
}

function Meta({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}): React.ReactElement {
  return (
    <div className="min-w-0">
      <div className="text-[10px] font-medium uppercase tracking-[0.12em] text-slate-400">
        {label}
      </div>
      <div className={`mt-1 truncate text-slate-600 ${mono ? 'font-mono' : ''}`}>{value}</div>
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: string }): React.ReactElement {
  return (
    <div className="rounded-xl border border-slate-100 bg-slate-50 p-2.5">
      <div className="text-[9px] font-medium uppercase tracking-wide text-slate-400">{label}</div>
      <div className="mt-0.5 text-xs font-semibold text-slate-700">{value}</div>
    </div>
  );
}

function StorageRow({
  allowed = false,
  label,
  detail,
}: {
  allowed?: boolean;
  label: string;
  detail: string;
}): React.ReactElement {
  return (
    <div className="flex items-start gap-3">
      <div
        className={`mt-0.5 rounded-full p-1 ${allowed ? 'bg-emerald-50 text-emerald-600' : 'bg-slate-100 text-slate-500'}`}
      >
        {allowed ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />}
      </div>
      <div>
        <h3 className="text-xs font-semibold text-slate-800">{label}</h3>
        <p className="mt-0.5 text-xs leading-5 text-slate-500">{detail}</p>
      </div>
    </div>
  );
}

function BindingRow({ label, value }: { label: string; value: string }): React.ReactElement {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-slate-100 px-4 py-3 text-xs last:border-b-0">
      <span className="font-medium text-slate-500">{label}</span>
      <span className="text-right text-slate-800">{value}</span>
    </div>
  );
}

function ProofStageIcon({
  stage,
  className,
}: {
  stage: ProofStage;
  className: string;
}): React.ReactElement {
  if (stage === 'challenge' || stage === 'wallet' || stage === 'verifying')
    return <Loader2 className={`${className} animate-spin`} />;
  if (stage === 'approved') return <CheckCircle2 className={className} />;
  if (stage === 'cancelled') return <XCircle className={className} />;
  if (stage === 'error') return <AlertTriangle className={className} />;
  return <ShieldCheck className={className} />;
}

function proofTone(stage: ProofStage): { border: string; icon: string; panel: string } {
  if (stage === 'approved')
    return { border: 'border-emerald-200', icon: 'text-emerald-600', panel: 'bg-emerald-50' };
  if (stage === 'error')
    return { border: 'border-red-200', icon: 'text-red-600', panel: 'bg-red-50' };
  if (stage === 'cancelled')
    return { border: 'border-amber-200', icon: 'text-amber-600', panel: 'bg-amber-50' };
  if (stage === 'idle')
    return { border: 'border-slate-200', icon: 'text-indigo-600', panel: 'bg-indigo-50/70' };
  return { border: 'border-indigo-200', icon: 'text-indigo-600', panel: 'bg-indigo-50' };
}

function proofProgress(stage: ProofStage, index: number): boolean {
  const progress: Record<ProofStage, number> = {
    idle: -1,
    challenge: 0,
    wallet: 1,
    verifying: 2,
    approved: 2,
    cancelled: 0,
    error: 1,
  };
  return index <= progress[stage];
}

function shortSubject(subject: string): string {
  return `${subject.slice(0, 11)}…${subject.slice(-6)}`;
}

function shortReceipt(receipt: string): string {
  return `${receipt.slice(0, 10)}…${receipt.slice(-6)}`;
}

function receiptLabel(action: ApplicationReceipt['operation']): string {
  if (action === 'note.create') return 'Note created';
  if (action === 'note.edit') return 'Note updated';
  return 'Note deleted';
}

function relativeTime(timestamp: number): string {
  const elapsed = Math.max(0, Math.floor(Date.now() / 1000) - timestamp);
  if (elapsed < 60) return 'just now';
  if (elapsed < 3_600) return `${Math.floor(elapsed / 60)}m ago`;
  if (elapsed < 86_400) return `${Math.floor(elapsed / 3_600)}h ago`;
  return `${Math.floor(elapsed / 86_400)}d ago`;
}

function formatDate(timestamp: number): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
    timestamp * 1_000,
  );
}

function expiresIn(timestamp: number): string {
  const seconds = Math.max(0, timestamp - Math.floor(Date.now() / 1000));
  return `${Math.max(1, Math.ceil(seconds / 60))} min`;
}

function readErrorCode(error: unknown): string {
  if (error instanceof NexusClientError || error instanceof ReferenceRpApiError) return error.code;
  return 'UNEXPECTED_ERROR';
}

function readErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return 'The request could not be completed.';
}
