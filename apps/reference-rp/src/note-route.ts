const NOTE_ID_PATTERN = /^nt_[A-Za-z0-9_-]{3,80}$/u;
const REPLY_ID_PATTERN = /^rpy_[A-Za-z0-9_-]{12,80}$/u;
const NOTE_PATH_PATTERN = /^\/notes\/([^/]+)(?:\/replies\/([^/]*))?\/?$/u;

export interface NoteRoute {
  noteId: string;
  replyId?: string;
}

export function notePath(noteId: string, replyId?: string): string {
  if (!NOTE_ID_PATTERN.test(noteId)) throw new TypeError('noteId is invalid.');
  if (replyId === undefined) return `/notes/${encodeURIComponent(noteId)}`;
  if (!REPLY_ID_PATTERN.test(replyId)) throw new TypeError('replyId is invalid.');
  return `/notes/${encodeURIComponent(noteId)}/replies/${encodeURIComponent(replyId)}`;
}

export function noteRouteFromPathname(pathname: string): NoteRoute | null {
  const match = NOTE_PATH_PATTERN.exec(pathname);
  if (match?.[1] === undefined) return null;
  try {
    const noteId = decodeURIComponent(match[1]);
    if (!NOTE_ID_PATTERN.test(noteId)) return null;
    if (match[2] === undefined) return { noteId };
    const replyId = decodeURIComponent(match[2]);
    return REPLY_ID_PATTERN.test(replyId) ? { noteId, replyId } : { noteId };
  } catch {
    return null;
  }
}
