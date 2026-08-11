import { describe, expect, it } from 'vitest';

import { noteRouteFromPathname, notePath } from './note-route.js';

describe('note routes', () => {
  it('round-trips canonical note identifiers', () => {
    expect(notePath('nt_field-notes')).toBe('/notes/nt_field-notes');
    expect(noteRouteFromPathname('/notes/nt_field-notes')).toEqual({
      noteId: 'nt_field-notes',
    });
    expect(noteRouteFromPathname('/notes/nt_field-notes/')).toEqual({
      noteId: 'nt_field-notes',
    });
  });

  it('round-trips a reply while treating an invalid reply as note-only', () => {
    const replyId = 'rpy_AAAAAAAAAAAA';
    expect(notePath('nt_field-notes', replyId)).toBe(`/notes/nt_field-notes/replies/${replyId}`);
    expect(noteRouteFromPathname(`/notes/nt_field-notes/replies/${replyId}`)).toEqual({
      noteId: 'nt_field-notes',
      replyId,
    });
    expect(noteRouteFromPathname('/notes/nt_field-notes/replies/missing')).toEqual({
      noteId: 'nt_field-notes',
    });
    expect(noteRouteFromPathname('/notes/nt_field-notes/replies/')).toEqual({
      noteId: 'nt_field-notes',
    });
  });

  it('falls back for malformed, nested, or non-note paths', () => {
    expect(noteRouteFromPathname('/')).toBeNull();
    expect(noteRouteFromPathname('/notes/')).toBeNull();
    expect(noteRouteFromPathname('/notes/not-a-note')).toBeNull();
    expect(noteRouteFromPathname('/notes/nt_valid/extra')).toBeNull();
    expect(noteRouteFromPathname('/notes/%E0%A4%A')).toBeNull();
    expect(() => notePath('../private')).toThrow('noteId is invalid.');
    expect(() => notePath('nt_field-notes', '../private')).toThrow('replyId is invalid.');
  });
});
