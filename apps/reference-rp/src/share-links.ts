import { notePath, noteRouteFromPathname } from './note-route.js';

const PI3_CREATE_URL = 'https://pi3.dev/create';
const MAX_PI3_RESPONSE_BYTES = 4_096;

export async function createPi3ShareLink(
  destination: string,
  expectedNotesOrigin: string,
  fetcher: typeof fetch = fetch,
): Promise<string> {
  const target = new URL(destination);
  const notesOrigin = new URL(expectedNotesOrigin).origin;
  const route = noteRouteFromPathname(target.pathname);
  if (
    target.protocol !== 'https:' ||
    target.origin !== notesOrigin ||
    target.username !== '' ||
    target.password !== '' ||
    target.search !== '' ||
    target.hash !== '' ||
    route === null ||
    target.pathname !== notePath(route.noteId, route.replyId)
  ) {
    throw new TypeError('Only a canonical HTTPS Notes URL can be shared.');
  }

  const response = await fetcher(PI3_CREATE_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ url: target.href }),
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  });
  const text = await response.text();
  if (!response.ok || text.length === 0 || text.length > MAX_PI3_RESPONSE_BYTES) {
    throw new Error('The short-link service could not create this link.');
  }

  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new Error('The short-link service returned an unreadable response.');
  }
  if (
    typeof value !== 'object' ||
    value === null ||
    !('link' in value) ||
    typeof value.link !== 'string'
  ) {
    throw new Error('The short-link service returned an unreadable response.');
  }

  const shortUrl = new URL(value.link);
  if (
    shortUrl.origin !== 'https://pi3.dev' ||
    shortUrl.username !== '' ||
    shortUrl.password !== '' ||
    shortUrl.search !== '' ||
    shortUrl.hash !== '' ||
    shortUrl.pathname === '/'
  ) {
    throw new Error('The short-link service returned an unsafe link.');
  }
  return shortUrl.href;
}
