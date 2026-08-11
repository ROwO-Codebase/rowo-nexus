import { describe, expect, it } from 'vitest';

import { createPi3ShareLink } from './share-links.js';

describe('pi3.dev Notes sharing', () => {
  it('preserves the exact canonical reply URL and accepts a safe short link', async () => {
    const destination = 'https://notes.rowo.link/notes/nt_field-notes/replies/rpy_AAAAAAAAAAAA';
    const fetcher: typeof fetch = (input, init) => {
      expect(input).toBe('https://pi3.dev/create');
      expect(init).toMatchObject({
        method: 'POST',
        credentials: 'omit',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
      });
      const requestBody = init?.body;
      expect(typeof requestBody).toBe('string');
      expect(JSON.parse(requestBody as string)).toEqual({ url: destination });
      return Promise.resolve(
        Response.json({ slug: 'Ab12', link: 'https://pi3.dev/Ab12', expiresAt: null }),
      );
    };

    await expect(createPi3ShareLink(destination, 'https://notes.rowo.link', fetcher)).resolves.toBe(
      'https://pi3.dev/Ab12',
    );
  });

  it('rejects noncanonical destinations and unsafe service responses', async () => {
    const unusedFetcher: typeof fetch = () => {
      throw new Error('fetch must not be called');
    };
    await expect(
      createPi3ShareLink(
        'https://other.example/notes/nt_field-notes',
        'https://notes.rowo.link',
        unusedFetcher,
      ),
    ).rejects.toThrow('Only a canonical HTTPS Notes URL can be shared.');

    const unsafeFetcher: typeof fetch = () =>
      Promise.resolve(Response.json({ link: 'https://attacker.example/link' }));
    await expect(
      createPi3ShareLink(
        'https://notes.rowo.link/notes/nt_field-notes',
        'https://notes.rowo.link',
        unsafeFetcher,
      ),
    ).rejects.toThrow('unsafe link');
  });
});
