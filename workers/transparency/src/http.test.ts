import { describe, expect, it } from 'vitest';

import { parseExactStringObject, readSmallJson, requireNexusJson } from './http.js';

describe('transparency HTTP input boundaries', () => {
  it('accepts only the Nexus JSON media type', () => {
    expect(() =>
      requireNexusJson(
        new Request('https://example.test', {
          method: 'POST',
          headers: { 'content-type': 'application/nexus+json; charset=utf-8' },
        }),
      ),
    ).not.toThrow();
    expect(() =>
      requireNexusJson(
        new Request('https://example.test', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
        }),
      ),
    ).toThrow(/Content-Type/);
  });

  it('rejects unknown inclusion-request fields', () => {
    expect(() =>
      parseExactStringObject({ eventHash: 'hash', subject: 'nx1_secret' }, 'eventHash'),
    ).toThrow(/exactly one/);
  });

  it('enforces the body limit before parsing', async () => {
    const request = new Request('https://example.test', {
      method: 'POST',
      body: JSON.stringify({ eventHash: 'x'.repeat(200) }),
    });
    await expect(readSmallJson(request, 32)).rejects.toMatchObject({
      code: 'BODY_TOO_LARGE',
    });
  });
});
