import { describe, expect, it } from 'vitest';

import { createTransparencyKeySetResponse, parseTransparencyKeySet } from './keyset.js';

const CURRENT_KID = 'transparency-2026-08';
const HISTORICAL_KID = 'transparency-2026-07';
const ZERO_KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const ONE_KEY = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE';

function keySetJson(): string {
  return JSON.stringify({
    keys: [
      {
        kty: 'OKP',
        crv: 'Ed25519',
        alg: 'EdDSA',
        kid: CURRENT_KID,
        x: ZERO_KEY,
        use: 'sig',
      },
      {
        kty: 'OKP',
        crv: 'Ed25519',
        alg: 'EdDSA',
        kid: HISTORICAL_KID,
        x: ONE_KEY,
      },
    ],
  });
}

describe('transparency verification keyset', () => {
  it('accepts the current key together with historical Ed25519 keys', () => {
    const keySet = parseTransparencyKeySet(keySetJson(), CURRENT_KID);
    expect(keySet.keys.map((key) => key.kid)).toEqual([CURRENT_KID, HISTORICAL_KID]);
  });

  it('fails closed for an absent current signing kid', () => {
    expect(() => parseTransparencyKeySet(keySetJson(), 'transparency-missing')).toThrow(
      /not configured correctly/,
    );
  });

  it('rejects unknown purpose fields and non-signing use', () => {
    const unknownPurpose = JSON.parse(keySetJson()) as {
      keys: Array<Record<string, unknown>>;
    };
    const purposeKey = unknownPurpose.keys[0];
    if (purposeKey === undefined) {
      throw new Error('Fixture key is unavailable.');
    }
    purposeKey.purpose = 'registry';
    expect(() => parseTransparencyKeySet(JSON.stringify(unknownPurpose), CURRENT_KID)).toThrow(
      /not configured correctly/,
    );

    const wrongUse = JSON.parse(keySetJson()) as {
      keys: Array<Record<string, unknown>>;
    };
    const useKey = wrongUse.keys[0];
    if (useKey === undefined) {
      throw new Error('Fixture key is unavailable.');
    }
    useKey.use = 'enc';
    expect(() => parseTransparencyKeySet(JSON.stringify(wrongUse), CURRENT_KID)).toThrow(
      /not configured correctly/,
    );
  });

  it('returns cacheable public JSON and honors If-None-Match', async () => {
    const keySet = parseTransparencyKeySet(keySetJson(), CURRENT_KID);
    const first = await createTransparencyKeySetResponse(
      new Request('https://status.rowo.link/.well-known/nexus-transparency-keys.json'),
      keySet,
    );
    expect(first.status).toBe(200);
    expect(first.headers.get('cache-control')).toBe(
      'public, max-age=300, stale-while-revalidate=60',
    );
    expect(first.headers.get('access-control-allow-origin')).toBe('*');
    expect(await first.json()).toEqual(keySet);

    const etag = first.headers.get('etag');
    if (etag === null) {
      throw new Error('Keyset ETag is unavailable.');
    }
    const cached = await createTransparencyKeySetResponse(
      new Request('https://status.rowo.link/.well-known/nexus-transparency-keys.json', {
        headers: { 'if-none-match': etag },
      }),
      keySet,
    );
    expect(cached.status).toBe(304);
    expect(await cached.text()).toBe('');
  });
});
