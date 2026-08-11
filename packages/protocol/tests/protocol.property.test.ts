import * as fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  ED25519_ALGORITHM,
  IDENTITY_PROTOCOL_V1,
  NEXUS_SUITE_V1,
  X25519_ALGORITHM,
  Base64UrlError,
  CanonicalizationError,
  base64Url32Schema,
  canonicalize,
  decodeBase64Url,
  decodeBase64UrlExact,
  encodeBase64Url,
  identityGenesisV1Schema,
  ownershipProofV1Schema,
} from '../src/index.js';

const PROPERTY_OPTIONS = {
  numRuns: 100,
  seed: 0x4e585631,
  endOnFailure: true,
} as const;

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function canCanonicalize(value: unknown): boolean {
  try {
    canonicalize(value);
    return true;
  } catch {
    return false;
  }
}

const validUnicodeStringArbitrary = fc
  .string({ maxLength: 80 })
  .filter((value) => !hasLoneSurrogate(value));

const canonicalJsonValueArbitrary = fc.jsonValue().filter(canCanonicalize);

const canonicalObjectEntriesArbitrary = fc.uniqueArray(
  fc.tuple(validUnicodeStringArbitrary, canonicalJsonValueArbitrary),
  {
    maxLength: 16,
    selector: ([key]) => key,
  },
);

const key32 = encodeBase64Url(new Uint8Array(32).fill(0x11));
const agreementKey32 = encodeBase64Url(new Uint8Array(32).fill(0x22));

const validGenesis = {
  protocol: IDENTITY_PROTOCOL_V1,
  suite: NEXUS_SUITE_V1,
  signingKey: { alg: ED25519_ALGORITHM, publicKey: key32 },
  agreementKey: { alg: X25519_ALGORITHM, publicKey: agreementKey32 },
  revocationCommitment: key32,
};

describe('bounded RFC 8785 properties', () => {
  it('is deterministic regardless of object insertion order', () => {
    fc.assert(
      fc.property(canonicalObjectEntriesArbitrary, (entries) => {
        const forward = Object.fromEntries(entries);
        const reverse = Object.fromEntries([...entries].reverse());

        expect(canonicalize(forward)).toBe(canonicalize(reverse));
      }),
      PROPERTY_OPTIONS,
    );
  });

  it('is idempotent after parsing its canonical JSON', () => {
    fc.assert(
      fc.property(canonicalJsonValueArbitrary, (value) => {
        const first = canonicalize(value);
        expect(canonicalize(JSON.parse(first) as unknown)).toBe(first);
      }),
      PROPERTY_OPTIONS,
    );
  });

  it('uses JSON string escaping for valid Unicode and preserves normalization', () => {
    fc.assert(
      fc.property(validUnicodeStringArbitrary, (value) => {
        expect(canonicalize({ value })).toBe(`{"value":${JSON.stringify(value)}}`);
      }),
      PROPERTY_OPTIONS,
    );

    const composed = '\u00e9';
    const decomposed = 'e\u0301';
    expect(canonicalize({ value: composed })).not.toBe(canonicalize({ value: decomposed }));
    expect(canonicalize({ value: '\u0000\b\t\n\f\r"\\/😀' })).toBe(
      '{"value":"\\u0000\\b\\t\\n\\f\\r\\"\\\\/😀"}',
    );
    expect(() => canonicalize({ value: '\ud800' })).toThrow(CanonicalizationError);
    expect(() => canonicalize({ value: '\udc00' })).toThrow(CanonicalizationError);
  });

  it('matches ECMAScript finite-number serialization', () => {
    fc.assert(
      fc.property(fc.double({ noDefaultInfinity: true, noNaN: true }), (value) => {
        expect(canonicalize({ value })).toBe(`{"value":${JSON.stringify(value)}}`);
      }),
      PROPERTY_OPTIONS,
    );

    for (const value of [
      -0,
      Number.MIN_VALUE,
      Number.MAX_VALUE,
      Number.MIN_SAFE_INTEGER,
      Number.MAX_SAFE_INTEGER,
      1e-7,
      1e21,
    ]) {
      expect(canonicalize({ value })).toBe(`{"value":${JSON.stringify(value)}}`);
    }
    expect(() => canonicalize({ value: Number.NaN })).toThrow(CanonicalizationError);
    expect(() => canonicalize({ value: Number.POSITIVE_INFINITY })).toThrow(CanonicalizationError);
  });
});

describe('bounded canonical base64url properties', () => {
  it('round-trips arbitrary bounded byte arrays without padding', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 256 }), (bytes) => {
        const encoded = encodeBase64Url(bytes);
        expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/u);
        expect(encoded).not.toContain('=');
        expect(decodeBase64Url(encoded)).toEqual(bytes);
        expect(encodeBase64Url(decodeBase64Url(encoded))).toBe(encoded);
      }),
      PROPERTY_OPTIONS,
    );
  });

  it('rejects padding and whitespace inserted into otherwise valid encodings', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 128 }), (bytes) => {
        const encoded = encodeBase64Url(bytes);
        const insertionPoint = Math.floor(encoded.length / 2);
        const withWhitespace = `${encoded.slice(0, insertionPoint)} ${encoded.slice(insertionPoint)}`;

        expect(() => decodeBase64Url(`${encoded}=`)).toThrow(Base64UrlError);
        expect(() => decodeBase64Url(withWhitespace)).toThrow(Base64UrlError);
      }),
      PROPERTY_OPTIONS,
    );
  });

  it('rejects inputs containing the standard alphabet or other illegal characters', () => {
    const malformedArbitrary = fc
      .array(fc.constantFrom('=', '+', '/', ' ', '\t', '\r', '\n', '*', '.'), {
        minLength: 1,
        maxLength: 32,
      })
      .map((characters) => characters.join(''));

    fc.assert(
      fc.property(malformedArbitrary, (value) => {
        expect(() => decodeBase64Url(value)).toThrow(Base64UrlError);
      }),
      PROPERTY_OPTIONS,
    );
  });

  it('enforces exact byte lengths at both helper and schema boundaries', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ maxLength: 64 }).filter((bytes) => bytes.length !== 32),
        (bytes) => {
          const encoded = encodeBase64Url(bytes);
          expect(() => decodeBase64UrlExact(encoded, 32)).toThrow(Base64UrlError);
          expect(base64Url32Schema.safeParse(encoded).success).toBe(false);
        },
      ),
      PROPERTY_OPTIONS,
    );

    // "AB" decodes in permissive decoders but has non-zero unused trailing bits.
    expect(() => decodeBase64Url('AB')).toThrow(Base64UrlError);
  });
});

describe('bounded strict-schema properties', () => {
  it('rejects every unknown genesis key at either object level', () => {
    const genesisKeys = new Set([
      'protocol',
      'suite',
      'signingKey',
      'agreementKey',
      'revocationCommitment',
    ]);
    const signingKeyKeys = new Set(['alg', 'publicKey']);
    const unknownKeyArbitrary = validUnicodeStringArbitrary.filter(
      (key) => key.length > 0 && key !== '__proto__',
    );

    fc.assert(
      fc.property(
        unknownKeyArbitrary.filter((key) => !genesisKeys.has(key)),
        canonicalJsonValueArbitrary,
        (key, value) => {
          expect(identityGenesisV1Schema.safeParse({ ...validGenesis, [key]: value }).success).toBe(
            false,
          );
        },
      ),
      PROPERTY_OPTIONS,
    );

    fc.assert(
      fc.property(
        unknownKeyArbitrary.filter((key) => !signingKeyKeys.has(key)),
        canonicalJsonValueArbitrary,
        (key, value) => {
          expect(
            identityGenesisV1Schema.safeParse({
              ...validGenesis,
              signingKey: { ...validGenesis.signingKey, [key]: value },
            }).success,
          ).toBe(false);
        },
      ),
      PROPERTY_OPTIONS,
    );
  });

  it('rejects malformed JSON values without throwing from safeParse', () => {
    const malformedArbitrary = fc.oneof(
      fc.constant(null),
      fc.boolean(),
      fc.double({ noDefaultInfinity: true, noNaN: true }),
      fc.string({ maxLength: 64 }),
      fc.array(fc.jsonValue(), { maxLength: 8 }),
    );

    fc.assert(
      fc.property(malformedArbitrary, (value) => {
        expect(() => identityGenesisV1Schema.safeParse(value)).not.toThrow();
        expect(identityGenesisV1Schema.safeParse(value).success).toBe(false);
        expect(() => ownershipProofV1Schema.safeParse(value)).not.toThrow();
        expect(ownershipProofV1Schema.safeParse(value).success).toBe(false);
      }),
      PROPERTY_OPTIONS,
    );
  });
});
