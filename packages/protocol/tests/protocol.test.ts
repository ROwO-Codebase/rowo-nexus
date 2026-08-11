import { describe, expect, it } from 'vitest';

import {
  CONTINUITY_LINK_PROTOCOL_V1,
  ED25519_ALGORITHM,
  GENESIS_HASH_DOMAIN,
  IDENTITY_PROTOCOL_V1,
  NEXUS_SUITE_V1,
  OWNERSHIP_PROOF_PROTOCOL_V1,
  REGISTRY_EVENT_HASH_DOMAIN,
  REGISTRY_EVENT_PROTOCOL_V1,
  REGISTRY_RECEIPT_PROTOCOL_V1,
  SIGNATURE_DOMAIN,
  STATUS_STATEMENT_PROTOCOL_V1,
  X25519_ALGORITHM,
  Base64UrlError,
  CanonicalizationError,
  audienceOriginSchema,
  canonicalize,
  continuityLinkPayloadV1Schema,
  createGenesisHashPreimage,
  createRegistryEventHashPreimage,
  createSignaturePreimage,
  decodeBase64Url,
  decodeBase64UrlExact,
  encodeBase64Url,
  formatRegistryEventId,
  formatSubject,
  identityGenesisV1Schema,
  ownershipProofPayloadV1Schema,
  registryEventV1Schema,
  registryReceiptPayloadV1Schema,
  serviceKeySetSchema,
  statusStatementPayloadV1Schema,
} from '../src/index.js';
import type {
  Base64Url32,
  Base64Url64,
  Base64UrlAtLeast16,
  IdentityGenesisV1,
  NexusEventId,
  NexusSubject,
  RegistryEventWithoutEventIdV1,
} from '../src/index.js';

const textDecoder = new TextDecoder();

function repeatedBytes(length: number, value: number): Uint8Array {
  return new Uint8Array(length).fill(value);
}

const hashA = encodeBase64Url(repeatedBytes(32, 0x11)) as Base64Url32;
const hashB = encodeBase64Url(repeatedBytes(32, 0x22)) as Base64Url32;
const signature = encodeBase64Url(repeatedBytes(64, 0x33)) as Base64Url64;
const nonce = encodeBase64Url(repeatedBytes(16, 0x44)) as Base64UrlAtLeast16;
const subjectA = formatSubject(repeatedBytes(32, 0x55));
const subjectB = formatSubject(repeatedBytes(32, 0x66));
const eventId = formatRegistryEventId(repeatedBytes(32, 0x77));

const genesisA: IdentityGenesisV1 = {
  protocol: IDENTITY_PROTOCOL_V1,
  suite: NEXUS_SUITE_V1,
  signingKey: { alg: ED25519_ALGORITHM, publicKey: hashA },
  agreementKey: { alg: X25519_ALGORITHM, publicKey: hashB },
  revocationCommitment: hashA,
};

describe('canonical base64url', () => {
  it('round-trips unpadded canonical bytes', () => {
    const encoded = encodeBase64Url(Uint8Array.of(0xff, 0xfe, 0xfd));
    expect(encoded).toBe('__79');
    expect(decodeBase64Url(encoded)).toEqual(Uint8Array.of(0xff, 0xfe, 0xfd));
  });

  it.each(['AA==', 'A+', 'A/', 'A A', 'A', 'AB'])(
    'rejects malformed or non-canonical input %s',
    (value) => {
      expect(() => decodeBase64Url(value)).toThrow(Base64UrlError);
    },
  );

  it('enforces decoded byte length', () => {
    expect(() => decodeBase64UrlExact(encodeBase64Url(Uint8Array.of(1)), 32)).toThrow(
      Base64UrlError,
    );
  });
});

describe('RFC 8785 canonicalization', () => {
  it('sorts recursively and uses ECMAScript number serialization', () => {
    expect(canonicalize({ z: -0, a: { z: 1e30, a: 0.002 }, list: [true, null, '€'] })).toBe(
      '{"a":{"a":0.002,"z":1e+30},"list":[true,null,"€"],"z":0}',
    );
  });

  it('sorts keys by UTF-16 code units', () => {
    expect(canonicalize({ '€': 1, '\r': 2, a: 3, '😀': 4 })).toBe('{"\\r":2,"a":3,"€":1,"😀":4}');
  });

  it('rejects values outside I-JSON', () => {
    expect(() => canonicalize({ value: Number.NaN })).toThrow(CanonicalizationError);
    expect(() => canonicalize({ value: undefined })).toThrow(CanonicalizationError);
    expect(() => canonicalize({ value: '\ud800' })).toThrow(CanonicalizationError);
  });
});

describe('strict protocol schemas', () => {
  it('accepts valid genesis and rejects unknown nested fields', () => {
    expect(identityGenesisV1Schema.parse(genesisA)).toEqual(genesisA);
    expect(
      identityGenesisV1Schema.safeParse({
        ...genesisA,
        signingKey: { ...genesisA.signingKey, unexpected: true },
      }).success,
    ).toBe(false);
  });

  it.each([
    'http://rp.example',
    'https://rp.example/',
    'https://rp.example/path',
    'https://rp.example?query=1',
    'https://*.example',
    'https://user:pass@rp.example',
    'https://RP.example',
  ])('rejects a non-canonical audience %s', (audience) => {
    expect(audienceOriginSchema.safeParse(audience).success).toBe(false);
  });

  it('accepts a canonical HTTPS origin', () => {
    expect(audienceOriginSchema.parse('https://rp.example:8443')).toBe('https://rp.example:8443');
  });

  it('enforces ownership time ordering', () => {
    const payload = {
      protocol: OWNERSHIP_PROOF_PROTOCOL_V1,
      subject: subjectA,
      genesis: genesisA,
      aud: 'https://rp.example',
      act: 'post.edit',
      resource: 'post:123',
      nonce,
      iat: 101,
      exp: 100,
    };
    expect(ownershipProofPayloadV1Schema.safeParse(payload).success).toBe(false);
    expect(ownershipProofPayloadV1Schema.safeParse({ ...payload, iat: 100 }).success).toBe(true);
  });

  it('rejects continuity self-links and reversed times', () => {
    const payload = {
      protocol: CONTINUITY_LINK_PROTOCOL_V1,
      subjectA,
      genesisA,
      subjectB: subjectA,
      genesisB: genesisA,
      iat: 10,
      exp: 9,
      nonce,
    };
    expect(continuityLinkPayloadV1Schema.safeParse(payload).success).toBe(false);
    expect(
      continuityLinkPayloadV1Schema.safeParse({
        ...payload,
        subjectB,
        exp: 10,
      }).success,
    ).toBe(true);
  });

  it('enforces registry event and receipt state pairs', () => {
    const registered = {
      protocol: REGISTRY_EVENT_PROTOCOL_V1,
      eventId,
      eventType: 'registered',
      subject: subjectA,
      genesisHash: hashA,
      sequence: 0,
      state: 'active',
      acceptedAt: 100,
      actionHash: hashB,
    } as const;
    expect(registryEventV1Schema.safeParse(registered).success).toBe(true);
    expect(registryEventV1Schema.safeParse({ ...registered, state: 'revoked' }).success).toBe(
      false,
    );

    const receipt = {
      protocol: REGISTRY_RECEIPT_PROTOCOL_V1,
      eventId,
      subject: subjectA,
      genesisHash: hashA,
      eventType: 'revoked',
      sequence: 1,
      state: 'revoked',
      acceptedAt: 101,
      signerKid: 'registry-2026-01',
    } as const;
    expect(registryReceiptPayloadV1Schema.safeParse(receipt).success).toBe(true);
    expect(registryReceiptPayloadV1Schema.safeParse({ ...receipt, sequence: 0 }).success).toBe(
      false,
    );
  });

  it('requires revokedAt exactly for revoked statements', () => {
    const base = {
      protocol: STATUS_STATEMENT_PROTOCOL_V1,
      subject: subjectA,
      registeredAt: 10,
      iat: 20,
      exp: 80,
      signerKid: 'registry-2026-01',
    } as const;
    expect(
      statusStatementPayloadV1Schema.safeParse({
        ...base,
        state: 'active',
        sequence: 0,
      }).success,
    ).toBe(true);
    expect(
      statusStatementPayloadV1Schema.safeParse({
        ...base,
        state: 'active',
        sequence: 0,
        revokedAt: 15,
      }).success,
    ).toBe(false);
    expect(
      statusStatementPayloadV1Schema.safeParse({
        ...base,
        state: 'revoked',
        sequence: 1,
      }).success,
    ).toBe(false);
    expect(
      statusStatementPayloadV1Schema.safeParse({
        ...base,
        state: 'revoked',
        sequence: 1,
        revokedAt: 15,
      }).success,
    ).toBe(true);
  });

  it('accepts only strict Ed25519 verification JWKS with unique kids', () => {
    const key = {
      kty: 'OKP',
      crv: 'Ed25519',
      alg: 'EdDSA',
      kid: 'registry-2026-01',
      x: hashA,
      use: 'sig',
    } as const;
    expect(serviceKeySetSchema.safeParse({ keys: [key] }).success).toBe(true);
    expect(serviceKeySetSchema.safeParse({ keys: [key, key] }).success).toBe(false);
    expect(serviceKeySetSchema.safeParse({ keys: [{ ...key, crv: 'X25519' }] }).success).toBe(
      false,
    );
  });
});

describe('cryptographic preimages and identifier formatting', () => {
  it('formats only 32-byte hashes', () => {
    expect(subjectA).toMatch(/^nx1_[A-Za-z0-9_-]{43}$/u);
    expect(eventId).toMatch(/^nxe1_[A-Za-z0-9_-]{43}$/u);
    expect(() => formatSubject(Uint8Array.of(1))).toThrow(RangeError);
    expect(() => formatRegistryEventId(Uint8Array.of(1))).toThrow(RangeError);
  });

  it('builds the exact direct-payload signature preimage', () => {
    const payload = { protocol: 'nexus.example.v1', z: 2, a: 1 };
    expect(textDecoder.decode(createSignaturePreimage(payload.protocol, payload))).toBe(
      `${SIGNATURE_DOMAIN}nexus.example.v1\0{"a":1,"protocol":"nexus.example.v1","z":2}`,
    );
    expect(() => createSignaturePreimage('bad\0protocol', payload)).toThrow(TypeError);
  });

  it('builds exact genesis and event hash preimages', () => {
    expect(textDecoder.decode(createGenesisHashPreimage(genesisA))).toBe(
      `${GENESIS_HASH_DOMAIN}${canonicalize(genesisA)}`,
    );

    const event: RegistryEventWithoutEventIdV1 = {
      protocol: REGISTRY_EVENT_PROTOCOL_V1,
      eventType: 'registered',
      subject: subjectA,
      genesisHash: hashA,
      sequence: 0,
      state: 'active',
      acceptedAt: 100,
      actionHash: hashB,
    };
    expect(textDecoder.decode(createRegistryEventHashPreimage(event))).toBe(
      `${REGISTRY_EVENT_HASH_DOMAIN}${canonicalize(event)}`,
    );
  });

  it('keeps signature fixture byte length canonical', () => {
    expect(decodeBase64UrlExact(signature, 64)).toHaveLength(64);
  });
});

// Compile-time assertions for the public template literal identifier types.
const typedSubject: NexusSubject = subjectA;
const typedEventId: NexusEventId = eventId;
void typedSubject;
void typedEventId;
