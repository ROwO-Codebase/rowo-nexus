import { describe, expect, it } from 'vitest';

import {
  DEVICE_ACTIVATION_PROTOCOL_V2,
  DEVICE_AUTHORIZATION_HASH_DOMAIN_V2,
  DEVICE_AUTHORIZATION_PROTOCOL_V2,
  DEVICE_ID_HASH_DOMAIN_V2,
  DEVICE_REGISTRY_EVENT_PROTOCOL_V2,
  ED25519_ALGORITHM,
  MAX_DEVICE_ACTIVATION_WINDOW_SECONDS,
  MAX_DEVICE_AUTHORIZATION_LIFETIME_SECONDS,
  createDeviceAuthorizationHashPreimageV2,
  createDeviceIdHashPreimageV2,
  deviceActivationRequestV2Schema,
  deviceAuthorizationPayloadV2Schema,
  deviceRegistryEventV2Schema,
  encodeBase64Url,
  formatDeviceAuthorizationIdV2,
  formatDeviceIdV2,
  formatDeviceOperationIdV2,
  formatDeviceRegistryEventIdV2,
  formatSubject,
  nexusDeviceErrorSchema,
  nexusErrorSchema,
  verificationExpectationV2Schema,
} from '../src/index.js';
import type { Base64Url32, Base64Url64, DeviceAuthorizationPayloadV2 } from '../src/index.js';

const bytes = (length: number, value: number): Uint8Array => new Uint8Array(length).fill(value);
const hashA = encodeBase64Url(bytes(32, 0x11)) as Base64Url32;
const hashB = encodeBase64Url(bytes(32, 0x22)) as Base64Url32;
const signature = encodeBase64Url(bytes(64, 0x33)) as Base64Url64;
const subject = formatSubject(bytes(32, 0x44));
const deviceId = formatDeviceIdV2(bytes(32, 0x55));
const authorizationId = formatDeviceAuthorizationIdV2(bytes(32, 0x66));
const operationId = formatDeviceOperationIdV2(bytes(32, 0x77));
const eventId = formatDeviceRegistryEventIdV2(bytes(32, 0x88));

function authorization(
  overrides: Partial<DeviceAuthorizationPayloadV2> = {},
): DeviceAuthorizationPayloadV2 {
  return {
    protocol: DEVICE_AUTHORIZATION_PROTOCOL_V2,
    subject,
    genesisHash: hashA,
    deviceId,
    signingKey: { alg: ED25519_ALGORITHM, publicKey: hashB },
    authorizationNonce: hashA,
    validFrom: 100,
    activationDeadline: 100 + MAX_DEVICE_ACTIVATION_WINDOW_SECONDS,
    expiresAt: 100 + MAX_DEVICE_AUTHORIZATION_LIFETIME_SECONDS,
    ...overrides,
  };
}

describe('Nexus v2 root-authorized device protocol', () => {
  it('formats each v2 identifier from exactly one SHA-256 hash', () => {
    expect(deviceId).toMatch(/^nxd2_[A-Za-z0-9_-]{43}$/u);
    expect(authorizationId).toMatch(/^nxa2_[A-Za-z0-9_-]{43}$/u);
    expect(operationId).toMatch(/^nxo2_[A-Za-z0-9_-]{43}$/u);
    expect(eventId).toMatch(/^nxde2_[A-Za-z0-9_-]{43}$/u);
    expect(() => formatDeviceIdV2(bytes(31, 0))).toThrow(RangeError);
    expect(() => formatDeviceAuthorizationIdV2(bytes(33, 0))).toThrow(RangeError);
  });

  it('uses independent canonical hash domains for device and authorization IDs', () => {
    const decoder = new TextDecoder();
    expect(
      decoder.decode(
        createDeviceIdHashPreimageV2({
          subject,
          signingKey: authorization().signingKey,
        }),
      ),
    ).toBe(
      `${DEVICE_ID_HASH_DOMAIN_V2}{"signingKey":{"alg":"Ed25519","publicKey":"${hashB}"},"subject":"${subject}"}`,
    );
    expect(decoder.decode(createDeviceAuthorizationHashPreimageV2(authorization()))).toMatch(
      new RegExp(`^${DEVICE_AUTHORIZATION_HASH_DOMAIN_V2.replaceAll('\0', '\\0')}`),
    );
  });

  it('accepts exact authorization caps and rejects either cap plus one second', () => {
    expect(deviceAuthorizationPayloadV2Schema.safeParse(authorization()).success).toBe(true);
    expect(
      deviceAuthorizationPayloadV2Schema.safeParse(
        authorization({ activationDeadline: 101 + MAX_DEVICE_ACTIVATION_WINDOW_SECONDS }),
      ).success,
    ).toBe(false);
    expect(
      deviceAuthorizationPayloadV2Schema.safeParse(
        authorization({ expiresAt: 101 + MAX_DEVICE_AUTHORIZATION_LIFETIME_SECONDS }),
      ).success,
    ).toBe(false);
  });

  it('rejects reversed authorization times and unknown nested fields', () => {
    expect(
      deviceAuthorizationPayloadV2Schema.safeParse(
        authorization({ validFrom: 200, activationDeadline: 199 }),
      ).success,
    ).toBe(false);
    expect(
      deviceAuthorizationPayloadV2Schema.safeParse({
        ...authorization(),
        signingKey: { ...authorization().signingKey, extractable: true },
      }).success,
    ).toBe(false);
  });

  it('requires activation and authorization subjects/device IDs to agree', () => {
    const request = {
      authorization: { payload: authorization(), rootSignature: signature },
      payload: {
        protocol: DEVICE_ACTIVATION_PROTOCOL_V2,
        subject,
        deviceId,
        authorizationId,
        requestId: hashB,
        iat: 200,
        exp: 201,
      },
      deviceSignature: signature,
    };
    expect(deviceActivationRequestV2Schema.safeParse(request).success).toBe(true);
    expect(
      deviceActivationRequestV2Schema.safeParse({
        ...request,
        payload: { ...request.payload, deviceId: formatDeviceIdV2(bytes(32, 0x99)) },
      }).success,
    ).toBe(false);
  });

  it('enforces activated and revoked device event state combinations', () => {
    const event = {
      protocol: DEVICE_REGISTRY_EVENT_PROTOCOL_V2,
      eventId,
      operationId,
      eventType: 'activated',
      subject,
      genesisHash: hashA,
      identitySequence: 0,
      identityState: 'active',
      deviceLedgerSequence: 1,
      deviceId,
      authorizationId,
      deviceState: 'active',
      authorizationExpiresAt: 1_000,
      acceptedAt: 200,
      actionHash: hashB,
    } as const;
    expect(deviceRegistryEventV2Schema.safeParse(event).success).toBe(true);
    expect(
      deviceRegistryEventV2Schema.safeParse({ ...event, deviceState: 'revoked' }).success,
    ).toBe(false);
    expect(
      deviceRegistryEventV2Schema.safeParse({
        ...event,
        eventType: 'revoked',
        deviceState: 'revoked',
        revokedBy: 'root',
      }).success,
    ).toBe(true);
  });

  it('keeps v1 error codes closed while accepting device errors on v2 surfaces', () => {
    const deviceError = {
      error: { code: 'DEVICE_REVOKED', message: 'The device is revoked.' },
    };
    expect(nexusErrorSchema.safeParse(deviceError).success).toBe(false);
    expect(nexusDeviceErrorSchema.safeParse(deviceError).success).toBe(true);
    expect(
      nexusDeviceErrorSchema.safeParse({
        error: { code: 'IDENTITY_REVOKED', message: 'The identity is revoked.' },
      }).success,
    ).toBe(true);
    for (const code of [
      'METHOD_NOT_ALLOWED',
      'UNSUPPORTED_MEDIA_TYPE',
      'ORIGIN_NOT_ALLOWED',
      'HTTPS_REQUIRED',
      'SERVICE_UNAVAILABLE',
    ]) {
      const transportError = { error: { code, message: 'Transport failure.' } };
      expect(nexusErrorSchema.safeParse(transportError).success).toBe(false);
      expect(nexusDeviceErrorSchema.safeParse(transportError).success).toBe(true);
    }
  });

  it('requires an explicit v2 context-binding policy', () => {
    const expectation = {
      audience: 'https://rp.example',
      action: 'post.edit',
      resource: 'post:123',
      nonce: encodeBase64Url(bytes(16, 0x99)),
      now: 100,
      maxClockSkewSeconds: 5,
    };
    expect(
      verificationExpectationV2Schema.safeParse({ ...expectation, contextHash: null }).success,
    ).toBe(true);
    expect(
      verificationExpectationV2Schema.safeParse({ ...expectation, contextHash: hashA }).success,
    ).toBe(true);
    expect(verificationExpectationV2Schema.safeParse(expectation).success).toBe(false);
  });
});
