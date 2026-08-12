import { describe, expect, it } from 'vitest';

import {
  NexusFault,
  NEXUS_DEVICE_ERROR_CODES,
  NEXUS_ERROR_CODES,
  createNexusDeviceErrorBody,
  createNexusErrorBody,
  faultCode,
  nexusErrorStatus,
  nexusDeviceErrorStatus,
  toNexusDeviceErrorResponse,
  toNexusErrorResponse,
} from '../src/errors.js';

describe('Nexus errors', () => {
  it('maps domain faults to stable public responses', async () => {
    const response = toNexusErrorResponse(new NexusFault('INVALID_REVOCATION_SECRET'), {
      requestId: 'nxr_AAAAAAAAAAAAAAAAAAAAAA',
    });

    expect(response.status).toBe(403);
    expect(response.headers.get('content-type')).toBe('application/nexus+json');
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.json()).toEqual({
      error: {
        code: 'INVALID_REVOCATION_SECRET',
        message: 'The revocation request is invalid.',
        requestId: 'nxr_AAAAAAAAAAAAAAAAAAAAAA',
      },
    });
  });

  it('drops a malformed request ID rather than reflecting arbitrary input', async () => {
    const response = toNexusErrorResponse(new NexusFault('BAD_REQUEST'), {
      requestId: 'subject:nx1_must_not_be_reflected',
    });
    expect(await response.text()).not.toContain('nx1_must_not_be_reflected');
  });

  it('never exposes arbitrary error details', async () => {
    const secret = 'nx-secret-must-not-leak';
    const response = toNexusErrorResponse(new Error(secret));
    const body = await response.text();

    expect(response.status).toBe(500);
    expect(body).not.toContain(secret);
    expect(body).toContain('INTERNAL_ERROR');
  });

  it('offers typed status and body helpers', () => {
    expect(nexusErrorStatus('BODY_TOO_LARGE')).toBe(413);
    expect(nexusDeviceErrorStatus('DEVICE_NOT_FOUND')).toBe(404);
    expect(nexusDeviceErrorStatus('DEVICE_REVOKED')).toBe(409);
    expect(nexusDeviceErrorStatus('DEVICE_AUTHORIZATION_CONFLICT')).toBe(409);
    expect(faultCode(new NexusFault('SEQUENCE_CONFLICT'))).toBe('SEQUENCE_CONFLICT');
    expect(createNexusErrorBody('BAD_REQUEST')).toEqual({
      error: { code: 'BAD_REQUEST', message: 'The request is invalid.' },
    });
  });

  it('keeps the v1 error union exact while exposing additive device errors', async () => {
    expect(NEXUS_ERROR_CODES).toEqual([
      'BAD_REQUEST',
      'UNSUPPORTED_PROTOCOL',
      'UNSUPPORTED_SUITE',
      'INVALID_SUBJECT',
      'INVALID_SIGNATURE',
      'INVALID_REVOCATION_SECRET',
      'IDENTITY_NOT_FOUND',
      'IDENTITY_REVOKED',
      'SEQUENCE_CONFLICT',
      'SUBJECT_GENESIS_CONFLICT',
      'RATE_LIMITED',
      'TURNSTILE_REQUIRED',
      'TURNSTILE_INVALID',
      'BODY_TOO_LARGE',
      'METHOD_NOT_ALLOWED',
      'UNSUPPORTED_MEDIA_TYPE',
      'ORIGIN_NOT_ALLOWED',
      'HTTPS_REQUIRED',
      'INTERNAL_ERROR',
      'SERVICE_UNAVAILABLE',
    ]);
    expect(NEXUS_DEVICE_ERROR_CODES).toContain('DEVICE_NOT_FOUND');
    expect(createNexusDeviceErrorBody('DEVICE_REVOKED')).toEqual({
      error: { code: 'DEVICE_REVOKED', message: 'The device is revoked.' },
    });
    const response = toNexusDeviceErrorResponse('DEVICE_AUTHORIZATION_CONFLICT');
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'DEVICE_AUTHORIZATION_CONFLICT' },
    });
  });

  it('accepts a typed code directly without accepting arbitrary strings', async () => {
    const response = toNexusErrorResponse('RATE_LIMITED');
    expect(response.status).toBe(429);
    await expect(response.json()).resolves.toMatchObject({ error: { code: 'RATE_LIMITED' } });
  });
});
