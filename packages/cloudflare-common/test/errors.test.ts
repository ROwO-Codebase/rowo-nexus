import { describe, expect, it } from 'vitest';

import {
  NexusFault,
  createNexusErrorBody,
  faultCode,
  nexusErrorStatus,
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
    expect(faultCode(new NexusFault('SEQUENCE_CONFLICT'))).toBe('SEQUENCE_CONFLICT');
    expect(createNexusErrorBody('BAD_REQUEST')).toEqual({
      error: { code: 'BAD_REQUEST', message: 'The request is invalid.' },
    });
  });

  it('accepts a typed code directly without accepting arbitrary strings', async () => {
    const response = toNexusErrorResponse('RATE_LIMITED');
    expect(response.status).toBe(429);
    await expect(response.json()).resolves.toMatchObject({ error: { code: 'RATE_LIMITED' } });
  });
});
