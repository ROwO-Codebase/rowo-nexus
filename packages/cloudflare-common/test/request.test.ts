import { describe, expect, it } from 'vitest';

import { NexusFault } from '../src/errors.js';
import {
  assertHttps,
  assertExactRequestOrigin,
  assertMethod,
  assertNexusContentType,
  handleExactOriginPreflight,
  readBodyBytes,
  readJsonBody,
} from '../src/request.js';

function nexusRequest(body: BodyInit, headers?: HeadersInit): Request {
  return new Request('https://nexus.rowo.link/v1/identity/status', {
    method: 'POST',
    body,
    headers: { 'Content-Type': 'application/nexus+json', ...headers },
  });
}

describe('request guards', () => {
  it('enforces method and HTTPS', () => {
    const request = nexusRequest('{}');
    expect(() => assertMethod(request, ['POST'])).not.toThrow();
    expect(() => assertMethod(request, ['GET'])).toThrowError(NexusFault);
    expect(() => assertHttps(request)).not.toThrow();
    expect(() => assertHttps(new Request('http://nexus.rowo.link'))).toThrowError(NexusFault);
    expect(() =>
      assertHttps(new Request('http://localhost:8787'), { allowLocalhost: true }),
    ).not.toThrow();
  });

  it('requires Nexus JSON and accepts UTF-8 only', () => {
    expect(() => assertNexusContentType(nexusRequest('{}'))).not.toThrow();
    expect(() =>
      assertNexusContentType(
        nexusRequest('{}', { 'Content-Type': 'application/nexus+json; charset=utf-8' }),
      ),
    ).not.toThrow();
    expect(() =>
      assertNexusContentType(nexusRequest('{}', { 'Content-Type': 'application/json' })),
    ).toThrowError(NexusFault);
  });

  it('rejects a browser mutation from any non-allowlisted origin', () => {
    const allowedOrigins = ['https://wallet.rowo.link'];
    expect(() =>
      assertExactRequestOrigin(
        nexusRequest('{}', { Origin: 'https://wallet.rowo.link' }),
        allowedOrigins,
      ),
    ).not.toThrow();
    expect(() =>
      assertExactRequestOrigin(nexusRequest('{}', { Origin: 'https://evil.test' }), allowedOrigins),
    ).toThrowError(NexusFault);
    expect(() => assertExactRequestOrigin(nexusRequest('{}'), allowedOrigins)).not.toThrow();
  });

  it('parses a JSON body as unknown', async () => {
    await expect(readJsonBody(nexusRequest('{"subject":"nx1_fixture"}'), 1_024)).resolves.toEqual({
      subject: 'nx1_fixture',
    });
  });

  it('rejects an invalid JSON body without echoing it', async () => {
    await expect(readJsonBody(nexusRequest('{"secret":"leak"'), 1_024)).rejects.toMatchObject({
      code: 'BAD_REQUEST',
    });
  });

  it('enforces the streamed size even without Content-Length', async () => {
    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('1234'));
        controller.enqueue(encoder.encode('5678'));
        controller.close();
      },
    });
    const request = new Request('https://nexus.rowo.link/v1/test', {
      method: 'POST',
      body: stream,
      duplex: 'half',
    } as RequestInit & { duplex: 'half' });

    await expect(readBodyBytes(request, 7)).rejects.toMatchObject({ code: 'BODY_TOO_LARGE' });
  });

  it('rejects a declared body larger than the route limit before reading', async () => {
    const request = nexusRequest('{}', { 'Content-Length': '4097' });
    await expect(readBodyBytes(request, 4_096)).rejects.toMatchObject({ code: 'BODY_TOO_LARGE' });
  });
});

describe('preflight', () => {
  it('returns exact-origin preflight headers', () => {
    const request = new Request('https://nexus.rowo.link/v1/identity/register', {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://wallet.rowo.link',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type',
      },
    });
    const response = handleExactOriginPreflight(request, {
      allowedOrigins: ['https://wallet.rowo.link'],
      allowedMethods: ['POST'],
    });

    expect(response?.status).toBe(204);
    expect(response?.headers.get('access-control-allow-origin')).toBe('https://wallet.rowo.link');
    expect(response?.headers.get('access-control-allow-credentials')).toBeNull();
  });

  it('returns a sanitized denial for an unapproved origin', async () => {
    const request = new Request('https://nexus.rowo.link/v1/identity/register', {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://evil.test',
        'Access-Control-Request-Method': 'POST',
      },
    });
    const response = handleExactOriginPreflight(request, {
      allowedOrigins: ['https://wallet.rowo.link'],
      allowedMethods: ['POST'],
    });

    expect(response?.status).toBe(403);
    await expect(response?.json()).resolves.toMatchObject({
      error: { code: 'ORIGIN_NOT_ALLOWED' },
    });
  });
});
