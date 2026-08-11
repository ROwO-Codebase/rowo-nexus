import { describe, expect, it } from 'vitest';

import {
  createApiHeaders,
  createCorsHeaders,
  createWalletHeaders,
  createWellKnownHeaders,
  isExactOriginAllowed,
  parseExactOrigin,
} from '../src/headers.js';

describe('security and privacy headers', () => {
  it('sets no-store protocol API headers', () => {
    const headers = createApiHeaders({ 'X-Request-ID': 'nxr_fixture' });
    expect(headers.get('cache-control')).toBe('no-store');
    expect(headers.get('content-type')).toBe('application/nexus+json');
    expect(headers.get('referrer-policy')).toBe('no-referrer');
    expect(headers.get('x-content-type-options')).toBe('nosniff');
    expect(headers.get('x-request-id')).toBe('nxr_fixture');
  });

  it('allows short controlled caching for well-known responses', () => {
    const headers = createWellKnownHeaders({ maxAgeSeconds: 120, etag: '"fixture"' });
    expect(headers.get('cache-control')).toBe('public, max-age=120, must-revalidate');
    expect(headers.get('access-control-allow-origin')).toBe('*');
    expect(headers.get('etag')).toBe('"fixture"');
  });

  it('builds a wallet CSP without third-party script execution', () => {
    const headers = createWalletHeaders({ apiOrigin: 'https://nexus.rowo.link' });
    const csp = headers.get('content-security-policy');
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain('connect-src https://nexus.rowo.link');
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('unsafe-eval');
  });
});

describe('exact-origin CORS', () => {
  it('normalizes only complete HTTP(S) origins', () => {
    expect(parseExactOrigin('https://wallet.rowo.link')).toBe('https://wallet.rowo.link');
    expect(parseExactOrigin('https://wallet.rowo.link/path')).toBeNull();
    expect(parseExactOrigin('data:text/plain,test')).toBeNull();
  });

  it('does not accept prefix, suffix, or path lookalikes', () => {
    const allowed = ['https://wallet.rowo.link'];
    expect(isExactOriginAllowed('https://wallet.rowo.link', allowed)).toBe(true);
    expect(isExactOriginAllowed('https://wallet.rowo.link.evil.test', allowed)).toBe(false);
    expect(isExactOriginAllowed('https://evil.test/https://wallet.rowo.link', allowed)).toBe(false);
  });

  it('echoes only an allowed mutation origin and never enables credentials', () => {
    const allowed = createCorsHeaders('https://wallet.rowo.link', {
      mode: 'exact',
      allowedOrigins: ['https://wallet.rowo.link'],
    });
    const denied = createCorsHeaders('https://evil.test', {
      mode: 'exact',
      allowedOrigins: ['https://wallet.rowo.link'],
    });

    expect(allowed.get('access-control-allow-origin')).toBe('https://wallet.rowo.link');
    expect(allowed.get('access-control-allow-credentials')).toBeNull();
    expect(denied.get('access-control-allow-origin')).toBeNull();
    expect(denied.get('vary')).toBe('Origin');
  });

  it('permits wildcard CORS only through the public policy', () => {
    const headers = createCorsHeaders(null, { mode: 'public' });
    expect(headers.get('access-control-allow-origin')).toBe('*');
    expect(headers.get('access-control-allow-credentials')).toBeNull();
  });
});
