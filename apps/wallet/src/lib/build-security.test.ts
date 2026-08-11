import { describe, expect, it } from 'vitest';

import {
  CANONICAL_NEXUS_API_ORIGIN,
  LOCAL_NEXUS_API_ORIGIN,
  renderWalletHeaders,
  resolveNexusApiOrigin,
} from '../../vite.config';

describe('wallet API origin and generated security headers', () => {
  it('uses canonical HTTPS in production and loopback only in development', () => {
    expect(resolveNexusApiOrigin(undefined, 'production')).toBe(CANONICAL_NEXUS_API_ORIGIN);
    expect(resolveNexusApiOrigin(undefined, 'development')).toBe(LOCAL_NEXUS_API_ORIGIN);
  });

  it('rejects insecure production and non-origin API URLs', () => {
    expect(() => resolveNexusApiOrigin('http://localhost:8787', 'production')).toThrow(/HTTPS/u);
    expect(() => resolveNexusApiOrigin('https://api.example/v1', 'production')).toThrow(
      /exact origin/u,
    );
    expect(() => resolveNexusApiOrigin('https://api.example?target=other', 'production')).toThrow(
      /exact origin/u,
    );
  });

  it('pins connect-src to self and the configured origin without weakening scripts', () => {
    const headers = renderWalletHeaders('https://staging-nexus.rowo.link');
    expect(headers).toContain("connect-src 'self' https://staging-nexus.rowo.link;");
    expect(headers).toContain("script-src 'self';");
    expect(headers).not.toContain("script-src 'self' 'unsafe-inline'");
    expect(headers).not.toContain('connect-src https:');
  });
});
