import type { NexusSubject } from '@nexus/protocol';
import { describe, expect, it } from 'vitest';

import { AuthoritativeRegistryLifecycleProvider } from './lifecycle.js';

describe('AuthoritativeRegistryLifecycleProvider', () => {
  it('uses the Nexus protocol media type for the fixed status endpoint', async () => {
    const subject: NexusSubject = `nx1_${'A'.repeat(43)}`;
    let requestedUrl = '';
    let requestedInit: RequestInit | undefined;
    const provider = new AuthoritativeRegistryLifecycleProvider(
      'https://nexus.rowo.link',
      (input, init) => {
        requestedUrl =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        requestedInit = init;
        return Promise.resolve(new Response(null, { status: 404 }));
      },
    );

    await expect(provider.getAuthoritativeStatus(subject)).resolves.toEqual({ state: 'not-found' });
    expect(requestedUrl).toBe('https://nexus.rowo.link/v1/identity/status');
    expect(new Headers(requestedInit?.headers).get('content-type')).toBe('application/nexus+json');
    expect(requestedInit?.method).toBe('POST');
    expect(requestedInit?.body).toBe(JSON.stringify({ subject }));
  });
});
