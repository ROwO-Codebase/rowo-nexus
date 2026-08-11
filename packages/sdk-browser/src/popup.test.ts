import { proofRequestSchema, type ProofRequest } from '@nexus/protocol';
import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from 'vitest';
import { NexusClient, NexusClientError } from './popup.js';

const WALLET_ORIGIN = 'https://wallet.nexus.test';
const RP_ORIGIN = 'https://rp-a.test';

interface FakePopup {
  closed: boolean;
  close: Mock<() => void>;
  postMessage: Mock<(message: unknown, targetOrigin: string) => void>;
}

interface FakeBrowser {
  crypto: Crypto;
  listeners: Set<(event: MessageEvent<unknown>) => void>;
  open: Mock<(url?: string, target?: string, features?: string) => FakePopup | null>;
  emit(data: unknown, origin?: string, source?: unknown): void;
}

function makePopup(): FakePopup {
  const popup: FakePopup = {
    closed: false,
    close: vi.fn(() => {
      popup.closed = true;
    }),
    postMessage: vi.fn<(message: unknown, targetOrigin: string) => void>(),
  };
  return popup;
}

function installBrowser(popup: FakePopup | null): FakeBrowser {
  const listeners = new Set<(event: MessageEvent<unknown>) => void>();
  const browser: FakeBrowser = {
    crypto: globalThis.crypto,
    listeners,
    open: vi.fn<(url?: string, target?: string, features?: string) => FakePopup | null>(
      () => popup,
    ),
    emit(data, origin = WALLET_ORIGIN, source = popup): void {
      const event = { data, origin, source } as MessageEvent<unknown>;
      for (const listener of [...listeners]) listener(event);
    },
  };

  const windowMock = {
    crypto: browser.crypto,
    open: browser.open,
    addEventListener: vi.fn(
      (type: string, listener: (event: MessageEvent<unknown>) => void): void => {
        if (type === 'message') listeners.add(listener);
      },
    ),
    removeEventListener: vi.fn(
      (type: string, listener: (event: MessageEvent<unknown>) => void): void => {
        if (type === 'message') listeners.delete(listener);
      },
    ),
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    setInterval: globalThis.setInterval.bind(globalThis),
    clearInterval: globalThis.clearInterval.bind(globalThis),
  };
  vi.stubGlobal('window', windowMock);
  return browser;
}

function validRequest(): ProofRequest {
  return proofRequestSchema.parse({
    action: 'post.edit',
    resource: 'post:01JABC',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAA',
    expiresAt: Math.floor(Date.now() / 1000) + 60,
    contextHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  });
}

function ready(): unknown {
  return { channel: 'nexus.popup.v1', type: 'NEXUS_READY' };
}

function sentRequest(popup: FakePopup): {
  requestId: string;
  request: Record<string, unknown>;
} {
  const firstCall = popup.postMessage.mock.calls[0];
  if (firstCall === undefined) throw new Error('Expected popup postMessage call');
  return firstCall[0] as { requestId: string; request: Record<string, unknown> };
}

describe('NexusClient popup transport', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-08-11T00:00:00.000Z'));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('sends a request only after READY and uses the exact wallet origin', async () => {
    const popup = makePopup();
    const browser = installBrowser(popup);
    const client = new NexusClient({ walletUrl: `${WALLET_ORIGIN}/approve` });
    const resultPromise = client.requestProof(validRequest());

    expect(popup.postMessage).not.toHaveBeenCalled();
    browser.emit(ready());
    expect(popup.postMessage).toHaveBeenCalledTimes(1);
    expect(popup.postMessage.mock.calls[0]?.[1]).toBe(WALLET_ORIGIN);
    expect(sentRequest(popup).request).not.toHaveProperty('aud');

    const requestId = sentRequest(popup).requestId;
    const proof = { payload: { protocol: 'nexus.ownership-proof.v1' }, signature: 'fixture' };
    browser.emit({
      channel: 'nexus.popup.v1',
      type: 'NEXUS_PROOF_RESULT',
      requestId,
      proof,
    });

    await expect(resultPromise).resolves.toEqual({ proof });
    expect(browser.listeners.size).toBe(0);
    expect(popup.close).toHaveBeenCalledOnce();
  });

  it('ignores messages from the wrong origin, source, or requestId', async () => {
    const popup = makePopup();
    const browser = installBrowser(popup);
    const client = new NexusClient({ walletUrl: WALLET_ORIGIN });
    const resultPromise = client.requestProof(validRequest());

    browser.emit(ready(), 'https://evil.test');
    browser.emit(ready(), WALLET_ORIGIN, makePopup());
    expect(popup.postMessage).not.toHaveBeenCalled();

    browser.emit(ready());
    const requestId = sentRequest(popup).requestId;
    browser.emit({
      channel: 'nexus.popup.v1',
      type: 'NEXUS_PROOF_RESULT',
      requestId: 'AAAAAAAAAAAAAAAAAAAAAA',
      proof: { payload: {}, signature: 'wrong' },
    });
    expect(popup.close).not.toHaveBeenCalled();

    const proof = { payload: {}, signature: 'right' };
    browser.emit({ channel: 'nexus.popup.v1', type: 'NEXUS_PROOF_RESULT', requestId, proof });
    await expect(resultPromise).resolves.toEqual({ proof });
  });

  it('rejects caller-supplied aud before opening the popup', async () => {
    const popup = makePopup();
    const browser = installBrowser(popup);
    const client = new NexusClient({ walletUrl: WALLET_ORIGIN });
    const request = { ...validRequest(), aud: 'https://attacker.test' };

    await expect(client.requestProof(request as never)).rejects.toMatchObject({
      code: 'INVALID_REQUEST',
    });
    expect(browser.open).not.toHaveBeenCalled();
    expect(browser.listeners.size).toBe(0);
  });

  it('rejects popup features that sever the opener relationship', () => {
    expect(
      () =>
        new NexusClient({
          walletUrl: WALLET_ORIGIN,
          popupFeatures: 'popup,width=480,noopener',
        }),
    ).toThrowError(NexusClientError);
  });

  it('rejects loopback HTTP unless explicitly enabled', () => {
    expect(() => new NexusClient({ walletUrl: 'http://localhost:5173/approve' })).toThrowError(
      NexusClientError,
    );
  });

  it.each([
    'http://localhost:5173/approve',
    'http://127.0.0.1:5173/approve',
    'http://[::1]:5173/approve',
  ])('allows explicitly enabled loopback HTTP wallet URL %s', (walletUrl) => {
    const client = new NexusClient({ walletUrl, allowInsecureLocalhost: true });
    expect(client.walletOrigin).toBe(new URL(walletUrl).origin);
  });

  it.each([
    'http://example.test/approve',
    'http://localhost.example.test/approve',
    'http://0.0.0.0:5173/approve',
    'http://192.168.1.10:5173/approve',
  ])('never allows non-loopback HTTP wallet URL %s', (walletUrl) => {
    expect(() => new NexusClient({ walletUrl, allowInsecureLocalhost: true })).toThrowError(
      NexusClientError,
    );
  });

  it('preserves credential and aud rejection for enabled loopback HTTP', () => {
    expect(
      () =>
        new NexusClient({
          walletUrl: 'http://user:password@localhost:5173/approve',
          allowInsecureLocalhost: true,
        }),
    ).toThrowError(NexusClientError);
    expect(
      () =>
        new NexusClient({
          walletUrl: 'http://localhost:5173/approve?aud=https://rp-a.test',
          allowInsecureLocalhost: true,
        }),
    ).toThrowError(NexusClientError);
  });

  it('rejects a blocked popup and removes its message listener', async () => {
    const browser = installBrowser(null);
    const client = new NexusClient({ walletUrl: WALLET_ORIGIN });

    await expect(client.requestProof(validRequest())).rejects.toMatchObject({
      code: 'POPUP_BLOCKED',
    });
    expect(browser.listeners.size).toBe(0);
  });

  it('rejects and cleans up when the popup closes', async () => {
    const popup = makePopup();
    const browser = installBrowser(popup);
    const client = new NexusClient({ walletUrl: WALLET_ORIGIN });
    const resultPromise = client.requestProof(validRequest());
    const rejection = expect(resultPromise).rejects.toMatchObject({ code: 'POPUP_CLOSED' });
    popup.closed = true;

    await vi.advanceTimersByTimeAsync(100);
    await rejection;
    expect(browser.listeners.size).toBe(0);
  });

  it('maps explicit wallet cancellation and cleans up', async () => {
    const popup = makePopup();
    const browser = installBrowser(popup);
    const client = new NexusClient({ walletUrl: WALLET_ORIGIN });
    const resultPromise = client.requestProof(validRequest());
    browser.emit(ready());

    browser.emit({
      channel: 'nexus.popup.v1',
      type: 'NEXUS_PROOF_ERROR',
      requestId: sentRequest(popup).requestId,
      error: { code: 'USER_CANCELLED' },
    });

    await expect(resultPromise).rejects.toMatchObject({
      code: 'USER_CANCELLED',
      walletCode: 'USER_CANCELLED',
    });
    expect(browser.listeners.size).toBe(0);
    expect(popup.close).toHaveBeenCalledOnce();
  });

  it('times out, closes the popup, and removes listeners', async () => {
    const popup = makePopup();
    const browser = installBrowser(popup);
    const client = new NexusClient({ walletUrl: WALLET_ORIGIN, timeoutMs: 500 });
    const resultPromise = client.requestProof(validRequest());
    const rejection = expect(resultPromise).rejects.toMatchObject({ code: 'REQUEST_TIMEOUT' });

    await vi.advanceTimersByTimeAsync(500);
    await rejection;
    expect(browser.listeners.size).toBe(0);
    expect(popup.close).toHaveBeenCalledOnce();
  });

  it('supports AbortSignal cancellation', async () => {
    const popup = makePopup();
    const browser = installBrowser(popup);
    const controller = new AbortController();
    const client = new NexusClient({ walletUrl: WALLET_ORIGIN });
    const resultPromise = client.requestProof(validRequest(), { signal: controller.signal });
    controller.abort();

    await expect(resultPromise).rejects.toMatchObject({ code: 'USER_CANCELLED' });
    expect(browser.listeners.size).toBe(0);
    expect(popup.close).toHaveBeenCalledOnce();
  });

  it('ignores malformed envelopes with extra fields', async () => {
    const popup = makePopup();
    const browser = installBrowser(popup);
    const client = new NexusClient({ walletUrl: WALLET_ORIGIN, timeoutMs: 500 });
    const resultPromise = client.requestProof(validRequest());
    const rejection = expect(resultPromise).rejects.toBeInstanceOf(NexusClientError);

    browser.emit({ channel: 'nexus.popup.v1', type: 'NEXUS_READY', aud: RP_ORIGIN });
    expect(popup.postMessage).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(500);
    await rejection;
  });
});
