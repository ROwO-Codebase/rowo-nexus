import type { OwnershipProofV1, ProofRequest } from '@nexus/protocol';
import type { TrustedWalletEventBoundary } from '@nexus/wallet-core';
import { describe, expect, it, vi } from 'vitest';

import {
  NEXUS_POPUP_CHANNEL,
  announceWalletReady,
  parseProofRequestMessage,
  postProofError,
  postProofResult,
  type PendingProofRequest,
} from './popup-protocol';

const NONCE = 'AAAAAAAAAAAAAAAAAAAAAA';
const REQUEST_ID = 'BBBBBBBBBBBBBBBBBBBBBB';

function proofRequest(expiresAt: number): ProofRequest {
  return {
    action: 'post.edit',
    resource: 'post:example',
    nonce: NONCE as ProofRequest['nonce'],
    expiresAt,
  };
}

describe('wallet popup boundary', () => {
  it('derives the audience from the exact HTTPS MessageEvent origin', () => {
    const channel = new MessageChannel();
    const source = channel.port1 as unknown as Window;
    const event = new MessageEvent('message', {
      source,
      origin: 'https://rp.example',
      data: {
        channel: NEXUS_POPUP_CHANNEL,
        type: 'NEXUS_PROOF_REQUEST',
        requestId: REQUEST_ID,
        request: proofRequest(1_788_000_120),
      },
    });

    const parsed = parseProofRequestMessage(event, source, 1_788_000_000);
    expect(parsed?.origin).toBe('https://rp.example');
    expect(parsed?.boundary.audience).toBe('https://rp.example');
  });

  it('rejects request JSON that tries to supply its own audience', () => {
    const channel = new MessageChannel();
    const source = channel.port1 as unknown as Window;
    const event = new MessageEvent('message', {
      source,
      origin: 'https://rp.example',
      data: {
        channel: NEXUS_POPUP_CHANNEL,
        type: 'NEXUS_PROOF_REQUEST',
        requestId: REQUEST_ID,
        request: { ...proofRequest(1_788_000_120), aud: 'https://attacker.example' },
      },
    });

    expect(parseProofRequestMessage(event, source, 1_788_000_000)).toBeUndefined();
  });

  it('pins proof and error responses to the captured origin', () => {
    const postMessage = vi.fn();
    const pending: PendingProofRequest = {
      requestId: REQUEST_ID,
      request: proofRequest(1_788_000_120),
      origin: 'https://rp.example',
      boundary: { audience: 'https://rp.example' } as TrustedWalletEventBoundary,
      source: { postMessage } as unknown as Window,
    };
    const proof = { payload: {}, signature: 'signature' } as unknown as OwnershipProofV1;

    postProofResult(pending, proof);
    postProofError(pending, 'USER_CANCELLED');

    expect(postMessage).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ type: 'NEXUS_PROOF_RESULT', proof }),
      'https://rp.example',
    );
    expect(postMessage).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ type: 'NEXUS_PROOF_ERROR' }),
      'https://rp.example',
    );
    expect(postMessage).not.toHaveBeenCalledWith(expect.anything(), '*');
  });

  it('uses a wildcard only for the non-sensitive ready signal', () => {
    const postMessage = vi.fn();
    announceWalletReady({ postMessage } as unknown as Window);
    expect(postMessage).toHaveBeenCalledWith(
      { channel: NEXUS_POPUP_CHANNEL, type: 'NEXUS_READY' },
      '*',
    );
  });
});
