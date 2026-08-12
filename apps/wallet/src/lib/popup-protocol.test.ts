import type { OwnershipProofV1, ProofRequest } from '@nexus/protocol';
import type { TrustedWalletEventBoundary } from '@nexus/wallet-core';
import { describe, expect, it, vi } from 'vitest';

import {
  NEXUS_POPUP_CHANNEL,
  NEXUS_POPUP_CHANNEL_V2,
  announceWalletReady,
  announceWalletReadyV2,
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
      popupProtocol: NEXUS_POPUP_CHANNEL,
      acceptedProofProtocols: ['nexus.ownership-proof.v1'],
    };
    const proof = {
      payload: { protocol: 'nexus.ownership-proof.v1' },
      signature: 'signature',
    } as unknown as OwnershipProofV1;

    postProofResult(pending, { proofProtocol: 'nexus.ownership-proof.v1', proof });
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

  it('strictly parses an ordered v2 allow-list and pins it to the trusted event boundary', () => {
    const channel = new MessageChannel();
    const source = channel.port1 as unknown as Window;
    const event = new MessageEvent('message', {
      source,
      origin: 'https://rp.example',
      data: {
        channel: NEXUS_POPUP_CHANNEL_V2,
        type: 'NEXUS_PROOF_REQUEST',
        requestId: REQUEST_ID,
        request: proofRequest(1_788_000_120),
        acceptedProofProtocols: ['nexus.ownership-proof.v2', 'nexus.ownership-proof.v1'],
      },
    });

    const parsed = parseProofRequestMessage(event, source, 1_788_000_000);
    expect(parsed).toMatchObject({
      popupProtocol: NEXUS_POPUP_CHANNEL_V2,
      acceptedProofProtocols: ['nexus.ownership-proof.v2', 'nexus.ownership-proof.v1'],
      origin: 'https://rp.example',
    });
    expect(parsed?.boundary.audience).toBe('https://rp.example');
  });

  it.each<readonly [readonly string[]]>([
    [[]],
    [['nexus.ownership-proof.v2', 'nexus.ownership-proof.v2']],
    [['nexus.ownership-proof.v3']],
  ])('rejects invalid v2 protocol policy %j', (acceptedProofProtocols) => {
    const channel = new MessageChannel();
    const source = channel.port1 as unknown as Window;
    const event = new MessageEvent('message', {
      source,
      origin: 'https://rp.example',
      data: {
        channel: NEXUS_POPUP_CHANNEL_V2,
        type: 'NEXUS_PROOF_REQUEST',
        requestId: REQUEST_ID,
        request: proofRequest(1_788_000_120),
        acceptedProofProtocols,
      },
    });
    expect(parseProofRequestMessage(event, source, 1_788_000_000)).toBeUndefined();
  });

  it('advertises v2 without changing the exact v1 READY envelope', () => {
    const postMessage = vi.fn();
    const opener = { postMessage } as unknown as Window;
    announceWalletReady(opener);
    announceWalletReadyV2(opener);

    expect(postMessage).toHaveBeenNthCalledWith(
      1,
      { channel: NEXUS_POPUP_CHANNEL, type: 'NEXUS_READY' },
      '*',
    );
    expect(postMessage).toHaveBeenNthCalledWith(
      2,
      {
        channel: NEXUS_POPUP_CHANNEL_V2,
        type: 'NEXUS_READY',
        supportedProofProtocols: ['nexus.ownership-proof.v2', 'nexus.ownership-proof.v1'],
      },
      '*',
    );
  });

  it('never returns a v2 proof through the v1 channel', () => {
    const pending: PendingProofRequest = {
      requestId: REQUEST_ID,
      request: proofRequest(1_788_000_120),
      origin: 'https://rp.example',
      boundary: { audience: 'https://rp.example' } as TrustedWalletEventBoundary,
      source: { postMessage: vi.fn() } as unknown as Window,
      popupProtocol: NEXUS_POPUP_CHANNEL,
      acceptedProofProtocols: ['nexus.ownership-proof.v1'],
    };

    expect(() =>
      postProofResult(pending, {
        proofProtocol: 'nexus.ownership-proof.v2',
        proof: {
          payload: { protocol: 'nexus.ownership-proof.v2' },
          deviceSignature: 'signature',
        } as never,
      }),
    ).toThrow(/not accepted|v1 popup/u);
  });

  it('rejects a result whose selected protocol disagrees with its signed payload', () => {
    const pending: PendingProofRequest = {
      requestId: REQUEST_ID,
      request: proofRequest(1_788_000_120),
      origin: 'https://rp.example',
      boundary: { audience: 'https://rp.example' } as TrustedWalletEventBoundary,
      source: { postMessage: vi.fn() } as unknown as Window,
      popupProtocol: NEXUS_POPUP_CHANNEL_V2,
      acceptedProofProtocols: ['nexus.ownership-proof.v2', 'nexus.ownership-proof.v1'],
    };

    expect(() =>
      postProofResult(pending, {
        proofProtocol: 'nexus.ownership-proof.v2',
        proof: {
          payload: { protocol: 'nexus.ownership-proof.v1' },
          deviceSignature: 'signature',
        } as never,
      }),
    ).toThrow(/does not match/u);
  });
});
