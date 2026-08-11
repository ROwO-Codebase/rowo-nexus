import { WalletCoreError } from './errors.js';
import type { TrustedWalletEventBoundary } from './types.js';

const trustedBoundaries = new WeakSet<object>();

function validateAudience(origin: string): string {
  let url: URL;
  try {
    url = new URL(origin);
  } catch (error) {
    throw new WalletCoreError('UNTRUSTED_WALLET_EVENT', 'The wallet event origin is invalid.', {
      cause: error,
    });
  }

  if (
    url.protocol !== 'https:' ||
    url.origin !== origin ||
    url.username !== '' ||
    url.password !== '' ||
    origin.includes('*')
  ) {
    throw new WalletCoreError(
      'UNTRUSTED_WALLET_EVENT',
      'The wallet event must carry an exact HTTPS origin.',
    );
  }
  return origin;
}

/**
 * This is the only public constructor for a proof audience. Wallet message
 * handlers must call it with the actual MessageEvent received from the browser.
 */
export function captureWalletEventBoundary(
  event: MessageEvent<unknown>,
): TrustedWalletEventBoundary {
  if (
    typeof MessageEvent === 'undefined' ||
    !(event instanceof MessageEvent) ||
    typeof event.origin !== 'string'
  ) {
    throw new WalletCoreError(
      'UNTRUSTED_WALLET_EVENT',
      'A browser MessageEvent is required at the wallet boundary.',
    );
  }
  const boundary = Object.freeze({ audience: validateAudience(event.origin) });
  trustedBoundaries.add(boundary);
  return boundary as TrustedWalletEventBoundary;
}

export function requireTrustedWalletEventBoundary(
  boundary: TrustedWalletEventBoundary,
): TrustedWalletEventBoundary {
  if (typeof boundary !== 'object' || boundary === null || !trustedBoundaries.has(boundary)) {
    throw new WalletCoreError(
      'UNTRUSTED_WALLET_EVENT',
      'The proof audience did not come from the wallet MessageEvent boundary.',
    );
  }
  return boundary;
}
