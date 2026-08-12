import type { ProofRequest } from '@nexus/protocol';
import {
  NEXUS_POPUP_CHANNEL,
  NEXUS_POPUP_CHANNEL_V2,
  parseAcceptedProofProtocols,
  parseWalletMessage,
  parseWalletMessageV2,
  type AcceptedProofProtocols,
  type NexusNegotiatedProofResult,
  type NexusProofRequestMessage,
  type NexusProofRequestMessageV2,
  type NexusProofResultMessage,
  type NexusOwnershipProofProtocol,
  type WalletProofErrorCode,
  type WalletProofErrorCodeV2,
} from './messages.js';
import { parseProofRequest, ProofRequestValidationError } from './request-schema.js';

const DEFAULT_TIMEOUT_MS = 120_000;
const POPUP_CLOSED_POLL_MS = 100;
const DEFAULT_POPUP_FEATURES = 'popup,width=480,height=720,resizable=yes,scrollbars=yes';

export type NexusClientErrorCode =
  | 'INVALID_REQUEST'
  | 'UNSUPPORTED_ENVIRONMENT'
  | 'POPUP_BLOCKED'
  | 'POPUP_CLOSED'
  | 'USER_CANCELLED'
  | 'REQUEST_TIMEOUT'
  | 'WALLET_ERROR';

export type NexusClientErrorCodeV2 = NexusClientErrorCode | 'UNSUPPORTED_PROOF_PROTOCOL';

export class NexusClientError extends Error {
  public readonly code: NexusClientErrorCode;
  public readonly walletCode?: WalletProofErrorCode;

  public constructor(
    code: NexusClientErrorCode,
    message: string,
    options?: { cause?: unknown; walletCode?: WalletProofErrorCode },
  ) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'NexusClientError';
    this.code = code;
    if (options?.walletCode !== undefined) this.walletCode = options.walletCode;
  }
}

/**
 * Additive error surface for negotiated v2 popup requests. It extends the legacy error so existing
 * cancellation handling keeps working, while v2-only codes live on separate properties and do not
 * widen the stable `NexusClientError` contract.
 */
export class NexusClientErrorV2 extends NexusClientError {
  public readonly codeV2: NexusClientErrorCodeV2;
  public readonly walletCodeV2?: WalletProofErrorCodeV2;

  public constructor(
    codeV2: NexusClientErrorCodeV2,
    message: string,
    options?: { cause?: unknown; walletCodeV2?: WalletProofErrorCodeV2 },
  ) {
    const legacyWalletCode =
      options?.walletCodeV2 === 'UNSUPPORTED_PROOF_PROTOCOL' ? undefined : options?.walletCodeV2;
    super(codeV2 === 'UNSUPPORTED_PROOF_PROTOCOL' ? 'WALLET_ERROR' : codeV2, message, {
      ...(options?.cause === undefined ? {} : { cause: options.cause }),
      ...(legacyWalletCode === undefined ? {} : { walletCode: legacyWalletCode }),
    });
    this.name = 'NexusClientErrorV2';
    this.codeV2 = codeV2;
    if (options?.walletCodeV2 !== undefined) this.walletCodeV2 = options.walletCodeV2;
  }
}

export interface NexusClientOptions {
  walletUrl: string | URL;
  allowInsecureLocalhost?: boolean;
  timeoutMs?: number;
  popupFeatures?: string;
}

export interface RequestProofOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

export interface RequestProofV2Options extends RequestProofOptions {
  /**
   * Ordered protocol policy copied from the RP's server-issued challenge. The backend remains the
   * authority and MUST independently enforce this policy when it verifies the returned proof.
   */
  acceptedProofProtocols: AcceptedProofProtocols;
}

export type NexusProofResult = Pick<NexusProofResultMessage, 'proof'>;
export type NexusProofResultV2 = NexusNegotiatedProofResult;

export class NexusClient {
  public readonly walletOrigin: string;
  readonly #walletUrl: string;
  readonly #timeoutMs: number;
  readonly #popupFeatures: string;

  public constructor(options: NexusClientOptions) {
    const walletUrl = parseWalletUrl(options.walletUrl, options.allowInsecureLocalhost ?? false);
    this.#walletUrl = walletUrl.href;
    this.walletOrigin = walletUrl.origin;
    this.#timeoutMs = parseTimeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    this.#popupFeatures = parsePopupFeatures(options.popupFeatures ?? DEFAULT_POPUP_FEATURES);
  }

  public requestProof(
    request: ProofRequest,
    options: RequestProofOptions = {},
  ): Promise<NexusProofResult> {
    const browser = getBrowserWindow();
    const now = Math.floor(Date.now() / 1000);
    let parsed: ProofRequest;
    try {
      parsed = parseProofRequest(request, now);
    } catch (error) {
      if (error instanceof ProofRequestValidationError) {
        return Promise.reject(
          new NexusClientError('INVALID_REQUEST', error.message, { cause: error }),
        );
      }
      throw error;
    }

    const signal = options.signal;
    if (signal?.aborted === true) {
      return Promise.reject(new NexusClientError('USER_CANCELLED', 'Proof request was cancelled'));
    }

    const configuredTimeout = parseTimeout(options.timeoutMs ?? this.#timeoutMs);
    const challengeRemainingMs = Math.max(1, parsed.expiresAt * 1000 - Date.now());
    const timeoutMs = Math.min(configuredTimeout, challengeRemainingMs);
    const requestId = createRequestId(browser.crypto);

    return new Promise<NexusProofResult>((resolve, reject) => {
      let popup: Window | null = null;
      let requestSent = false;
      let settled = false;
      const timerHandles: { timeout?: number; closedPoll?: number } = {};

      const cleanup = (closePopup: boolean): void => {
        browser.removeEventListener('message', onMessage);
        if (timerHandles.timeout !== undefined) browser.clearTimeout(timerHandles.timeout);
        if (timerHandles.closedPoll !== undefined) {
          browser.clearInterval(timerHandles.closedPoll);
        }
        signal?.removeEventListener('abort', onAbort);
        if (closePopup && popup !== null && !popup.closed) {
          try {
            popup.close();
          } catch {
            // A navigated cross-origin popup can reject access; cleanup is still complete.
          }
        }
      };

      const succeed = (value: NexusProofResult): void => {
        if (settled) return;
        settled = true;
        cleanup(true);
        resolve(value);
      };

      const fail = (error: NexusClientError, closePopup = true): void => {
        if (settled) return;
        settled = true;
        cleanup(closePopup);
        reject(error);
      };

      const onAbort = (): void => {
        fail(new NexusClientError('USER_CANCELLED', 'Proof request was cancelled'));
      };

      const onMessage = (event: MessageEvent<unknown>): void => {
        if (popup === null || event.source !== popup || event.origin !== this.walletOrigin) return;
        const message = parseWalletMessage(event.data);
        if (message === undefined) return;

        if (message.type === 'NEXUS_READY') {
          if (requestSent) return;
          requestSent = true;
          const outgoing: NexusProofRequestMessage = {
            channel: NEXUS_POPUP_CHANNEL,
            type: 'NEXUS_PROOF_REQUEST',
            requestId,
            request: parsed,
          };
          try {
            popup.postMessage(outgoing, this.walletOrigin);
          } catch (error) {
            fail(
              new NexusClientError('WALLET_ERROR', 'Unable to contact Nexus wallet', {
                cause: error,
              }),
            );
          }
          return;
        }

        if (!requestSent || message.requestId !== requestId) return;
        if (message.type === 'NEXUS_PROOF_RESULT') {
          succeed({ proof: message.proof });
          return;
        }

        const code = walletErrorToClientCode(message.error.code);
        fail(
          new NexusClientError(code, walletErrorMessage(message.error.code), {
            walletCode: message.error.code,
          }),
        );
      };

      browser.addEventListener('message', onMessage);
      signal?.addEventListener('abort', onAbort, { once: true });

      try {
        popup = browser.open(this.#walletUrl, `nexus-proof-${requestId}`, this.#popupFeatures);
      } catch (error) {
        fail(
          new NexusClientError('WALLET_ERROR', 'Unable to open the Nexus wallet', { cause: error }),
          false,
        );
        return;
      }
      if (popup === null) {
        fail(new NexusClientError('POPUP_BLOCKED', 'Nexus wallet popup was blocked'), false);
        return;
      }

      timerHandles.timeout = browser.setTimeout(() => {
        fail(new NexusClientError('REQUEST_TIMEOUT', 'Nexus proof request timed out'));
      }, timeoutMs);
      timerHandles.closedPoll = browser.setInterval(() => {
        if (popup?.closed === true) {
          fail(new NexusClientError('POPUP_CLOSED', 'Nexus wallet popup was closed'), false);
        }
      }, POPUP_CLOSED_POLL_MS);
    });
  }

  /**
   * Requests a negotiated v2 popup proof. This never falls back to a v1 popup exchange: legacy
   * proofs, when explicitly allowed, are returned inside the v2 envelope with their protocol
   * selected and echoed.
   */
  public requestProofV2(
    request: ProofRequest,
    options: RequestProofV2Options,
  ): Promise<NexusProofResultV2> {
    const browser = getBrowserWindowV2();
    const acceptedProofProtocols = parseAcceptedProofProtocols(options.acceptedProofProtocols);
    if (acceptedProofProtocols === undefined) {
      return Promise.reject(
        new NexusClientErrorV2(
          'INVALID_REQUEST',
          'acceptedProofProtocols must be a non-empty, duplicate-free ordered protocol list',
        ),
      );
    }

    const now = Math.floor(Date.now() / 1000);
    let parsed: ProofRequest;
    try {
      parsed = parseProofRequest(request, now);
    } catch (error) {
      if (error instanceof ProofRequestValidationError) {
        return Promise.reject(
          new NexusClientErrorV2('INVALID_REQUEST', error.message, { cause: error }),
        );
      }
      throw error;
    }

    const signal = options.signal;
    if (signal?.aborted === true) {
      return Promise.reject(
        new NexusClientErrorV2('USER_CANCELLED', 'Proof request was cancelled'),
      );
    }

    const configuredTimeout = parseTimeoutV2(options.timeoutMs ?? this.#timeoutMs);
    const challengeRemainingMs = Math.max(1, parsed.expiresAt * 1000 - Date.now());
    const timeoutMs = Math.min(configuredTimeout, challengeRemainingMs);
    const requestId = createRequestId(browser.crypto);

    return new Promise<NexusProofResultV2>((resolve, reject) => {
      let popup: Window | null = null;
      let requestSent = false;
      let settled = false;
      let advertisedProtocols: readonly NexusOwnershipProofProtocol[] = [];
      const timerHandles: { timeout?: number; closedPoll?: number } = {};

      const cleanup = (closePopup: boolean): void => {
        browser.removeEventListener('message', onMessage);
        if (timerHandles.timeout !== undefined) browser.clearTimeout(timerHandles.timeout);
        if (timerHandles.closedPoll !== undefined) browser.clearInterval(timerHandles.closedPoll);
        signal?.removeEventListener('abort', onAbort);
        if (closePopup && popup !== null && !popup.closed) {
          try {
            popup.close();
          } catch {
            // A navigated cross-origin popup can reject access; cleanup is still complete.
          }
        }
      };

      const succeed = (value: NexusProofResultV2): void => {
        if (settled) return;
        settled = true;
        cleanup(true);
        resolve(value);
      };

      const fail = (error: NexusClientErrorV2, closePopup = true): void => {
        if (settled) return;
        settled = true;
        cleanup(closePopup);
        reject(error);
      };

      const onAbort = (): void => {
        fail(new NexusClientErrorV2('USER_CANCELLED', 'Proof request was cancelled'));
      };

      const onMessage = (event: MessageEvent<unknown>): void => {
        if (popup === null || event.source !== popup || event.origin !== this.walletOrigin) return;
        const message = parseWalletMessageV2(event.data);
        if (message === undefined) return;

        if (message.type === 'NEXUS_READY') {
          if (requestSent) return;
          advertisedProtocols = message.supportedProofProtocols;
          if (!acceptedProofProtocols.some((protocol) => advertisedProtocols.includes(protocol))) {
            fail(
              new NexusClientErrorV2(
                'UNSUPPORTED_PROOF_PROTOCOL',
                'Nexus wallet supports none of the proof protocols allowed by this challenge',
              ),
            );
            return;
          }
          requestSent = true;
          const outgoing: NexusProofRequestMessageV2 = {
            channel: NEXUS_POPUP_CHANNEL_V2,
            type: 'NEXUS_PROOF_REQUEST',
            requestId,
            request: parsed,
            acceptedProofProtocols,
          };
          try {
            popup.postMessage(outgoing, this.walletOrigin);
          } catch (error) {
            fail(
              new NexusClientErrorV2('WALLET_ERROR', 'Unable to contact Nexus wallet', {
                cause: error,
              }),
            );
          }
          return;
        }

        if (!requestSent || message.requestId !== requestId) return;
        if (message.type === 'NEXUS_PROOF_RESULT') {
          if (
            !acceptedProofProtocols.includes(message.proofProtocol) ||
            !advertisedProtocols.includes(message.proofProtocol)
          ) {
            fail(
              new NexusClientErrorV2(
                'UNSUPPORTED_PROOF_PROTOCOL',
                'Nexus wallet returned a proof protocol not allowed by this challenge',
              ),
            );
            return;
          }
          succeed({
            proofProtocol: message.proofProtocol,
            proof: message.proof,
          } as NexusProofResultV2);
          return;
        }

        const code = walletErrorToClientCodeV2(message.error.code);
        fail(
          new NexusClientErrorV2(code, walletErrorMessage(message.error.code), {
            walletCodeV2: message.error.code,
          }),
        );
      };

      browser.addEventListener('message', onMessage);
      signal?.addEventListener('abort', onAbort, { once: true });

      try {
        popup = browser.open(this.#walletUrl, `nexus-proof-${requestId}`, this.#popupFeatures);
      } catch (error) {
        fail(
          new NexusClientErrorV2('WALLET_ERROR', 'Unable to open the Nexus wallet', {
            cause: error,
          }),
          false,
        );
        return;
      }
      if (popup === null) {
        fail(new NexusClientErrorV2('POPUP_BLOCKED', 'Nexus wallet popup was blocked'), false);
        return;
      }

      timerHandles.timeout = browser.setTimeout(() => {
        fail(new NexusClientErrorV2('REQUEST_TIMEOUT', 'Nexus proof request timed out'));
      }, timeoutMs);
      timerHandles.closedPoll = browser.setInterval(() => {
        if (popup?.closed === true) {
          fail(new NexusClientErrorV2('POPUP_CLOSED', 'Nexus wallet popup was closed'), false);
        }
      }, POPUP_CLOSED_POLL_MS);
    });
  }
}

export function createNexusClient(options: NexusClientOptions): NexusClient {
  return new NexusClient(options);
}

function parseWalletUrl(value: string | URL, allowInsecureLocalhost: boolean): URL {
  let parsed: URL;
  try {
    parsed = value instanceof URL ? new URL(value.href) : new URL(value);
  } catch (error) {
    throw new NexusClientError('INVALID_REQUEST', 'walletUrl must be an absolute HTTPS URL', {
      cause: error,
    });
  }
  const isHttps = parsed.protocol === 'https:';
  const isAllowedLocalHttp =
    allowInsecureLocalhost && parsed.protocol === 'http:' && isLoopbackHostname(parsed.hostname);
  if ((!isHttps && !isAllowedLocalHttp) || parsed.origin === 'null') {
    throw new NexusClientError(
      'INVALID_REQUEST',
      'walletUrl must use HTTPS unless loopback HTTP is explicitly enabled',
    );
  }
  if (parsed.username !== '' || parsed.password !== '') {
    throw new NexusClientError('INVALID_REQUEST', 'walletUrl must not contain credentials');
  }
  if (parsed.searchParams.has('aud')) {
    throw new NexusClientError('INVALID_REQUEST', 'walletUrl must not contain an aud parameter');
  }
  return parsed;
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}

function parseTimeout(value: number): number {
  if (!Number.isFinite(value) || value <= 0) {
    throw new NexusClientError('INVALID_REQUEST', 'timeoutMs must be a positive number');
  }
  return value;
}

function parsePopupFeatures(value: string): string {
  const tokens = value
    .split(',')
    .map((token) => token.trim().toLowerCase())
    .filter((token) => token.length > 0);
  if (
    tokens.some((token) => {
      const name = token.split('=', 1)[0];
      return name === 'noopener' || name === 'noreferrer';
    })
  ) {
    throw new NexusClientError(
      'INVALID_REQUEST',
      'popupFeatures must preserve the wallet opener relationship',
    );
  }
  return value;
}

function getBrowserWindow(): Window {
  if (typeof window === 'undefined') {
    throw new NexusClientError(
      'UNSUPPORTED_ENVIRONMENT',
      'Nexus browser SDK requires a Window environment',
    );
  }
  return window;
}

function getBrowserWindowV2(): Window {
  if (typeof window === 'undefined') {
    throw new NexusClientErrorV2(
      'UNSUPPORTED_ENVIRONMENT',
      'Nexus browser SDK requires a Window environment',
    );
  }
  return window;
}

function parseTimeoutV2(value: number): number {
  if (!Number.isFinite(value) || value <= 0) {
    throw new NexusClientErrorV2('INVALID_REQUEST', 'timeoutMs must be a positive number');
  }
  return value;
}

function createRequestId(crypto: Crypto): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let binary = '';
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function walletErrorToClientCode(code: WalletProofErrorCode): NexusClientErrorCode {
  if (code === 'USER_CANCELLED') return 'USER_CANCELLED';
  if (code === 'POPUP_CLOSED') return 'POPUP_CLOSED';
  if (code === 'INVALID_REQUEST' || code === 'CHALLENGE_EXPIRED') return 'INVALID_REQUEST';
  return 'WALLET_ERROR';
}

function walletErrorToClientCodeV2(code: WalletProofErrorCodeV2): NexusClientErrorCodeV2 {
  if (code === 'UNSUPPORTED_PROOF_PROTOCOL') return 'UNSUPPORTED_PROOF_PROTOCOL';
  return walletErrorToClientCode(code);
}

function walletErrorMessage(code: WalletProofErrorCode | WalletProofErrorCodeV2): string {
  switch (code) {
    case 'USER_CANCELLED':
      return 'Proof request was cancelled';
    case 'POPUP_CLOSED':
      return 'Nexus wallet popup was closed';
    case 'INVALID_REQUEST':
      return 'Nexus wallet rejected the proof request';
    case 'CHALLENGE_EXPIRED':
      return 'Nexus challenge has expired';
    case 'NO_ACTIVE_IDENTITY':
      return 'Nexus wallet has no active identity available';
    case 'REGISTRATION_FAILED':
      return 'Nexus identity registration failed';
    case 'INTERNAL_ERROR':
      return 'Nexus wallet could not complete the request';
    case 'UNSUPPORTED_PROOF_PROTOCOL':
      return 'Nexus wallet cannot issue an allowed proof protocol';
  }
}
