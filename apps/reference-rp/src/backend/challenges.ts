import type { Base64UrlAtLeast16 } from '@nexus/protocol';
import type { ChallengeRecord, ChallengeStore } from '@nexus/verifier';

import type { IssuedChallenge, ProofAction } from '../shared/contracts.js';
import { sha256Base64Url } from './digests.js';

interface StoredChallenge {
  challengeId: string;
  nonceHash: string;
  action: ProofAction;
  resource: string;
  contextHash: string;
  expiresAt: number;
  consumedAt: number | null;
}

export class HashOnlyChallengeStore implements ChallengeStore {
  readonly #byId = new Map<string, StoredChallenge>();
  readonly #byNonceHash = new Map<string, StoredChallenge>();

  public insert(challenge: IssuedChallenge): void {
    const record: StoredChallenge = {
      challengeId: challenge.challengeId,
      nonceHash: sha256Base64Url(challenge.nonce),
      action: challenge.action as ProofAction,
      resource: challenge.resource,
      contextHash: challenge.contextHash ?? '',
      expiresAt: challenge.expiresAt,
      consumedAt: null,
    };
    this.#byId.set(record.challengeId, record);
    this.#byNonceHash.set(record.nonceHash, record);
  }

  public getById(challengeId: string): StoredChallenge | null {
    return this.#byId.get(challengeId) ?? null;
  }

  public get(nonce: string): Promise<ChallengeRecord | null> {
    const stored = this.#byNonceHash.get(sha256Base64Url(nonce));
    if (stored === undefined) return Promise.resolve(null);
    return Promise.resolve({
      nonce,
      action: stored.action,
      resource: stored.resource,
      expiresAt: stored.expiresAt,
      consumed: stored.consumedAt !== null,
    });
  }

  public consumeAtomically(nonce: string): Promise<boolean> {
    const stored = this.#byNonceHash.get(sha256Base64Url(nonce));
    if (stored === undefined || stored.consumedAt !== null) return Promise.resolve(false);
    stored.consumedAt = Math.floor(Date.now() / 1000);
    return Promise.resolve(true);
  }

  public debugSnapshot(): readonly Readonly<StoredChallenge>[] {
    return [...this.#byId.values()].map((record) => ({ ...record }));
  }
}

export function asNonce(value: string): Base64UrlAtLeast16 {
  return value as Base64UrlAtLeast16;
}
