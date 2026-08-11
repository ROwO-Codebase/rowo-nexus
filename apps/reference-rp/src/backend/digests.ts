import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import { canonicalizeToBytes, encodeBase64Url } from '@nexus/protocol';

export function secureToken(byteLength = 32): string {
  return encodeBase64Url(randomBytes(byteLength));
}

export function sha256Base64Url(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('base64url');
}

export function canonicalSha256(value: unknown): string {
  return sha256Base64Url(canonicalizeToBytes(value));
}

export function constantTimeTextEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}
