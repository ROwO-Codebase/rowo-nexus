import { canonicalizeToBytes, encodeBase64Url } from '@nexus/protocol';

const encoder = new TextEncoder();

export function secureToken(byteLength = 32): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

export async function sha256Base64Url(value: string | Uint8Array): Promise<string> {
  const bytes = typeof value === 'string' ? encoder.encode(value) : value;
  const input = new Uint8Array(bytes.byteLength);
  input.set(bytes);
  return encodeBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', input.buffer)));
}

export async function canonicalSha256(value: unknown): Promise<string> {
  return await sha256Base64Url(canonicalizeToBytes(value));
}

export function constantTimeTextEqual(left: string, right: string): boolean {
  const length = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < length; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}
