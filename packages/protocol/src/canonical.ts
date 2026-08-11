import canonicalizeRfc8785 from 'canonicalize';

import type { JsonValue } from './types.js';

const textEncoder = new TextEncoder();

export class CanonicalizationError extends TypeError {
  public constructor(message: string) {
    super(message);
    this.name = 'CanonicalizationError';
  }
}

function containsLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function assertJsonValue(value: unknown, path: string): asserts value is JsonValue {
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'string') {
    if (containsLoneSurrogate(value)) {
      throw new CanonicalizationError(`Lone Unicode surrogate at ${path}.`);
    }
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new CanonicalizationError(`Non-finite number at ${path}.`);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value)) {
        throw new CanonicalizationError(`Sparse array entry at ${path}[${String(index)}].`);
      }
      assertJsonValue(value[index], `${path}[${String(index)}]`);
    }
    return;
  }
  if (typeof value !== 'object') {
    throw new CanonicalizationError(`Non-JSON value at ${path}.`);
  }

  const tag = Object.prototype.toString.call(value);
  if (tag !== '[object Object]') {
    throw new CanonicalizationError(`Non-plain JSON object at ${path}.`);
  }
  for (const [key, child] of Object.entries(value)) {
    if (containsLoneSurrogate(key)) {
      throw new CanonicalizationError(`Lone Unicode surrogate in key at ${path}.`);
    }
    assertJsonValue(child, `${path}.${key}`);
  }
}

export function canonicalize(value: unknown): string {
  assertJsonValue(value, '$');
  const result = canonicalizeRfc8785(value);
  if (result === undefined) {
    throw new CanonicalizationError('RFC 8785 canonicalization produced no value.');
  }
  return result;
}

export function canonicalizeToBytes(value: unknown): Uint8Array {
  return textEncoder.encode(canonicalize(value));
}
