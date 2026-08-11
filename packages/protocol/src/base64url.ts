const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/u;

export class Base64UrlError extends TypeError {
  public constructor(message: string) {
    super(message);
    this.name = 'Base64UrlError';
  }
}

function bytesToBinary(bytes: Uint8Array): string {
  let output = '';
  for (let index = 0; index < bytes.length; index += 1) {
    output += String.fromCharCode(bytes[index] ?? 0);
  }
  return output;
}

export function encodeBase64Url(bytes: Uint8Array): string {
  return btoa(bytesToBinary(bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

export function decodeBase64Url(value: string): Uint8Array {
  if (!BASE64URL_PATTERN.test(value) || value.length % 4 === 1) {
    throw new Base64UrlError('Value is not unpadded base64url.');
  }

  const base64 = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');

  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new Base64UrlError('Value is not valid base64url.');
  }

  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64Url(bytes) !== value) {
    throw new Base64UrlError('Value is not canonically encoded base64url.');
  }
  return bytes;
}

export function decodeBase64UrlExact(value: string, byteLength: number): Uint8Array {
  if (!Number.isSafeInteger(byteLength) || byteLength < 0) {
    throw new RangeError('byteLength must be a non-negative safe integer.');
  }
  const bytes = decodeBase64Url(value);
  if (bytes.length !== byteLength) {
    throw new Base64UrlError(`Expected ${String(byteLength)} decoded bytes.`);
  }
  return bytes;
}

export function decodeBase64UrlMinimum(value: string, minimumBytes: number): Uint8Array {
  if (!Number.isSafeInteger(minimumBytes) || minimumBytes < 0) {
    throw new RangeError('minimumBytes must be a non-negative safe integer.');
  }
  const bytes = decodeBase64Url(value);
  if (bytes.length < minimumBytes) {
    throw new Base64UrlError(`Expected at least ${String(minimumBytes)} decoded bytes.`);
  }
  return bytes;
}
