export function bytesFromHex(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/u.test(value)) {
    throw new TypeError('Expected lowercase, even-length hexadecimal.');
  }
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function replaceFirstBase64UrlCharacter(value: string): string {
  if (value.length === 0) throw new TypeError('Cannot alter an empty base64url value.');
  return `${value[0] === 'A' ? 'B' : 'A'}${value.slice(1)}`;
}
