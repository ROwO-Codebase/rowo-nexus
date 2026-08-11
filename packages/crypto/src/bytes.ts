const textEncoder = new TextEncoder();

export function utf8Encode(value: string): Uint8Array {
  return textEncoder.encode(value);
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const part of parts) {
    totalLength += part.byteLength;
    if (!Number.isSafeInteger(totalLength)) {
      throw new RangeError('Concatenated byte length exceeds the safe integer range.');
    }
  }

  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

/**
 * Best-effort constant-work byte comparison for JavaScript runtimes.
 *
 * The loop always traverses the longer input and does not return early. JavaScript
 * engines do not promise hard constant-time execution, so protocol code should
 * still prefer Web Crypto verification for signatures and authentication tags.
 */
export function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  const comparisonLength = Math.max(left.byteLength, right.byteLength);
  let difference = left.byteLength ^ right.byteLength;

  for (let index = 0; index < comparisonLength; index += 1) {
    const leftByte = index < left.byteLength ? left[index] : 0;
    const rightByte = index < right.byteLength ? right[index] : 0;
    difference |= (leftByte ?? 0) ^ (rightByte ?? 0);
  }

  return difference === 0;
}
