export const SHARD_COUNT = 256;

export function resolveShardId(eventHash: Uint8Array): string {
  if (eventHash.byteLength !== 32) {
    throw new Error('A registry event hash must be exactly 32 bytes.');
  }
  const firstByte = eventHash[0];
  if (firstByte === undefined) {
    throw new Error('A registry event hash cannot be empty.');
  }
  return firstByte.toString(16).padStart(2, '0');
}

export function isShardId(value: string): boolean {
  return /^[0-9a-f]{2}$/.test(value);
}
