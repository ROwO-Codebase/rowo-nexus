import { describe, expect, it } from 'vitest';

import { isShardId, resolveShardId } from './sharding.js';

describe('transparency shard resolver', () => {
  it('uses the first event-hash byte as two lowercase hex digits', () => {
    const eventHash = new Uint8Array(32);
    eventHash[0] = 0xaf;
    expect(resolveShardId(eventHash)).toBe('af');
  });

  it('rejects non-SHA-256 input lengths', () => {
    expect(() => resolveShardId(new Uint8Array(31))).toThrow(/32 bytes/);
  });

  it('accepts only canonical shard IDs', () => {
    expect(isShardId('00')).toBe(true);
    expect(isShardId('ff')).toBe(true);
    expect(isShardId('FF')).toBe(false);
    expect(isShardId('000')).toBe(false);
  });
});
