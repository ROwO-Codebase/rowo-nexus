import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { buildTestVectorFiles } from '../src/generate.js';
import { verifyTestVectorDirectory } from '../src/verify.js';

const vectorDirectory = new URL('../vectors/', import.meta.url);

describe('committed Nexus test vectors', () => {
  it('are reproduced byte-for-byte by the deterministic generator', async () => {
    const generated = await buildTestVectorFiles();
    for (const [name, expectedContents] of generated) {
      await expect(readFile(new URL(name, vectorDirectory), 'utf8')).resolves.toBe(
        expectedContents,
      );
    }
  });

  it('pass independent protocol, crypto, and verifier checks', async () => {
    const verified = await verifyTestVectorDirectory(vectorDirectory);
    expect(verified).toContain('continuity-link');
    expect(verified).toContain('ownership-proof-v2');
    expect(verified).toHaveLength(18);
  });
});
