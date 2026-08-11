import { describe, expect, it } from 'vitest';

import inertWorker, { BACKUP_IMPLEMENTATION_STATUS } from './index.js';

describe('closed backup ADR gate', () => {
  it('exports no callable Worker handlers', () => {
    expect(BACKUP_IMPLEMENTATION_STATUS).toBe('blocked-pending-security-adr');
    expect(Object.keys(inertWorker)).toEqual([]);
  });
});
