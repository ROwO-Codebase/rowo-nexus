import { describe, expect, it, vi } from 'vitest';

import {
  createJsonConsoleSink,
  createRequestId,
  emitAggregateMetric,
  latencyBucket,
  sizeBucket,
  type PrivacySafeAggregateRecord,
} from '../src/logging.js';

describe('privacy-safe operational helpers', () => {
  it('creates an opaque per-request identifier from injected random bytes', () => {
    const requestId = createRequestId((target) => {
      target.fill(0xa5);
      return target;
    });
    expect(requestId).toBe('nxr_paWlpaWlpaWlpaWlpaWlpQ');
  });

  it('projects metrics onto an allowlisted aggregate record', () => {
    const records: PrivacySafeAggregateRecord[] = [];
    const untrustedMetric = {
      operation: 'register' as const,
      result: 'ok' as const,
      latencyBucket: 'lt50ms' as const,
      subject: 'nx1_must_not_be_logged',
    };
    emitAggregateMetric({ write: (record) => records.push(record) }, untrustedMetric);

    expect(records).toEqual([
      {
        event: 'api_result',
        operation: 'register',
        result: 'ok',
        latencyBucket: 'lt50ms',
      },
    ]);
    expect(JSON.stringify(records)).not.toContain('nx1_must_not_be_logged');
  });

  it('emits only the projected record to the JSON console sink', () => {
    const info = vi.fn();
    const sink = createJsonConsoleSink({ info });
    emitAggregateMetric(sink, {
      operation: 'revoke',
      result: 'rejected',
      errorCode: 'INVALID_SIGNATURE',
      latencyBucket: 'lt10ms',
    });
    expect(info).toHaveBeenCalledWith(
      '{"event":"api_result","operation":"revoke","result":"rejected","latencyBucket":"lt10ms","errorCode":"INVALID_SIGNATURE"}',
    );
  });

  it('uses stable aggregate buckets', () => {
    expect(latencyBucket(49)).toBe('lt50ms');
    expect(latencyBucket(1_000)).toBe('gte1s');
    expect(sizeBucket(0)).toBe('0');
    expect(sizeBucket(100)).toBe('51-100');
  });
});
