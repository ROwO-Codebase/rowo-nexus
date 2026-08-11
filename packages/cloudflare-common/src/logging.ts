import { isNexusErrorCode, type NexusErrorCode } from './errors.js';

export const AGGREGATE_OPERATIONS = [
  'discovery',
  'jwks',
  'register',
  'status',
  'status_batch',
  'revoke',
  'project_event',
  'publish_outbox',
  'transparency_append',
  'transparency_include',
  'notary_stamp',
] as const;

export type AggregateOperation = (typeof AGGREGATE_OPERATIONS)[number];
export type AggregateResult = 'ok' | 'error' | 'rejected';
export type LatencyBucket = 'lt10ms' | 'lt50ms' | 'lt100ms' | 'lt500ms' | 'lt1s' | 'gte1s';
export type SizeBucket = '0' | '1' | '2-10' | '11-50' | '51-100' | 'gt100';

export interface AggregateMetric {
  readonly operation: AggregateOperation;
  readonly result: AggregateResult;
  readonly latencyBucket: LatencyBucket;
  readonly errorCode?: NexusErrorCode;
  readonly sizeBucket?: SizeBucket;
}

export interface PrivacySafeAggregateRecord extends AggregateMetric {
  readonly event: 'api_result';
}

export interface AggregateMetricSink {
  write(record: PrivacySafeAggregateRecord): void;
}

export type RandomFill = (target: Uint8Array) => Uint8Array;

function defaultRandomFill(target: Uint8Array): Uint8Array {
  return crypto.getRandomValues(target);
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

export function createRequestId(randomFill: RandomFill = defaultRandomFill): string {
  const random = randomFill(new Uint8Array(16));
  if (random.byteLength !== 16) {
    throw new TypeError('randomFill must return the supplied 16-byte buffer');
  }
  return `nxr_${encodeBase64Url(random)}`;
}

export function latencyBucket(milliseconds: number): LatencyBucket {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) {
    throw new RangeError('milliseconds must be a non-negative finite number');
  }
  if (milliseconds < 10) return 'lt10ms';
  if (milliseconds < 50) return 'lt50ms';
  if (milliseconds < 100) return 'lt100ms';
  if (milliseconds < 500) return 'lt500ms';
  if (milliseconds < 1_000) return 'lt1s';
  return 'gte1s';
}

export function sizeBucket(size: number): SizeBucket {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new RangeError('size must be a non-negative safe integer');
  }
  if (size === 0) return '0';
  if (size === 1) return '1';
  if (size <= 10) return '2-10';
  if (size <= 50) return '11-50';
  if (size <= 100) return '51-100';
  return 'gt100';
}

function assertMetric(metric: AggregateMetric): void {
  if (!(AGGREGATE_OPERATIONS as readonly string[]).includes(metric.operation)) {
    throw new TypeError('Unsupported aggregate operation');
  }
  if (!(metric.result === 'ok' || metric.result === 'error' || metric.result === 'rejected')) {
    throw new TypeError('Unsupported aggregate result');
  }
  if (metric.errorCode !== undefined && !isNexusErrorCode(metric.errorCode)) {
    throw new TypeError('Unsupported aggregate error code');
  }
}

export function emitAggregateMetric(sink: AggregateMetricSink, metric: AggregateMetric): void {
  assertMetric(metric);
  const record: PrivacySafeAggregateRecord = Object.freeze({
    event: 'api_result',
    operation: metric.operation,
    result: metric.result,
    latencyBucket: metric.latencyBucket,
    ...(metric.errorCode === undefined ? {} : { errorCode: metric.errorCode }),
    ...(metric.sizeBucket === undefined ? {} : { sizeBucket: metric.sizeBucket }),
  });
  sink.write(record);
}

export function createJsonConsoleSink(output: Pick<Console, 'info'>): AggregateMetricSink {
  return {
    write(record): void {
      output.info(JSON.stringify(record));
    },
  };
}
