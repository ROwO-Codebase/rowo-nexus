export const NEXUS_ERROR_CODES = [
  'BAD_REQUEST',
  'UNSUPPORTED_PROTOCOL',
  'UNSUPPORTED_SUITE',
  'INVALID_SUBJECT',
  'INVALID_SIGNATURE',
  'INVALID_REVOCATION_SECRET',
  'IDENTITY_NOT_FOUND',
  'IDENTITY_REVOKED',
  'SEQUENCE_CONFLICT',
  'SUBJECT_GENESIS_CONFLICT',
  'RATE_LIMITED',
  'TURNSTILE_REQUIRED',
  'TURNSTILE_INVALID',
  'BODY_TOO_LARGE',
  'METHOD_NOT_ALLOWED',
  'UNSUPPORTED_MEDIA_TYPE',
  'ORIGIN_NOT_ALLOWED',
  'HTTPS_REQUIRED',
  'INTERNAL_ERROR',
  'SERVICE_UNAVAILABLE',
] as const;

export const NEXUS_DEVICE_ERROR_CODES = [
  ...NEXUS_ERROR_CODES,
  'DEVICE_NOT_FOUND',
  'DEVICE_REVOKED',
  'DEVICE_AUTHORIZATION_CONFLICT',
] as const;

export type NexusErrorCode = (typeof NEXUS_ERROR_CODES)[number];
export type NexusDeviceErrorCode = (typeof NEXUS_DEVICE_ERROR_CODES)[number];

export interface NexusErrorBody {
  readonly error: {
    readonly code: NexusErrorCode;
    readonly message: string;
    readonly requestId?: string;
  };
}

export interface NexusDeviceErrorBody {
  readonly error: {
    readonly code: NexusDeviceErrorCode;
    readonly message: string;
    readonly requestId?: string;
  };
}

interface ErrorDefinition {
  readonly status: number;
  readonly message: string;
}

const ERROR_DEFINITIONS: Readonly<Record<NexusDeviceErrorCode, ErrorDefinition>> = {
  BAD_REQUEST: { status: 400, message: 'The request is invalid.' },
  UNSUPPORTED_PROTOCOL: { status: 400, message: 'The protocol version is not supported.' },
  UNSUPPORTED_SUITE: { status: 400, message: 'The cryptographic suite is not supported.' },
  INVALID_SUBJECT: { status: 400, message: 'The subject is invalid.' },
  INVALID_SIGNATURE: { status: 403, message: 'The signature is invalid.' },
  INVALID_REVOCATION_SECRET: { status: 403, message: 'The revocation request is invalid.' },
  IDENTITY_NOT_FOUND: { status: 404, message: 'The identity was not found.' },
  IDENTITY_REVOKED: { status: 409, message: 'The identity is revoked.' },
  SEQUENCE_CONFLICT: { status: 409, message: 'The identity sequence has changed.' },
  SUBJECT_GENESIS_CONFLICT: {
    status: 409,
    message: 'The subject conflicts with existing genesis data.',
  },
  DEVICE_NOT_FOUND: { status: 404, message: 'The device was not found.' },
  DEVICE_REVOKED: { status: 409, message: 'The device is revoked.' },
  DEVICE_AUTHORIZATION_CONFLICT: {
    status: 409,
    message: 'The device authorization conflicts with existing state.',
  },
  RATE_LIMITED: { status: 429, message: 'Too many requests.' },
  TURNSTILE_REQUIRED: { status: 403, message: 'An anti-abuse check is required.' },
  TURNSTILE_INVALID: { status: 403, message: 'The anti-abuse check failed.' },
  BODY_TOO_LARGE: { status: 413, message: 'The request body is too large.' },
  METHOD_NOT_ALLOWED: { status: 405, message: 'The request method is not allowed.' },
  UNSUPPORTED_MEDIA_TYPE: { status: 415, message: 'The content type is not supported.' },
  ORIGIN_NOT_ALLOWED: { status: 403, message: 'The request origin is not allowed.' },
  HTTPS_REQUIRED: { status: 400, message: 'HTTPS is required.' },
  INTERNAL_ERROR: { status: 500, message: 'An internal error occurred.' },
  SERVICE_UNAVAILABLE: { status: 503, message: 'The service is temporarily unavailable.' },
};

export class NexusFault extends Error {
  public readonly code: NexusErrorCode;

  public constructor(code: NexusErrorCode, options?: { readonly cause?: unknown }) {
    super(ERROR_DEFINITIONS[code].message, options);
    this.name = 'NexusFault';
    this.code = code;
  }
}

export class NexusDeviceFault extends Error {
  public readonly code: NexusDeviceErrorCode;

  public constructor(code: NexusDeviceErrorCode, options?: { readonly cause?: unknown }) {
    super(ERROR_DEFINITIONS[code].message, options);
    this.name = 'NexusDeviceFault';
    this.code = code;
  }
}

export function isNexusErrorCode(value: unknown): value is NexusErrorCode {
  return typeof value === 'string' && (NEXUS_ERROR_CODES as readonly string[]).includes(value);
}

export function isNexusDeviceErrorCode(value: unknown): value is NexusDeviceErrorCode {
  return (
    typeof value === 'string' && (NEXUS_DEVICE_ERROR_CODES as readonly string[]).includes(value)
  );
}

export function nexusErrorStatus(code: NexusErrorCode): number {
  return ERROR_DEFINITIONS[code].status;
}

export function nexusDeviceErrorStatus(code: NexusDeviceErrorCode): number {
  return ERROR_DEFINITIONS[code].status;
}

export function nexusErrorMessage(code: NexusErrorCode): string {
  return ERROR_DEFINITIONS[code].message;
}

export function nexusDeviceErrorMessage(code: NexusDeviceErrorCode): string {
  return ERROR_DEFINITIONS[code].message;
}

export function faultCode(error: unknown): NexusErrorCode {
  if (error instanceof NexusFault) {
    return error.code;
  }
  return isNexusErrorCode(error) ? error : 'INTERNAL_ERROR';
}

export function deviceFaultCode(error: unknown): NexusDeviceErrorCode {
  if (error instanceof NexusDeviceFault || error instanceof NexusFault) {
    return error.code;
  }
  return isNexusDeviceErrorCode(error) ? error : 'INTERNAL_ERROR';
}

export function isNexusRequestId(value: unknown): value is string {
  return typeof value === 'string' && /^nxr_[A-Za-z0-9_-]{22}$/u.test(value);
}

export function createNexusErrorBody(code: NexusErrorCode, requestId?: string): NexusErrorBody {
  const error = !isNexusRequestId(requestId)
    ? { code, message: nexusErrorMessage(code) }
    : { code, message: nexusErrorMessage(code), requestId };

  return { error };
}

export function createNexusDeviceErrorBody(
  code: NexusDeviceErrorCode,
  requestId?: string,
): NexusDeviceErrorBody {
  const error = !isNexusRequestId(requestId)
    ? { code, message: nexusDeviceErrorMessage(code) }
    : { code, message: nexusDeviceErrorMessage(code), requestId };

  return { error };
}

export function toNexusErrorResponse(
  error: unknown,
  options: {
    readonly requestId?: string | undefined;
    readonly headers?: HeadersInit;
  } = {},
): Response {
  const code = faultCode(error);
  const headers = new Headers(options.headers);
  headers.set('Cache-Control', 'no-store');
  headers.set('Content-Type', 'application/nexus+json');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('X-Content-Type-Options', 'nosniff');

  return new Response(JSON.stringify(createNexusErrorBody(code, options.requestId)), {
    status: nexusErrorStatus(code),
    headers,
  });
}

export function toNexusDeviceErrorResponse(
  error: unknown,
  options: {
    readonly requestId?: string | undefined;
    readonly headers?: HeadersInit;
  } = {},
): Response {
  const code = deviceFaultCode(error);
  const headers = new Headers(options.headers);
  headers.set('Cache-Control', 'no-store');
  headers.set('Content-Type', 'application/nexus+json');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('X-Content-Type-Options', 'nosniff');

  return new Response(JSON.stringify(createNexusDeviceErrorBody(code, options.requestId)), {
    status: nexusDeviceErrorStatus(code),
    headers,
  });
}
