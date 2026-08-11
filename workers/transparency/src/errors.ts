export class TransparencyError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = 'TransparencyError';
  }
}

export function badRequest(message: string): TransparencyError {
  return new TransparencyError('BAD_REQUEST', message, 400);
}

export function notFound(message: string): TransparencyError {
  return new TransparencyError('TRANSPARENCY_EVENT_NOT_FOUND', message, 404);
}
