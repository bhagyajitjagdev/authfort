/** Error thrown by AuthFort client operations. */
export class AuthClientError extends Error {
  /** Server error code (e.g., "invalid_credentials", "user_exists") */
  readonly code: string;
  /** HTTP status code from the server response */
  readonly statusCode: number;

  constructor(message: string, code: string, statusCode: number) {
    super(message);
    this.name = 'AuthClientError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

/**
 * Parse an error response from the AuthFort server.
 * FastAPI wraps errors as { detail: { error, message } }.
 */
export async function parseErrorResponse(
  response: Response,
): Promise<AuthClientError> {
  try {
    const body = await response.json();
    const detail = body.detail ?? body;
    return new AuthClientError(
      detail.message ?? response.statusText,
      detail.error ?? 'unknown_error',
      response.status,
    );
  } catch {
    return new AuthClientError(
      response.statusText,
      'unknown_error',
      response.status,
    );
  }
}
