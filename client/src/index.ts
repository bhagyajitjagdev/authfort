/**
 * AuthFort Client — TypeScript SDK for AuthFort authentication.
 *
 * Handles token lifecycle, proactive refresh, and authenticated requests.
 */

export { createAuthClient } from './client';
export { AuthClientError } from './errors';
export type { AuthClientConfig, AuthClient, AuthState, AuthUser } from './types';
