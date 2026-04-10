/**
 * AuthFort Client — TypeScript SDK for AuthFort authentication.
 *
 * Handles token lifecycle, proactive refresh, and authenticated requests.
 */

export { createAuthClient } from './client.js';
export { AuthClientError } from './errors.js';
export type { AuthClientConfig, AuthClient, AuthState, AuthUser, OAuthProvider, OAuthSignInOptions, TokenStorage, SignInResult } from './types.js';
