/**
 * Storage adapter for refresh tokens in bearer mode.
 *
 * Implement this interface to persist the refresh token across app restarts.
 * Examples: `localStorage`, `expo-secure-store`, `react-native-keychain`, etc.
 */
export interface TokenStorage {
  /** Retrieve the stored refresh token, or null if none exists. */
  get(): Promise<string | null>;
  /** Persist a refresh token. */
  set(token: string): Promise<void>;
  /** Remove the stored refresh token. */
  clear(): Promise<void>;
}

/** Configuration for creating an AuthFort client. */
export interface AuthClientConfig {
  /** Base URL of the auth server (e.g., "https://myapp.com/auth") */
  baseUrl: string;

  /**
   * Token delivery mode.
   * - `'cookie'` — server sets httponly cookies, JS never touches tokens (default)
   * - `'bearer'` — access token stored in memory, sent via Authorization header
   */
  tokenMode?: 'cookie' | 'bearer';

  /** Seconds before expiry to trigger proactive refresh (default: 30) */
  refreshBuffer?: number;

  /**
   * Storage adapter for refresh tokens. Required when `tokenMode` is `'bearer'`.
   *
   * The client calls `get()`, `set()`, and `clear()` to manage the refresh token.
   * You control what storage backend is used (localStorage, SecureStore, etc.).
   */
  tokenStorage?: TokenStorage;
}

/**
 * Authentication state.
 * - `'authenticated'` — user is signed in with full tokens
 * - `'unauthenticated'` — no active session
 * - `'loading'` — checking for existing session
 * - `'mfa_pending'` — password verified, waiting for TOTP code (call `verifyMFA()`)
 */
export type AuthState = 'authenticated' | 'unauthenticated' | 'loading' | 'mfa_pending';

/** Known OAuth provider names (accepts any string for generic providers) */
export type OAuthProvider = 'google' | 'github' | (string & {});

/** Options for OAuth sign-in */
export interface OAuthSignInOptions {
  /**
   * OAuth flow mode.
   * - `'redirect'` — full-page redirect (default)
   * - `'popup'` — opens a popup window, resolves when auth completes
   */
  mode?: 'redirect' | 'popup';

  /** URL path to redirect to after auth (must be a relative path starting with "/"). Only used in redirect mode. */
  redirectTo?: string;
}

/** Authenticated user data (camelCase) */
export interface AuthUser {
  id: string;
  email: string;
  name?: string;
  phone?: string;
  roles: string[];
  emailVerified: boolean;
  avatarUrl?: string;
  createdAt: string;
  /** Whether the user has TOTP MFA enabled on their account. */
  mfaEnabled: boolean;
}

/**
 * Result of `signIn()`.
 *
 * - `status: 'authenticated'` — tokens issued, `user` is populated.
 * - `status: 'mfa_required'` — password verified but MFA is enabled.
 *   Call `verifyMFA(code)` to complete the login.
 */
export type SignInResult =
  | { status: 'authenticated'; user: AuthUser }
  | { status: 'mfa_required' };

/** Auth client interface */
export interface AuthClient {
  /** Check for an existing session on app startup or after OAuth redirect. */
  initialize(): Promise<void>;

  /** Get a valid access token. Returns null in cookie mode. */
  getToken(): Promise<string | null>;

  /** Make an authenticated fetch request (auto-attaches token, handles 401 retry) */
  fetch(url: string, options?: RequestInit): Promise<Response>;

  /** Get current user data */
  getUser(): Promise<AuthUser>;

  /** Sign up with email and password */
  signUp(data: { email: string; password: string; name?: string; avatarUrl?: string; phone?: string }): Promise<AuthUser>;

  /**
   * Sign in with email and password.
   *
   * Returns `{ status: 'authenticated', user }` on success, or
   * `{ status: 'mfa_required' }` if the user has TOTP MFA enabled.
   * In the MFA case, call `verifyMFA(code)` to complete the login.
   */
  signIn(data: { email: string; password: string }): Promise<SignInResult>;

  /**
   * Complete a login that requires MFA.
   *
   * Submit the 6-digit TOTP code from the user's authenticator app (or a
   * backup code). Only valid after `signIn()` returns `{ status: 'mfa_required' }`.
   *
   * @throws {AuthClientError} If the code is wrong or the session has expired.
   */
  verifyMFA(code: string): Promise<AuthUser>;

  /** Sign in with OAuth provider. Redirect mode (default) navigates the browser. Popup mode opens a window and returns a promise. */
  signInWithProvider(provider: OAuthProvider, options?: OAuthSignInOptions): void | Promise<AuthUser>;

  /** Request a magic link for passwordless login */
  requestMagicLink(email: string): Promise<void>;

  /** Verify a magic link token and log in */
  verifyMagicLink(token: string): Promise<AuthUser>;

  /** Request an email OTP code for passwordless login */
  requestOTP(email: string): Promise<void>;

  /** Verify an email OTP code and log in */
  verifyOTP(email: string, code: string): Promise<AuthUser>;

  /** Verify email address with a verification token */
  verifyEmail(token: string): Promise<void>;

  /** Sign out */
  signOut(): Promise<void>;

  /** Subscribe to auth state changes. Returns unsubscribe function. */
  onAuthStateChange(
    callback: (state: AuthState, user: AuthUser | null) => void,
  ): () => void;
}

// ---------------------------------------------------------------------------
// Internal types — server response shapes (snake_case)
// ---------------------------------------------------------------------------

/** Token response from server */
export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

/** User response from server (snake_case) */
export interface ServerUserResponse {
  id: string;
  email: string;
  name: string | null;
  phone: string | null;
  email_verified: boolean;
  avatar_url: string | null;
  roles: string[];
  created_at: string;
  mfa_enabled: boolean;
}

/** Full auth response from server (signup/login/refresh) */
export interface ServerAuthResponse {
  user: ServerUserResponse;
  tokens: AuthTokens;
}

/** MFA challenge response — returned by /login when user has MFA enabled */
export interface ServerMFAChallengeResponse {
  mfa_required: true;
  mfa_token: string;
  expires_in: number;
}
