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

/** Authentication state */
export type AuthState = 'authenticated' | 'unauthenticated' | 'loading';

/** Authenticated user data (camelCase) */
export interface AuthUser {
  id: string;
  email: string;
  name?: string;
  roles: string[];
  emailVerified: boolean;
  avatarUrl?: string;
  createdAt: string;
}

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
  signUp(data: { email: string; password: string; name?: string }): Promise<AuthUser>;

  /** Sign in with email and password */
  signIn(data: { email: string; password: string }): Promise<AuthUser>;

  /** Sign in with OAuth provider (redirects the browser) */
  signInWithProvider(provider: string): void;

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
  email_verified: boolean;
  avatar_url: string | null;
  roles: string[];
  created_at: string;
}

/** Full auth response from server (signup/login/refresh) */
export interface ServerAuthResponse {
  user: ServerUserResponse;
  tokens: AuthTokens;
}
