/**
 * AuthFort client — main implementation.
 */

import { AuthClientError, parseErrorResponse } from './errors.js';
import { TokenManager } from './token-manager.js';
import type {
  AuthClient,
  AuthClientConfig,
  AuthState,
  AuthUser,
  OAuthProvider,
  OAuthSignInOptions,
  ServerAuthResponse,
  ServerUserResponse,
} from './types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mapUser(server: ServerUserResponse): AuthUser {
  return {
    id: server.id,
    email: server.email,
    name: server.name ?? undefined,
    phone: server.phone ?? undefined,
    roles: server.roles,
    emailVerified: server.email_verified,
    avatarUrl: server.avatar_url ?? undefined,
    createdAt: server.created_at,
  };
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

class AuthClientImpl implements AuthClient {
  private _state: AuthState = 'unauthenticated';
  private _user: AuthUser | null = null;
  private _listeners = new Set<
    (state: AuthState, user: AuthUser | null) => void
  >();
  private _tokenManager: TokenManager | null = null;
  private _initPromise: Promise<void> | null = null;
  private _cookieRefreshPromise: Promise<boolean> | null = null;

  private readonly _baseUrl: string;
  private readonly _tokenMode: 'cookie' | 'bearer';

  constructor(config: AuthClientConfig) {
    this._baseUrl = config.baseUrl.replace(/\/+$/, '');
    this._tokenMode = config.tokenMode ?? 'cookie';

    if (this._tokenMode === 'bearer') {
      if (!config.tokenStorage) {
        throw new AuthClientError(
          'tokenStorage is required when tokenMode is "bearer". Provide a { get, set, clear } adapter.',
          'missing_token_storage',
          0,
        );
      }
      this._tokenManager = new TokenManager(
        this._baseUrl,
        config.refreshBuffer ?? 30,
        config.tokenStorage,
        (response) => this._setAuthenticated(mapUser(response.user)),
        () => this._setState('unauthenticated', null),
      );
    }
  }

  initialize(): Promise<void> {
    if (this._initPromise) return this._initPromise;
    this._initPromise = this._doInitialize();
    return this._initPromise;
  }

  private async _doInitialize(): Promise<void> {
    this._setState('loading', null);

    try {
      if (this._tokenMode === 'bearer') {
        const result = await this._tokenManager!.refresh();
        if (!result) {
          this._setState('unauthenticated', null);
        }
        // onRefreshSuccess already called _setAuthenticated
      } else {
        // Cookie mode: try /me, then /refresh on 401
        const meResponse = await fetch(`${this._baseUrl}/me`, {
          credentials: 'include',
        });

        if (meResponse.ok) {
          const serverUser: ServerUserResponse = await meResponse.json();
          this._setAuthenticated(mapUser(serverUser));
        } else if (meResponse.status === 401) {
          // Access cookie expired — try refreshing
          const refreshResponse = await fetch(`${this._baseUrl}/refresh`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
          });

          if (refreshResponse.ok) {
            const data: ServerAuthResponse = await refreshResponse.json();
            this._setAuthenticated(mapUser(data.user));
          } else {
            this._setState('unauthenticated', null);
          }
        } else {
          this._setState('unauthenticated', null);
        }
      }
    } catch {
      this._setState('unauthenticated', null);
    }
  }

  async getToken(): Promise<string | null> {
    if (this._tokenMode === 'cookie') {
      return null;
    }

    const token = this._tokenManager!.getToken();
    if (token) return token;

    // Token expired or absent — try refresh
    const result = await this._tokenManager!.refresh();
    return result ? result.tokens.access_token : null;
  }

  async fetch(url: string, options: RequestInit = {}): Promise<Response> {
    const doFetch = async (): Promise<Response> => {
      const fetchOptions: RequestInit = { ...options };

      if (this._tokenMode === 'cookie') {
        fetchOptions.credentials = 'include';
      } else {
        const token = await this.getToken();
        if (token) {
          fetchOptions.headers = {
            ...fetchOptions.headers,
            Authorization: `Bearer ${token}`,
          };
        }
      }

      return globalThis.fetch(url, fetchOptions);
    };

    let response = await doFetch();

    // 401 retry: refresh then retry once
    if (response.status === 401) {
      let refreshed = false;

      if (this._tokenMode === 'bearer') {
        this._tokenManager!.clearAccessToken();
        const result = await this._tokenManager!.refresh();
        refreshed = result !== null;
      } else {
        refreshed = await this._doCookieRefresh();
      }

      if (refreshed) {
        response = await doFetch();
      }

      // Still 401 after retry — session is dead
      if (response.status === 401) {
        if (this._tokenManager) await this._tokenManager.clear();
        this._setState('unauthenticated', null);
      }
    }

    return response;
  }

  async signUp(data: {
    email: string;
    password: string;
    name?: string;
    avatarUrl?: string;
    phone?: string;
  }): Promise<AuthUser> {
    const body: Record<string, string> = { email: data.email, password: data.password };
    if (data.name !== undefined) body.name = data.name;
    if (data.avatarUrl !== undefined) body.avatar_url = data.avatarUrl;
    if (data.phone !== undefined) body.phone = data.phone;

    const response = await globalThis.fetch(`${this._baseUrl}/signup`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw await parseErrorResponse(response);
    }

    const result: ServerAuthResponse = await response.json();
    const user = mapUser(result.user);

    if (this._tokenManager) {
      await this._tokenManager.setTokens(
        result.tokens.access_token,
        result.tokens.refresh_token,
        result.tokens.expires_in,
      );
    }
    this._setAuthenticated(user);
    return user;
  }

  async signIn(data: { email: string; password: string }): Promise<AuthUser> {
    const response = await globalThis.fetch(`${this._baseUrl}/login`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      throw await parseErrorResponse(response);
    }

    const result: ServerAuthResponse = await response.json();
    const user = mapUser(result.user);

    if (this._tokenManager) {
      await this._tokenManager.setTokens(
        result.tokens.access_token,
        result.tokens.refresh_token,
        result.tokens.expires_in,
      );
    }
    this._setAuthenticated(user);
    return user;
  }

  signInWithProvider(provider: OAuthProvider, options?: OAuthSignInOptions): void | Promise<AuthUser> {
    const mode = options?.mode ?? 'redirect';
    const params = new URLSearchParams();
    if (options?.redirectTo) params.set('redirect_to', options.redirectTo);
    if (mode === 'popup') params.set('mode', 'popup');
    const qs = params.toString();
    const authorizeUrl = `${this._baseUrl}/oauth/${provider}/authorize${qs ? `?${qs}` : ''}`;

    if (mode === 'popup') {
      return this._oauthPopup(authorizeUrl);
    }

    window.location.href = authorizeUrl;
  }

  private _oauthPopup(url: string): Promise<AuthUser> {
    return new Promise<AuthUser>((resolve, reject) => {
      const width = 500;
      const height = 600;
      const left = window.screenX + (window.outerWidth - width) / 2;
      const top = window.screenY + (window.outerHeight - height) / 2;
      const popup = window.open(
        url,
        'authfort-oauth',
        `width=${width},height=${height},left=${left},top=${top},popup=yes`,
      );

      if (!popup) {
        reject(new AuthClientError('Popup blocked by browser', 'popup_blocked', 0));
        return;
      }

      const cleanup = () => {
        window.removeEventListener('message', onMessage);
        clearInterval(pollTimer);
      };

      const onMessage = (event: MessageEvent) => {
        // Accept messages from our own origin or the auth server origin
        const data = event.data;
        if (!data || typeof data !== 'object' || !data.user) return;

        cleanup();
        try { popup.close(); } catch { /* ignore */ }

        const user = mapUser(data.user);

        if (this._tokenManager && data.tokens) {
          this._tokenManager
            .setTokens(data.tokens.access_token, data.tokens.refresh_token, data.tokens.expires_in)
            .then(() => {
              this._setAuthenticated(user);
              resolve(user);
            })
            .catch(reject);
        } else {
          this._setAuthenticated(user);
          resolve(user);
        }
      };

      // Poll for popup closure (user closed manually)
      const pollTimer = setInterval(() => {
        if (popup.closed) {
          cleanup();
          reject(new AuthClientError('OAuth popup was closed', 'popup_closed', 0));
        }
      }, 500);

      window.addEventListener('message', onMessage);
    });
  }

  async requestMagicLink(email: string): Promise<void> {
    const response = await globalThis.fetch(`${this._baseUrl}/magic-link`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });

    if (!response.ok) {
      throw await parseErrorResponse(response);
    }
  }

  async verifyMagicLink(token: string): Promise<AuthUser> {
    const response = await globalThis.fetch(`${this._baseUrl}/magic-link/verify`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });

    if (!response.ok) {
      throw await parseErrorResponse(response);
    }

    const result: ServerAuthResponse = await response.json();
    const user = mapUser(result.user);

    if (this._tokenManager) {
      await this._tokenManager.setTokens(
        result.tokens.access_token,
        result.tokens.refresh_token,
        result.tokens.expires_in,
      );
    }
    this._setAuthenticated(user);
    return user;
  }

  async requestOTP(email: string): Promise<void> {
    const response = await globalThis.fetch(`${this._baseUrl}/otp`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });

    if (!response.ok) {
      throw await parseErrorResponse(response);
    }
  }

  async verifyOTP(email: string, code: string): Promise<AuthUser> {
    const response = await globalThis.fetch(`${this._baseUrl}/otp/verify`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, code }),
    });

    if (!response.ok) {
      throw await parseErrorResponse(response);
    }

    const result: ServerAuthResponse = await response.json();
    const user = mapUser(result.user);

    if (this._tokenManager) {
      await this._tokenManager.setTokens(
        result.tokens.access_token,
        result.tokens.refresh_token,
        result.tokens.expires_in,
      );
    }
    this._setAuthenticated(user);
    return user;
  }

  async verifyEmail(token: string): Promise<void> {
    const response = await globalThis.fetch(`${this._baseUrl}/verify-email`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });

    if (!response.ok) {
      throw await parseErrorResponse(response);
    }

    // Update local user state if authenticated
    if (this._user) {
      this._setAuthenticated({ ...this._user, emailVerified: true });
    }
  }

  async signOut(): Promise<void> {
    try {
      let body: string;
      if (this._tokenManager) {
        const refreshToken = await this._tokenManager.getRefreshToken();
        body = refreshToken
          ? JSON.stringify({ refresh_token: refreshToken })
          : JSON.stringify({});
      } else {
        body = JSON.stringify({});
      }

      await globalThis.fetch(`${this._baseUrl}/logout`, {
        method: 'POST',
        credentials: this._tokenMode === 'cookie' ? 'include' : undefined,
        headers: { 'Content-Type': 'application/json' },
        body,
      });
    } finally {
      if (this._tokenManager) await this._tokenManager.clear();
      this._setState('unauthenticated', null);
    }
  }

  async getUser(): Promise<AuthUser> {
    const response = await this.fetch(`${this._baseUrl}/me`);

    if (!response.ok) {
      throw await parseErrorResponse(response);
    }

    const serverUser: ServerUserResponse = await response.json();
    const user = mapUser(serverUser);
    this._user = user;
    return user;
  }

  onAuthStateChange(
    callback: (state: AuthState, user: AuthUser | null) => void,
  ): () => void {
    this._listeners.add(callback);
    // Fire immediately with current state
    callback(this._state, this._user);
    return () => {
      this._listeners.delete(callback);
    };
  }

  // ---------------------------------------------------------------------------
  // Private
  // ---------------------------------------------------------------------------

  /**
   * Deduplicated cookie-mode refresh. Multiple concurrent 401 handlers
   * share a single /refresh request instead of each firing their own.
   */
  private _doCookieRefresh(): Promise<boolean> {
    if (this._cookieRefreshPromise) {
      return this._cookieRefreshPromise;
    }

    this._cookieRefreshPromise = globalThis
      .fetch(`${this._baseUrl}/refresh`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      .then((r) => r.ok)
      .catch(() => false)
      .finally(() => {
        this._cookieRefreshPromise = null;
      });

    return this._cookieRefreshPromise;
  }

  private _setAuthenticated(user: AuthUser): void {
    this._setState('authenticated', user);
  }

  private _setState(state: AuthState, user: AuthUser | null): void {
    const changed = this._state !== state || this._user !== user;
    this._state = state;
    this._user = user;
    if (changed) {
      for (const listener of this._listeners) {
        try {
          listener(state, user);
        } catch {
          // Don't break on listener errors
        }
      }
    }
  }
}

/** Create an AuthFort client instance. */
export function createAuthClient(config: AuthClientConfig): AuthClient {
  return new AuthClientImpl(config);
}
