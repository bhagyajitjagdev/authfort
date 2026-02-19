/**
 * Token lifecycle manager (bearer mode only).
 *
 * Handles:
 * - In-memory access token storage
 * - Refresh token persistence via TokenStorage adapter
 * - Proactive refresh (before expiry)
 * - Single refresh promise deduplication
 */

import type { ServerAuthResponse, TokenStorage } from './types.js';

export class TokenManager {
  private _accessToken: string | null = null;
  private _expiresAt = 0;
  private _refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private _refreshPromise: Promise<ServerAuthResponse | null> | null = null;

  constructor(
    private readonly _baseUrl: string,
    private readonly _refreshBuffer: number,
    private readonly _tokenStorage: TokenStorage,
    private readonly _onRefreshSuccess: (response: ServerAuthResponse) => void,
    private readonly _onRefreshFailure: () => void,
  ) {}

  /** Returns the current access token, or null if expired/absent. */
  getToken(): string | null {
    if (this._accessToken && Date.now() < this._expiresAt) {
      return this._accessToken;
    }
    return null;
  }

  /** Retrieve the stored refresh token from storage. */
  async getRefreshToken(): Promise<string | null> {
    return this._tokenStorage.get();
  }

  /** Store a new access + refresh token pair and schedule proactive refresh. */
  async setTokens(accessToken: string, refreshToken: string, expiresIn: number): Promise<void> {
    this._accessToken = accessToken;
    this._expiresAt = Date.now() + expiresIn * 1000;
    await this._tokenStorage.set(refreshToken);
    this._scheduleRefresh(expiresIn);
  }

  /** Clear all tokens (in-memory + storage) and cancel any scheduled refresh. */
  async clear(): Promise<void> {
    this._accessToken = null;
    this._expiresAt = 0;
    await this._tokenStorage.clear();
    this._cancelRefresh();
  }

  /** Clear only the in-memory access token. Preserves stored refresh token. */
  clearAccessToken(): void {
    this._accessToken = null;
    this._expiresAt = 0;
    this._cancelRefresh();
  }

  /**
   * Refresh the access token via POST /refresh.
   * Sends the stored refresh token in the request body.
   * Deduplicates concurrent calls — only one fetch in flight at a time.
   */
  async refresh(): Promise<ServerAuthResponse | null> {
    if (this._refreshPromise) {
      return this._refreshPromise;
    }

    this._refreshPromise = this._doRefresh();
    try {
      return await this._refreshPromise;
    } finally {
      this._refreshPromise = null;
    }
  }

  /** Cleanup timers and storage. */
  async dispose(): Promise<void> {
    await this.clear();
  }

  // ---------------------------------------------------------------------------
  // Private
  // ---------------------------------------------------------------------------

  private async _doRefresh(): Promise<ServerAuthResponse | null> {
    try {
      const refreshToken = await this._tokenStorage.get();
      if (!refreshToken) {
        this._onRefreshFailure();
        return null;
      }

      const response = await fetch(`${this._baseUrl}/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });

      if (!response.ok) {
        await this.clear();
        this._onRefreshFailure();
        return null;
      }

      const data: ServerAuthResponse = await response.json();
      await this.setTokens(data.tokens.access_token, data.tokens.refresh_token, data.tokens.expires_in);
      this._onRefreshSuccess(data);
      return data;
    } catch {
      await this.clear();
      this._onRefreshFailure();
      return null;
    }
  }

  private _scheduleRefresh(expiresIn: number): void {
    this._cancelRefresh();
    const refreshMs = (expiresIn - this._refreshBuffer) * 1000;
    if (refreshMs > 0) {
      this._refreshTimer = setTimeout(() => {
        this.refresh();
      }, refreshMs);
    }
  }

  private _cancelRefresh(): void {
    if (this._refreshTimer !== null) {
      clearTimeout(this._refreshTimer);
      this._refreshTimer = null;
    }
  }
}
