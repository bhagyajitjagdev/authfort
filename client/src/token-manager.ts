/**
 * Token lifecycle manager (bearer mode only).
 *
 * Handles:
 * - In-memory access token storage
 * - Proactive refresh (before expiry)
 * - Single refresh promise deduplication
 */

import type { ServerAuthResponse } from './types';

export class TokenManager {
  private _accessToken: string | null = null;
  private _expiresAt = 0;
  private _refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private _refreshPromise: Promise<ServerAuthResponse | null> | null = null;

  constructor(
    private readonly _baseUrl: string,
    private readonly _refreshBuffer: number,
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

  /** Store a new access token and schedule proactive refresh. */
  setTokens(accessToken: string, expiresIn: number): void {
    this._accessToken = accessToken;
    this._expiresAt = Date.now() + expiresIn * 1000;
    this._scheduleRefresh(expiresIn);
  }

  /** Clear stored token and cancel any scheduled refresh. */
  clear(): void {
    this._accessToken = null;
    this._expiresAt = 0;
    this._cancelRefresh();
  }

  /**
   * Refresh the access token via POST /refresh (using refresh cookie).
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

  /** Cleanup timers. */
  dispose(): void {
    this.clear();
  }

  // ---------------------------------------------------------------------------
  // Private
  // ---------------------------------------------------------------------------

  private async _doRefresh(): Promise<ServerAuthResponse | null> {
    try {
      const response = await fetch(`${this._baseUrl}/refresh`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });

      if (!response.ok) {
        this.clear();
        this._onRefreshFailure();
        return null;
      }

      const data: ServerAuthResponse = await response.json();
      this.setTokens(data.tokens.access_token, data.tokens.expires_in);
      this._onRefreshSuccess(data);
      return data;
    } catch {
      this.clear();
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
