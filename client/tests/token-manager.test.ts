import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { TokenManager } from '../src/token-manager';
import type { ServerAuthResponse } from '../src/types';

const BASE_URL = 'http://localhost:8000/auth';
const REFRESH_BUFFER = 30;

const mockAuthResponse: ServerAuthResponse = {
  user: {
    id: '123',
    email: 'test@example.com',
    name: 'Test User',
    email_verified: false,
    avatar_url: null,
    roles: ['user'],
    created_at: '2026-01-01T00:00:00Z',
  },
  tokens: {
    access_token: 'new-access-token',
    refresh_token: 'new-refresh-token',
    expires_in: 900,
  },
};

describe('TokenManager', () => {
  let onRefreshSuccess: ReturnType<typeof vi.fn>;
  let onRefreshFailure: ReturnType<typeof vi.fn>;
  let manager: TokenManager;

  beforeEach(() => {
    vi.useFakeTimers();
    onRefreshSuccess = vi.fn();
    onRefreshFailure = vi.fn();
    manager = new TokenManager(
      BASE_URL,
      REFRESH_BUFFER,
      onRefreshSuccess,
      onRefreshFailure,
    );
  });

  afterEach(() => {
    manager.dispose();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('stores and returns a valid token', () => {
    manager.setTokens('my-token', 900);
    expect(manager.getToken()).toBe('my-token');
  });

  it('returns null for expired token', () => {
    manager.setTokens('my-token', 60);
    vi.advanceTimersByTime(61_000);
    expect(manager.getToken()).toBeNull();
  });

  it('returns null when no token is set', () => {
    expect(manager.getToken()).toBeNull();
  });

  it('clears token and cancels timer', () => {
    manager.setTokens('my-token', 900);
    manager.clear();
    expect(manager.getToken()).toBeNull();
  });

  it('refreshes via POST /refresh with credentials', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockAuthResponse),
    });
    vi.stubGlobal('fetch', mockFetch);

    const result = await manager.refresh();

    expect(result).toEqual(mockAuthResponse);
    expect(mockFetch).toHaveBeenCalledWith(`${BASE_URL}/refresh`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    expect(manager.getToken()).toBe('new-access-token');
    expect(onRefreshSuccess).toHaveBeenCalledWith(mockAuthResponse);
  });

  it('deduplicates concurrent refresh calls', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockAuthResponse),
    });
    vi.stubGlobal('fetch', mockFetch);

    // Fire three concurrent refreshes
    const [r1, r2, r3] = await Promise.all([
      manager.refresh(),
      manager.refresh(),
      manager.refresh(),
    ]);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(r1).toEqual(mockAuthResponse);
    expect(r2).toEqual(mockAuthResponse);
    expect(r3).toEqual(mockAuthResponse);
  });

  it('calls onRefreshFailure on failed refresh', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: false, status: 401 }),
    );

    const result = await manager.refresh();

    expect(result).toBeNull();
    expect(onRefreshFailure).toHaveBeenCalled();
    expect(manager.getToken()).toBeNull();
  });

  it('calls onRefreshFailure on network error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new Error('Network error')),
    );

    const result = await manager.refresh();

    expect(result).toBeNull();
    expect(onRefreshFailure).toHaveBeenCalled();
  });

  it('schedules proactive refresh before expiry', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockAuthResponse),
    });
    vi.stubGlobal('fetch', mockFetch);

    // Set token with 60s expiry, 30s buffer → refresh fires at 30s
    manager.setTokens('my-token', 60);

    expect(mockFetch).not.toHaveBeenCalled();

    // Advance to just before the refresh point
    await vi.advanceTimersByTimeAsync(29_000);
    expect(mockFetch).not.toHaveBeenCalled();

    // Advance past the refresh point (use async to flush the refresh promise)
    await vi.advanceTimersByTimeAsync(2_000);

    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});
