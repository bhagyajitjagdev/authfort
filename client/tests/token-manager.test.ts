import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { TokenManager } from '../src/token-manager';
import type { ServerAuthResponse, TokenStorage } from '../src/types';

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

function createMockStorage(): TokenStorage & {
  _value: () => string | null;
} {
  const store = { value: null as string | null };
  const s = {
    get: vi.fn(async () => store.value),
    set: vi.fn(async (token: string) => { store.value = token; }),
    clear: vi.fn(async () => { store.value = null; }),
    _value: () => store.value,
  };
  return s;
}

describe('TokenManager', () => {
  let onRefreshSuccess: ReturnType<typeof vi.fn>;
  let onRefreshFailure: ReturnType<typeof vi.fn>;
  let storage: ReturnType<typeof createMockStorage>;
  let manager: TokenManager;

  beforeEach(() => {
    vi.useFakeTimers();
    onRefreshSuccess = vi.fn();
    onRefreshFailure = vi.fn();
    storage = createMockStorage();
    manager = new TokenManager(
      BASE_URL,
      REFRESH_BUFFER,
      storage,
      onRefreshSuccess,
      onRefreshFailure,
    );
  });

  afterEach(async () => {
    await manager.dispose();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('stores and returns a valid token', async () => {
    await manager.setTokens('my-token', 'my-refresh', 900);
    expect(manager.getToken()).toBe('my-token');
  });

  it('returns null for expired token', async () => {
    await manager.setTokens('my-token', 'my-refresh', 60);
    vi.advanceTimersByTime(61_000);
    expect(manager.getToken()).toBeNull();
  });

  it('returns null when no token is set', () => {
    expect(manager.getToken()).toBeNull();
  });

  it('clears token and cancels timer', async () => {
    await manager.setTokens('my-token', 'my-refresh', 900);
    await manager.clear();
    expect(manager.getToken()).toBeNull();
  });

  it('refreshes via POST /refresh with refresh token in body', async () => {
    // Pre-populate storage with a refresh token
    await manager.setTokens('old-access', 'stored-refresh', 900);

    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockAuthResponse),
    });
    vi.stubGlobal('fetch', mockFetch);

    const result = await manager.refresh();

    expect(result).toEqual(mockAuthResponse);
    expect(mockFetch).toHaveBeenCalledWith(`${BASE_URL}/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: 'stored-refresh' }),
    });
    expect(manager.getToken()).toBe('new-access-token');
    expect(onRefreshSuccess).toHaveBeenCalledWith(mockAuthResponse);
  });

  it('deduplicates concurrent refresh calls', async () => {
    await manager.setTokens('old-access', 'stored-refresh', 900);

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
    await manager.setTokens('old-access', 'stored-refresh', 900);

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
    await manager.setTokens('old-access', 'stored-refresh', 900);

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
    await manager.setTokens('my-token', 'my-refresh', 60);

    expect(mockFetch).not.toHaveBeenCalled();

    // Advance to just before the refresh point
    await vi.advanceTimersByTimeAsync(29_000);
    expect(mockFetch).not.toHaveBeenCalled();

    // Advance past the refresh point (use async to flush the refresh promise)
    await vi.advanceTimersByTimeAsync(2_000);

    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  // ---------------------------------------------------------------------------
  // New: storage-specific tests
  // ---------------------------------------------------------------------------

  it('stores refresh token in tokenStorage', async () => {
    await manager.setTokens('my-token', 'my-refresh', 900);
    expect(storage.set).toHaveBeenCalledWith('my-refresh');
    expect(storage._value()).toBe('my-refresh');
  });

  it('clears refresh token from tokenStorage', async () => {
    await manager.setTokens('my-token', 'my-refresh', 900);
    await manager.clear();
    expect(storage.clear).toHaveBeenCalled();
    expect(storage._value()).toBeNull();
  });

  it('returns null when no refresh token in storage', async () => {
    // Storage is empty — no refresh token stored
    const result = await manager.refresh();
    expect(result).toBeNull();
    expect(onRefreshFailure).toHaveBeenCalled();
  });

  it('clearAccessToken preserves stored refresh token', async () => {
    await manager.setTokens('my-token', 'my-refresh', 900);
    manager.clearAccessToken();
    expect(manager.getToken()).toBeNull();
    expect(storage._value()).toBe('my-refresh');
  });

  it('getRefreshToken returns stored refresh token', async () => {
    await manager.setTokens('my-token', 'my-refresh', 900);
    const rt = await manager.getRefreshToken();
    expect(rt).toBe('my-refresh');
  });

  it('refresh stores new refresh token from response', async () => {
    await manager.setTokens('old-access', 'old-refresh', 900);

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockAuthResponse),
    }));

    await manager.refresh();

    // Should have stored the new refresh token from the response
    expect(storage._value()).toBe('new-refresh-token');
  });
});
