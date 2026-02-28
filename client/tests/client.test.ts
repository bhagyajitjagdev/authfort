import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createAuthClient } from '../src/client';
import { AuthClientError } from '../src/errors';
import type { AuthClient, AuthState, AuthUser, TokenStorage } from '../src/types';

const BASE_URL = 'http://localhost:8000/auth';

const serverUser = {
  id: '123',
  email: 'test@example.com',
  name: 'Test User',
  email_verified: true,
  avatar_url: null,
  roles: ['user'],
  created_at: '2026-01-01T00:00:00Z',
};

const serverAuthResponse = {
  user: serverUser,
  tokens: {
    access_token: 'access-123',
    refresh_token: 'refresh-123',
    expires_in: 900,
  },
};

const expectedUser: AuthUser = {
  id: '123',
  email: 'test@example.com',
  name: 'Test User',
  roles: ['user'],
  emailVerified: true,
  avatarUrl: undefined,
  createdAt: '2026-01-01T00:00:00Z',
};

function jsonResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: () => Promise.resolve(data),
    headers: new Headers(),
  } as Response;
}

function createMockStorage(): TokenStorage & {
  _value: () => string | null;
} {
  const store = { value: null as string | null };
  return {
    get: vi.fn(async () => store.value),
    set: vi.fn(async (token: string) => { store.value = token; }),
    clear: vi.fn(async () => { store.value = null; }),
    _value: () => store.value,
  };
}

describe('AuthClient — cookie mode', () => {
  let client: AuthClient;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
    client = createAuthClient({ baseUrl: BASE_URL, tokenMode: 'cookie' });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('signUp calls POST /signup and returns user', async () => {
    mockFetch.mockResolvedValue(jsonResponse(serverAuthResponse, 201));

    const user = await client.signUp({
      email: 'test@example.com',
      password: 'password123',
    });

    expect(user).toEqual(expectedUser);
    expect(mockFetch).toHaveBeenCalledWith(
      `${BASE_URL}/signup`,
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
      }),
    );
  });

  it('signIn calls POST /login and sets state to authenticated', async () => {
    mockFetch.mockResolvedValue(jsonResponse(serverAuthResponse));

    const stateChanges: AuthState[] = [];
    client.onAuthStateChange((state) => stateChanges.push(state));

    const user = await client.signIn({
      email: 'test@example.com',
      password: 'password123',
    });

    expect(user).toEqual(expectedUser);
    // Initial fire (unauthenticated) + after signIn (authenticated)
    expect(stateChanges).toEqual(['unauthenticated', 'authenticated']);
  });

  it('signUp throws AuthClientError on 409', async () => {
    mockFetch.mockResolvedValue(
      jsonResponse(
        { detail: { error: 'user_exists', message: 'Email already registered' } },
        409,
      ),
    );

    await expect(
      client.signUp({ email: 'test@example.com', password: 'password123' }),
    ).rejects.toThrow(AuthClientError);

    try {
      await client.signUp({ email: 'test@example.com', password: 'password123' });
    } catch (e) {
      expect(e).toBeInstanceOf(AuthClientError);
      expect((e as AuthClientError).code).toBe('user_exists');
      expect((e as AuthClientError).statusCode).toBe(409);
    }
  });

  it('signOut calls POST /logout and sets state to unauthenticated', async () => {
    // First sign in
    mockFetch.mockResolvedValueOnce(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    // Then sign out
    mockFetch.mockResolvedValueOnce(jsonResponse(null, 204));
    await client.signOut();

    const stateChanges: AuthState[] = [];
    client.onAuthStateChange((state) => stateChanges.push(state));
    expect(stateChanges).toEqual(['unauthenticated']);
  });

  it('getUser calls GET /me via fetch wrapper', async () => {
    // signIn first to be authenticated
    mockFetch.mockResolvedValueOnce(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    // getUser calls this.fetch() which adds credentials
    mockFetch.mockResolvedValueOnce(jsonResponse(serverUser));
    const user = await client.getUser();

    expect(user).toEqual(expectedUser);
  });

  it('getToken returns null in cookie mode', async () => {
    const token = await client.getToken();
    expect(token).toBeNull();
  });

  it('initialize calls /me and sets state to authenticated', async () => {
    mockFetch.mockResolvedValue(jsonResponse(serverUser));

    await client.initialize();

    const stateChanges: AuthState[] = [];
    client.onAuthStateChange((state) => stateChanges.push(state));
    expect(stateChanges).toEqual(['authenticated']);
  });

  it('initialize refreshes on 401 from /me', async () => {
    // /me returns 401
    mockFetch.mockResolvedValueOnce(jsonResponse(null, 401));
    // /refresh succeeds
    mockFetch.mockResolvedValueOnce(jsonResponse(serverAuthResponse));

    await client.initialize();

    const stateChanges: AuthState[] = [];
    client.onAuthStateChange((state) => stateChanges.push(state));
    expect(stateChanges).toEqual(['authenticated']);
  });

  it('initialize sets unauthenticated when both /me and /refresh fail', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse(null, 401));
    mockFetch.mockResolvedValueOnce(jsonResponse(null, 401));

    await client.initialize();

    const stateChanges: AuthState[] = [];
    client.onAuthStateChange((state) => stateChanges.push(state));
    expect(stateChanges).toEqual(['unauthenticated']);
  });

  it('fetch uses credentials:include in cookie mode', async () => {
    mockFetch.mockResolvedValue(jsonResponse({ data: 'ok' }));

    await client.fetch('http://api.example.com/data');

    expect(mockFetch).toHaveBeenCalledWith(
      'http://api.example.com/data',
      expect.objectContaining({ credentials: 'include' }),
    );
  });

  it('fetch retries once on 401 (cookie mode)', async () => {
    // First request returns 401
    mockFetch.mockResolvedValueOnce(jsonResponse(null, 401));
    // Refresh succeeds
    mockFetch.mockResolvedValueOnce(jsonResponse(serverAuthResponse));
    // Retry succeeds
    mockFetch.mockResolvedValueOnce(jsonResponse({ data: 'ok' }));

    const response = await client.fetch('http://api.example.com/data');
    expect(response.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it('deduplicates concurrent 401 refresh calls (cookie mode)', async () => {
    // All 3 initial requests return 401
    mockFetch.mockResolvedValueOnce(jsonResponse(null, 401)); // req A
    mockFetch.mockResolvedValueOnce(jsonResponse(null, 401)); // req B
    mockFetch.mockResolvedValueOnce(jsonResponse(null, 401)); // req C
    // Single shared refresh → succeeds
    mockFetch.mockResolvedValueOnce(jsonResponse(serverAuthResponse));
    // All 3 retries succeed
    mockFetch.mockResolvedValueOnce(jsonResponse({ a: 1 }));
    mockFetch.mockResolvedValueOnce(jsonResponse({ b: 2 }));
    mockFetch.mockResolvedValueOnce(jsonResponse({ c: 3 }));

    const [a, b, c] = await Promise.all([
      client.fetch('http://api.example.com/a'),
      client.fetch('http://api.example.com/b'),
      client.fetch('http://api.example.com/c'),
    ]);

    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect(c.status).toBe(200);

    // 3 initial + 1 refresh (NOT 3) + 3 retries = 7 total
    expect(mockFetch).toHaveBeenCalledTimes(7);

    // Verify only 1 call to /refresh
    const refreshCalls = mockFetch.mock.calls.filter(
      (call: unknown[]) => call[0] === `${BASE_URL}/refresh`,
    );
    expect(refreshCalls).toHaveLength(1);
  });

  it('fetch emits unauthenticated after failed retry', async () => {
    // Sign in first
    mockFetch.mockResolvedValueOnce(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    const stateChanges: AuthState[] = [];
    client.onAuthStateChange((state) => stateChanges.push(state));

    // Request 401, refresh fails, retry 401
    mockFetch.mockResolvedValueOnce(jsonResponse(null, 401));
    mockFetch.mockResolvedValueOnce(jsonResponse(null, 401));

    const response = await client.fetch('http://api.example.com/data');
    expect(response.status).toBe(401);
    expect(stateChanges).toContain('unauthenticated');
  });

  it('onAuthStateChange fires immediately with current state', async () => {
    mockFetch.mockResolvedValue(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    const callback = vi.fn();
    client.onAuthStateChange(callback);

    // Should have been called once immediately with current state
    expect(callback).toHaveBeenCalledTimes(1);
    expect(callback).toHaveBeenCalledWith('authenticated', expectedUser);
  });

  it('onAuthStateChange unsubscribe works', async () => {
    const callback = vi.fn();
    const unsubscribe = client.onAuthStateChange(callback);
    expect(callback).toHaveBeenCalledTimes(1); // initial fire

    unsubscribe();

    // Sign in should not trigger the callback
    mockFetch.mockResolvedValue(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    expect(callback).toHaveBeenCalledTimes(1); // still just the initial fire
  });

  it('signInWithProvider sets window.location.href', () => {
    // jsdom doesn't support navigation, so mock window.location
    const mockLocation = { href: '' };
    vi.stubGlobal('location', mockLocation);

    client.signInWithProvider('google');

    expect(mockLocation.href).toBe(
      `${BASE_URL}/oauth/google/authorize`,
    );

    vi.unstubAllGlobals();
  });

  it('signOut sends empty body with credentials:include in cookie mode', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    mockFetch.mockResolvedValueOnce(jsonResponse(null, 204));
    await client.signOut();

    const logoutCall = mockFetch.mock.calls.find(
      (call: unknown[]) => call[0] === `${BASE_URL}/logout`,
    );
    expect(logoutCall).toBeDefined();
    expect(logoutCall![1].credentials).toBe('include');
    expect(JSON.parse(logoutCall![1].body)).toEqual({});
  });
});

describe('AuthClient — bearer mode', () => {
  let client: AuthClient;
  let mockFetch: ReturnType<typeof vi.fn>;
  let storage: ReturnType<typeof createMockStorage>;

  beforeEach(() => {
    vi.useFakeTimers();
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
    storage = createMockStorage();
    client = createAuthClient({
      baseUrl: BASE_URL,
      tokenMode: 'bearer',
      tokenStorage: storage,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  // ---------------------------------------------------------------------------
  // Validation
  // ---------------------------------------------------------------------------

  it('throws when tokenStorage is missing in bearer mode', () => {
    expect(() =>
      createAuthClient({ baseUrl: BASE_URL, tokenMode: 'bearer' }),
    ).toThrow('tokenStorage is required');
  });

  // ---------------------------------------------------------------------------
  // Core bearer flow
  // ---------------------------------------------------------------------------

  it('initialize calls /refresh with stored token and sets state', async () => {
    // Pre-populate storage — simulates app restart with persisted token
    storage.set('persisted-refresh');
    mockFetch.mockResolvedValue(jsonResponse(serverAuthResponse));

    await client.initialize();

    const token = await client.getToken();
    expect(token).toBe('access-123');
  });

  it('initialize with no stored token stays unauthenticated', async () => {
    // Storage is empty
    await client.initialize();

    const stateChanges: AuthState[] = [];
    client.onAuthStateChange((state) => stateChanges.push(state));
    expect(stateChanges).toEqual(['unauthenticated']);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('getToken returns access token after signIn', async () => {
    mockFetch.mockResolvedValue(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    const token = await client.getToken();
    expect(token).toBe('access-123');
  });

  it('fetch attaches Authorization header', async () => {
    // signIn to get a token
    mockFetch.mockResolvedValueOnce(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    // Make an authenticated request
    mockFetch.mockResolvedValueOnce(jsonResponse({ data: 'ok' }));
    await client.fetch('http://api.example.com/data');

    const lastCall = mockFetch.mock.calls[mockFetch.mock.calls.length - 1];
    expect(lastCall[1].headers).toEqual(
      expect.objectContaining({ Authorization: 'Bearer access-123' }),
    );
  });

  it('fetch does not send credentials:include in bearer mode', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    mockFetch.mockResolvedValueOnce(jsonResponse({ data: 'ok' }));
    await client.fetch('http://api.example.com/data');

    const lastCall = mockFetch.mock.calls[mockFetch.mock.calls.length - 1];
    expect(lastCall[1].credentials).toBeUndefined();
  });

  it('fetch retries on 401 with refreshed token (bearer mode)', async () => {
    // signIn
    mockFetch.mockResolvedValueOnce(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    // First request returns 401
    mockFetch.mockResolvedValueOnce(jsonResponse(null, 401));
    // Refresh returns new tokens
    const newAuthResponse = {
      ...serverAuthResponse,
      tokens: {
        ...serverAuthResponse.tokens,
        access_token: 'access-456',
        refresh_token: 'refresh-456',
      },
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(newAuthResponse));
    // Retry succeeds
    mockFetch.mockResolvedValueOnce(jsonResponse({ data: 'ok' }));

    const response = await client.fetch('http://api.example.com/data');
    expect(response.status).toBe(200);

    // Verify the retry used the new token
    const lastCall = mockFetch.mock.calls[mockFetch.mock.calls.length - 1];
    expect(lastCall[1].headers).toEqual(
      expect.objectContaining({ Authorization: 'Bearer access-456' }),
    );
  });

  // ---------------------------------------------------------------------------
  // Token storage interactions
  // ---------------------------------------------------------------------------

  it('stores refresh token via tokenStorage on signIn', async () => {
    mockFetch.mockResolvedValue(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    expect(storage.set).toHaveBeenCalledWith('refresh-123');
    expect(storage._value()).toBe('refresh-123');
  });

  it('stores refresh token via tokenStorage on signUp', async () => {
    mockFetch.mockResolvedValue(jsonResponse(serverAuthResponse, 201));
    await client.signUp({ email: 'test@example.com', password: 'password123' });

    expect(storage.set).toHaveBeenCalledWith('refresh-123');
    expect(storage._value()).toBe('refresh-123');
  });

  it('sends refresh_token in body during refresh', async () => {
    storage.set('stored-refresh-token');
    mockFetch.mockResolvedValue(jsonResponse(serverAuthResponse));

    await client.initialize();

    expect(mockFetch).toHaveBeenCalledWith(
      `${BASE_URL}/refresh`,
      expect.objectContaining({
        body: JSON.stringify({ refresh_token: 'stored-refresh-token' }),
      }),
    );
  });

  it('signOut sends refresh_token in body for bearer mode', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    mockFetch.mockResolvedValueOnce(jsonResponse(null, 204));
    await client.signOut();

    const logoutCall = mockFetch.mock.calls.find(
      (call: unknown[]) => call[0] === `${BASE_URL}/logout`,
    );
    expect(logoutCall).toBeDefined();
    expect(JSON.parse(logoutCall![1].body)).toEqual({ refresh_token: 'refresh-123' });
  });

  it('signOut does not send credentials:include in bearer mode', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    mockFetch.mockResolvedValueOnce(jsonResponse(null, 204));
    await client.signOut();

    const logoutCall = mockFetch.mock.calls.find(
      (call: unknown[]) => call[0] === `${BASE_URL}/logout`,
    );
    expect(logoutCall![1].credentials).toBeUndefined();
  });

  it('clears tokenStorage on signOut', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    mockFetch.mockResolvedValueOnce(jsonResponse(null, 204));
    await client.signOut();

    expect(storage.clear).toHaveBeenCalled();
    expect(storage._value()).toBeNull();
  });

  it('clears tokenStorage on refresh failure', async () => {
    storage.set('expired-refresh-token');
    mockFetch.mockResolvedValue(jsonResponse(null, 401));

    await client.initialize();

    expect(storage.clear).toHaveBeenCalled();
    expect(storage._value()).toBeNull();
  });
});
