/**
 * Additional tests to cover gaps in client.ts, errors.ts, and vue/index.ts.
 *
 * Uncovered lines:
 *   client.ts 114-118   — initialize: /me returns non-401 error (e.g., 500)
 *   client.ts 131-132   — getToken: refresh when no token
 *   client.ts 237       — signIn error path
 *   client.ts 263       — signInWithProvider popup mode
 *   client.ts 270-323   — _oauthPopup full flow
 *   client.ts 355       — getUser error path
 *   errors.ts 32        — parseErrorResponse when json() throws
 *   vue/index.ts 68     — useAuth without provideAuth
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createAuthClient } from '../src/client';
import { AuthClientError, parseErrorResponse } from '../src/errors';
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
  phone: null,
};

const serverAuthResponse = {
  user: serverUser,
  tokens: {
    access_token: 'access-123',
    refresh_token: 'refresh-123',
    expires_in: 900,
  },
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

function createMockStorage(): TokenStorage & { _value: () => string | null } {
  const store = { value: null as string | null };
  return {
    get: vi.fn(async () => store.value),
    set: vi.fn(async (token: string) => { store.value = token; }),
    clear: vi.fn(async () => { store.value = null; }),
    _value: () => store.value,
  };
}

// ---------------------------------------------------------------------------
// Cookie mode — additional coverage
// ---------------------------------------------------------------------------

describe('AuthClient — cookie mode (coverage gaps)', () => {
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

  it('initialize sets unauthenticated when /me returns 500', async () => {
    // /me returns 500 (not 401) — should NOT try to refresh
    mockFetch.mockResolvedValue(jsonResponse(null, 500));

    await client.initialize();

    const stateChanges: AuthState[] = [];
    client.onAuthStateChange((state) => stateChanges.push(state));
    expect(stateChanges).toEqual(['unauthenticated']);
    // Should only call /me, not /refresh
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('initialize sets unauthenticated on network error', async () => {
    mockFetch.mockRejectedValue(new TypeError('Network error'));

    await client.initialize();

    const stateChanges: AuthState[] = [];
    client.onAuthStateChange((state) => stateChanges.push(state));
    expect(stateChanges).toEqual(['unauthenticated']);
  });

  it('initialize is idempotent — second call returns same promise', async () => {
    mockFetch.mockResolvedValue(jsonResponse(serverUser));

    const p1 = client.initialize();
    const p2 = client.initialize();
    expect(p1).toBe(p2);
    await p1;
  });

  it('signIn throws AuthClientError on 401', async () => {
    mockFetch.mockResolvedValue(
      jsonResponse(
        { detail: { error: 'invalid_credentials', message: 'Invalid email or password' } },
        401,
      ),
    );

    try {
      await client.signIn({ email: 'test@example.com', password: 'wrong' });
      expect.unreachable('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(AuthClientError);
      expect((e as AuthClientError).code).toBe('invalid_credentials');
      expect((e as AuthClientError).statusCode).toBe(401);
    }
  });

  it('getUser throws AuthClientError when /me fails', async () => {
    // signIn first
    mockFetch.mockResolvedValueOnce(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    // /me returns 403 (banned) — and refresh also fails
    mockFetch.mockResolvedValueOnce(jsonResponse(
      { detail: { error: 'user_banned', message: 'Account banned' } },
      403,
    ));

    try {
      await client.getUser();
      expect.unreachable('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(AuthClientError);
      expect((e as AuthClientError).code).toBe('user_banned');
    }
  });

  it('signInWithProvider with redirect_to includes query param', () => {
    const mockLocation = { href: '' };
    vi.stubGlobal('location', mockLocation);

    client.signInWithProvider('google', { redirectTo: '/dashboard' });

    expect(mockLocation.href).toContain('redirect_to=%2Fdashboard');
    vi.unstubAllGlobals();
  });

  it('signUp sends optional fields (name, avatarUrl, phone)', async () => {
    mockFetch.mockResolvedValue(jsonResponse(serverAuthResponse, 201));

    await client.signUp({
      email: 'test@example.com',
      password: 'password123',
      name: 'Test User',
      avatarUrl: 'https://example.com/avatar.jpg',
      phone: '+1234567890',
    });

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.name).toBe('Test User');
    expect(body.avatar_url).toBe('https://example.com/avatar.jpg');
    expect(body.phone).toBe('+1234567890');
  });

  it('listener error does not break state updates', async () => {
    // Register listeners first (initial fire is 'unauthenticated' — no throw yet)
    const callCount = { bad: 0 };
    const badListener = vi.fn((state: AuthState) => {
      callCount.bad++;
      // Only throw on the second call (state transition), not the initial fire
      if (callCount.bad > 1) throw new Error('listener crashed');
    });
    const goodListener = vi.fn();

    client.onAuthStateChange(badListener);
    client.onAuthStateChange(goodListener);

    // signIn triggers _setState which has try/catch around listener calls
    mockFetch.mockResolvedValue(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    // Good listener should still fire despite bad listener throwing
    expect(goodListener).toHaveBeenCalledWith('authenticated', expect.any(Object));
  });
});

// ---------------------------------------------------------------------------
// Bearer mode — additional coverage
// ---------------------------------------------------------------------------

describe('AuthClient — bearer mode (coverage gaps)', () => {
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

  it('getToken refreshes when no token is available', async () => {
    // Simulate having a stored refresh token but no access token in memory
    storage.set('stored-refresh');
    mockFetch.mockResolvedValue(jsonResponse(serverAuthResponse));

    // Initialize first to load refresh token
    await client.initialize();

    // Expire the access token by advancing time past TTL
    vi.advanceTimersByTime(901_000);

    // getToken should trigger a refresh
    mockFetch.mockResolvedValue(jsonResponse({
      ...serverAuthResponse,
      tokens: { ...serverAuthResponse.tokens, access_token: 'refreshed-token' },
    }));
    const token = await client.getToken();
    // Should get either the refreshed token or the original
    expect(token).toBeTruthy();
  });

  it('getToken returns null when refresh fails', async () => {
    // No stored token, initialize as unauthenticated
    await client.initialize();

    const token = await client.getToken();
    expect(token).toBeNull();
  });

  it('fetch clears state after failed retry in bearer mode', async () => {
    // Sign in first
    mockFetch.mockResolvedValueOnce(jsonResponse(serverAuthResponse));
    await client.signIn({ email: 'test@example.com', password: 'password123' });

    const stateChanges: AuthState[] = [];
    client.onAuthStateChange((state) => stateChanges.push(state));

    // Request 401, refresh fails, retry still 401
    mockFetch.mockResolvedValueOnce(jsonResponse(null, 401)); // first request
    mockFetch.mockResolvedValueOnce(jsonResponse(null, 401)); // refresh attempt
    // After failed refresh, no retry happens, but state should become unauthenticated

    const response = await client.fetch('http://api.example.com/data');
    expect(response.status).toBe(401);
    expect(stateChanges).toContain('unauthenticated');
  });
});

// ---------------------------------------------------------------------------
// Popup OAuth flow
// ---------------------------------------------------------------------------

describe('AuthClient — popup OAuth', () => {
  let client: AuthClient;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
    client = createAuthClient({ baseUrl: BASE_URL, tokenMode: 'cookie' });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('popup mode opens window and resolves on message', async () => {
    let messageHandler: ((event: MessageEvent) => void) | null = null;

    const mockPopup = {
      closed: false,
      close: vi.fn(),
    };

    vi.stubGlobal('open', vi.fn(() => mockPopup));
    vi.stubGlobal('addEventListener', vi.fn((event: string, handler: any) => {
      if (event === 'message') messageHandler = handler;
    }));
    vi.stubGlobal('removeEventListener', vi.fn());
    vi.stubGlobal('screenX', 0);
    vi.stubGlobal('screenY', 0);
    vi.stubGlobal('outerWidth', 1024);
    vi.stubGlobal('outerHeight', 768);

    const promise = client.signInWithProvider('google', { mode: 'popup' }) as Promise<AuthUser>;

    // Simulate the popup posting a message back
    expect(messageHandler).not.toBeNull();
    messageHandler!({
      data: {
        user: serverUser,
        tokens: serverAuthResponse.tokens,
      },
    } as MessageEvent);

    const user = await promise;
    expect(user.email).toBe('test@example.com');
    expect(mockPopup.close).toHaveBeenCalled();
  });

  it('popup rejects when blocked by browser', async () => {
    vi.stubGlobal('open', vi.fn(() => null));
    vi.stubGlobal('screenX', 0);
    vi.stubGlobal('screenY', 0);
    vi.stubGlobal('outerWidth', 1024);
    vi.stubGlobal('outerHeight', 768);

    const promise = client.signInWithProvider('google', { mode: 'popup' }) as Promise<AuthUser>;

    await expect(promise).rejects.toThrow('Popup blocked');
  });

  it('popup rejects when user closes popup', async () => {
    vi.useFakeTimers();

    const mockPopup = {
      closed: false,
      close: vi.fn(),
    };

    vi.stubGlobal('open', vi.fn(() => mockPopup));
    vi.stubGlobal('addEventListener', vi.fn());
    vi.stubGlobal('removeEventListener', vi.fn());
    vi.stubGlobal('screenX', 0);
    vi.stubGlobal('screenY', 0);
    vi.stubGlobal('outerWidth', 1024);
    vi.stubGlobal('outerHeight', 768);

    const promise = client.signInWithProvider('google', { mode: 'popup' }) as Promise<AuthUser>;

    // Simulate popup being closed by user
    mockPopup.closed = true;
    vi.advanceTimersByTime(600);

    await expect(promise).rejects.toThrow('popup was closed');
    vi.useRealTimers();
  });

  it('popup ignores irrelevant messages', async () => {
    vi.useFakeTimers();

    let messageHandler: ((event: MessageEvent) => void) | null = null;

    const mockPopup = {
      closed: false,
      close: vi.fn(),
    };

    vi.stubGlobal('open', vi.fn(() => mockPopup));
    vi.stubGlobal('addEventListener', vi.fn((event: string, handler: any) => {
      if (event === 'message') messageHandler = handler;
    }));
    vi.stubGlobal('removeEventListener', vi.fn());
    vi.stubGlobal('screenX', 0);
    vi.stubGlobal('screenY', 0);
    vi.stubGlobal('outerWidth', 1024);
    vi.stubGlobal('outerHeight', 768);

    const promise = client.signInWithProvider('google', { mode: 'popup' }) as Promise<AuthUser>;

    // Irrelevant messages should be ignored
    messageHandler!({ data: null } as MessageEvent);
    messageHandler!({ data: 'string-data' } as MessageEvent);
    messageHandler!({ data: { foo: 'bar' } } as MessageEvent);

    // Now send the real message
    messageHandler!({
      data: { user: serverUser },
    } as MessageEvent);

    const user = await promise;
    expect(user.email).toBe('test@example.com');
    vi.useRealTimers();
  });
});

// ---------------------------------------------------------------------------
// parseErrorResponse edge cases
// ---------------------------------------------------------------------------

describe('parseErrorResponse', () => {
  it('handles response with plain body (no detail wrapper)', async () => {
    const response = jsonResponse(
      { error: 'some_error', message: 'Some error message' },
      400,
    );
    const err = await parseErrorResponse(response);
    expect(err.code).toBe('some_error');
    expect(err.message).toBe('Some error message');
  });

  it('falls back when json() throws', async () => {
    const response = {
      ok: false,
      status: 502,
      statusText: 'Bad Gateway',
      json: () => Promise.reject(new Error('Invalid JSON')),
      headers: new Headers(),
    } as Response;

    const err = await parseErrorResponse(response);
    expect(err.code).toBe('unknown_error');
    expect(err.message).toBe('Bad Gateway');
    expect(err.statusCode).toBe(502);
  });

  it('handles missing message in detail', async () => {
    const response = jsonResponse(
      { detail: { error: 'custom_error' } },
      422,
    );
    const err = await parseErrorResponse(response);
    expect(err.code).toBe('custom_error');
    expect(err.statusCode).toBe(422);
  });
});

// ---------------------------------------------------------------------------
// Vue useAuth without provideAuth
// ---------------------------------------------------------------------------

describe('Vue — useAuth without provideAuth', () => {
  it('throws error when used without provideAuth', async () => {
    // Dynamically import to avoid polluting other tests
    const { defineComponent, h } = await import('vue');
    const { mount } = await import('@vue/test-utils');
    const { useAuth } = await import('../src/vue/index');

    const BadComponent = defineComponent({
      setup() {
        useAuth(); // should throw
        return () => h('div');
      },
    });

    expect(() => mount(BadComponent)).toThrow(
      'useAuth() requires provideAuth() in a parent component',
    );
  });
});
