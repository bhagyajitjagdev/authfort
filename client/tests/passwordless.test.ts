import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createAuthClient } from '../src/client.js';
import type { AuthClient, AuthState, AuthUser, ServerAuthResponse, TokenStorage } from '../src/types.js';

const BASE_URL = 'http://localhost:3000/auth';

const mockAuthResponse: ServerAuthResponse = {
  user: {
    id: '123',
    email: 'test@example.com',
    name: 'Test User',
    phone: null,
    email_verified: true,
    avatar_url: null,
    roles: ['user'],
    created_at: '2024-01-01T00:00:00Z',
  },
  tokens: {
    access_token: 'access-token-123',
    refresh_token: 'refresh-token-456',
    expires_in: 900,
  },
};

const expectedUser: AuthUser = {
  id: '123',
  email: 'test@example.com',
  name: 'Test User',
  phone: undefined,
  roles: ['user'],
  emailVerified: true,
  avatarUrl: undefined,
  createdAt: '2024-01-01T00:00:00Z',
};

function mockResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
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

describe('Passwordless Authentication', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // requestMagicLink
  // -------------------------------------------------------------------------

  describe('requestMagicLink', () => {
    it('sends POST /magic-link with email', async () => {
      const client = createAuthClient({ baseUrl: BASE_URL });
      mockFetch.mockResolvedValue(mockResponse(200, { message: 'ok' }));

      await client.requestMagicLink('test@example.com');

      expect(mockFetch).toHaveBeenCalledWith(
        `${BASE_URL}/magic-link`,
        expect.objectContaining({
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'test@example.com' }),
        }),
      );
    });

    it('throws on error response', async () => {
      const client = createAuthClient({ baseUrl: BASE_URL });
      mockFetch.mockResolvedValue(
        mockResponse(400, { detail: { error: 'bad_request', message: 'Invalid email' } }),
      );

      await expect(client.requestMagicLink('bad')).rejects.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // verifyMagicLink
  // -------------------------------------------------------------------------

  describe('verifyMagicLink', () => {
    it('sends POST /magic-link/verify and returns user', async () => {
      const client = createAuthClient({ baseUrl: BASE_URL });
      mockFetch.mockResolvedValue(mockResponse(200, mockAuthResponse));

      const user = await client.verifyMagicLink('token123');

      expect(user).toEqual(expectedUser);
      expect(mockFetch).toHaveBeenCalledWith(
        `${BASE_URL}/magic-link/verify`,
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ token: 'token123' }),
        }),
      );
    });

    it('sets state to authenticated', async () => {
      const client = createAuthClient({ baseUrl: BASE_URL });
      mockFetch.mockResolvedValue(mockResponse(200, mockAuthResponse));

      const stateChanges: AuthState[] = [];
      client.onAuthStateChange((state) => stateChanges.push(state));

      await client.verifyMagicLink('token123');

      expect(stateChanges).toEqual(['unauthenticated', 'authenticated']);
    });

    it('stores tokens in bearer mode', async () => {
      const storage = createMockStorage();
      const bearerClient = createAuthClient({
        baseUrl: BASE_URL,
        tokenMode: 'bearer',
        tokenStorage: storage,
      });
      mockFetch.mockResolvedValue(mockResponse(200, mockAuthResponse));

      await bearerClient.verifyMagicLink('token123');

      expect(storage.set).toHaveBeenCalledWith('refresh-token-456');
      expect(storage._value()).toBe('refresh-token-456');
    });
  });

  // -------------------------------------------------------------------------
  // requestOTP
  // -------------------------------------------------------------------------

  describe('requestOTP', () => {
    it('sends POST /otp with email', async () => {
      const client = createAuthClient({ baseUrl: BASE_URL });
      mockFetch.mockResolvedValue(mockResponse(200, { message: 'ok' }));

      await client.requestOTP('test@example.com');

      expect(mockFetch).toHaveBeenCalledWith(
        `${BASE_URL}/otp`,
        expect.objectContaining({
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'test@example.com' }),
        }),
      );
    });

    it('throws on error response', async () => {
      const client = createAuthClient({ baseUrl: BASE_URL });
      mockFetch.mockResolvedValue(
        mockResponse(400, { detail: { error: 'bad_request', message: 'Invalid email' } }),
      );

      await expect(client.requestOTP('bad')).rejects.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // verifyOTP
  // -------------------------------------------------------------------------

  describe('verifyOTP', () => {
    it('sends POST /otp/verify with email and code, returns user', async () => {
      const client = createAuthClient({ baseUrl: BASE_URL });
      mockFetch.mockResolvedValue(mockResponse(200, mockAuthResponse));

      const user = await client.verifyOTP('test@example.com', '123456');

      expect(user).toEqual(expectedUser);
      expect(mockFetch).toHaveBeenCalledWith(
        `${BASE_URL}/otp/verify`,
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ email: 'test@example.com', code: '123456' }),
        }),
      );
    });

    it('sets state to authenticated', async () => {
      const client = createAuthClient({ baseUrl: BASE_URL });
      mockFetch.mockResolvedValue(mockResponse(200, mockAuthResponse));

      const stateChanges: AuthState[] = [];
      client.onAuthStateChange((state) => stateChanges.push(state));

      await client.verifyOTP('test@example.com', '123456');

      expect(stateChanges).toEqual(['unauthenticated', 'authenticated']);
    });

    it('stores tokens in bearer mode', async () => {
      const storage = createMockStorage();
      const bearerClient = createAuthClient({
        baseUrl: BASE_URL,
        tokenMode: 'bearer',
        tokenStorage: storage,
      });
      mockFetch.mockResolvedValue(mockResponse(200, mockAuthResponse));

      await bearerClient.verifyOTP('test@example.com', '123456');

      expect(storage.set).toHaveBeenCalledWith('refresh-token-456');
      expect(storage._value()).toBe('refresh-token-456');
    });
  });

  // -------------------------------------------------------------------------
  // verifyEmail
  // -------------------------------------------------------------------------

  describe('verifyEmail', () => {
    it('sends POST /verify-email with token', async () => {
      const client = createAuthClient({ baseUrl: BASE_URL });
      mockFetch.mockResolvedValue(mockResponse(200, { message: 'ok' }));

      await client.verifyEmail('token123');

      expect(mockFetch).toHaveBeenCalledWith(
        `${BASE_URL}/verify-email`,
        expect.objectContaining({
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: 'token123' }),
        }),
      );
    });

    it('updates local emailVerified to true', async () => {
      const client = createAuthClient({ baseUrl: BASE_URL });

      // First authenticate via verifyMagicLink with email_verified: false
      const unverifiedResponse: ServerAuthResponse = {
        ...mockAuthResponse,
        user: { ...mockAuthResponse.user, email_verified: false },
      };
      mockFetch.mockResolvedValueOnce(mockResponse(200, unverifiedResponse));
      await client.verifyMagicLink('token123');

      // Capture state changes going forward
      const users: (AuthUser | null)[] = [];
      client.onAuthStateChange((_state, user) => users.push(user));

      // Now verify email
      mockFetch.mockResolvedValueOnce(mockResponse(200, { message: 'ok' }));
      await client.verifyEmail('verify-token');

      // The most recent user should have emailVerified: true
      const lastUser = users[users.length - 1];
      expect(lastUser).not.toBeNull();
      expect(lastUser!.emailVerified).toBe(true);
    });

    it('throws on error response', async () => {
      const client = createAuthClient({ baseUrl: BASE_URL });
      mockFetch.mockResolvedValue(
        mockResponse(400, { detail: { error: 'invalid_token', message: 'Token expired' } }),
      );

      await expect(client.verifyEmail('bad-token')).rejects.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // signInWithProvider — custom provider string
  // -------------------------------------------------------------------------

  describe('signInWithProvider', () => {
    it('accepts custom provider string', () => {
      const client = createAuthClient({ baseUrl: BASE_URL });

      vi.stubGlobal('window', {
        location: { href: '' },
        screenX: 0,
        screenY: 0,
        outerWidth: 1024,
        outerHeight: 768,
        open: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      });

      client.signInWithProvider('facebook');

      expect(window.location.href).toBe(`${BASE_URL}/oauth/facebook/authorize`);
    });
  });
});
