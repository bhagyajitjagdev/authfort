import { describe, it, expect, vi } from 'vitest';
import { get } from 'svelte/store';
import { createAuthStore } from '../src/svelte/index';
import type { AuthClient, AuthState, AuthUser } from '../src/types';

// ---------------------------------------------------------------------------
// Mock client
// ---------------------------------------------------------------------------

type StateCallback = (state: AuthState, user: AuthUser | null) => void;

function createMockClient(
  initialState: AuthState = 'unauthenticated',
  initialUser: AuthUser | null = null,
) {
  let listener: StateCallback | null = null;

  const client: AuthClient = {
    initialize: vi.fn(),
    getToken: vi.fn(),
    fetch: vi.fn(),
    getUser: vi.fn(),
    signUp: vi.fn(),
    signIn: vi.fn(),
    signInWithProvider: vi.fn(),
    signOut: vi.fn(),
    onAuthStateChange: vi.fn((cb: StateCallback) => {
      listener = cb;
      cb(initialState, initialUser);
      return () => {
        listener = null;
      };
    }),
  };

  const emit = (state: AuthState, user: AuthUser | null) => {
    if (listener) listener(state, user);
  };

  return { client, emit };
}

const testUser: AuthUser = {
  id: '123',
  email: 'test@example.com',
  name: 'Test User',
  roles: ['user'],
  emailVerified: true,
  avatarUrl: undefined,
  createdAt: '2026-01-01T00:00:00Z',
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Svelte — createAuthStore', () => {
  it('initializes with unauthenticated state', () => {
    const { client } = createMockClient();
    const store = createAuthStore(client);

    expect(get(store.state)).toBe('unauthenticated');
    expect(get(store.user)).toBeNull();
    expect(get(store.isAuthenticated)).toBe(false);
    expect(get(store.isLoading)).toBe(false);
  });

  it('initializes with authenticated state and user', () => {
    const { client } = createMockClient('authenticated', testUser);
    const store = createAuthStore(client);

    expect(get(store.state)).toBe('authenticated');
    expect(get(store.user)?.email).toBe('test@example.com');
    expect(get(store.isAuthenticated)).toBe(true);
  });

  it('updates stores on state transition', () => {
    const { client, emit } = createMockClient();
    const store = createAuthStore(client);

    expect(get(store.state)).toBe('unauthenticated');

    emit('authenticated', testUser);

    expect(get(store.state)).toBe('authenticated');
    expect(get(store.user)?.email).toBe('test@example.com');
    expect(get(store.isAuthenticated)).toBe(true);
  });

  it('derived isLoading store works', () => {
    const { client } = createMockClient('loading');
    const store = createAuthStore(client);

    expect(get(store.isLoading)).toBe(true);
    expect(get(store.isAuthenticated)).toBe(false);
  });

  it('exposes client instance', () => {
    const { client } = createMockClient();
    const store = createAuthStore(client);

    expect(store.client).toBe(client);
  });
});
