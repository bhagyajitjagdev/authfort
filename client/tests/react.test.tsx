import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { AuthProvider, useAuth } from '../src/react/index';
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
// Test component that uses useAuth
// ---------------------------------------------------------------------------

function TestConsumer() {
  const { state, user, isAuthenticated, isLoading } = useAuth();
  return (
    <div>
      <span data-testid="state">{state}</span>
      <span data-testid="email">{user?.email ?? 'none'}</span>
      <span data-testid="isAuth">{String(isAuthenticated)}</span>
      <span data-testid="isLoading">{String(isLoading)}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('React — AuthProvider + useAuth', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('provides initial unauthenticated state', () => {
    const { client } = createMockClient();

    render(
      <AuthProvider client={client}>
        <TestConsumer />
      </AuthProvider>,
    );

    expect(screen.getByTestId('state').textContent).toBe('unauthenticated');
    expect(screen.getByTestId('email').textContent).toBe('none');
    expect(screen.getByTestId('isAuth').textContent).toBe('false');
  });

  it('provides authenticated state with user', () => {
    const { client } = createMockClient('authenticated', testUser);

    render(
      <AuthProvider client={client}>
        <TestConsumer />
      </AuthProvider>,
    );

    expect(screen.getByTestId('state').textContent).toBe('authenticated');
    expect(screen.getByTestId('email').textContent).toBe('test@example.com');
    expect(screen.getByTestId('isAuth').textContent).toBe('true');
  });

  it('updates on state transition', () => {
    const { client, emit } = createMockClient();

    render(
      <AuthProvider client={client}>
        <TestConsumer />
      </AuthProvider>,
    );

    expect(screen.getByTestId('state').textContent).toBe('unauthenticated');

    act(() => {
      emit('authenticated', testUser);
    });

    expect(screen.getByTestId('state').textContent).toBe('authenticated');
    expect(screen.getByTestId('email').textContent).toBe('test@example.com');
  });

  it('shows loading state', () => {
    const { client } = createMockClient('loading');

    render(
      <AuthProvider client={client}>
        <TestConsumer />
      </AuthProvider>,
    );

    expect(screen.getByTestId('isLoading').textContent).toBe('true');
    expect(screen.getByTestId('isAuth').textContent).toBe('false');
  });

  it('throws when useAuth is used outside AuthProvider', () => {
    // Suppress React error boundary logging
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => render(<TestConsumer />)).toThrow(
      'useAuth() must be used inside <AuthProvider>',
    );

    spy.mockRestore();
  });
});
