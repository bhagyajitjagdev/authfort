/**
 * React hooks for AuthFort.
 *
 * Usage:
 *   import { AuthProvider, useAuth } from 'authfort-client/react';
 *
 *   // Wrap your app
 *   <AuthProvider client={auth}><App /></AuthProvider>
 *
 *   // Use in any component
 *   const { user, isAuthenticated, client } = useAuth();
 */

import {
  createContext,
  useContext,
  useState,
  useEffect,
  type ReactNode,
} from 'react';
import type { AuthClient, AuthState, AuthUser } from '../types.js';

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const AuthContext = createContext<AuthClient | null>(null);

/** Props for AuthProvider */
export interface AuthProviderProps {
  client: AuthClient;
  children: ReactNode;
}

/** Provides the AuthFort client to all child components. */
export function AuthProvider({ client, children }: AuthProviderProps) {
  return <AuthContext.Provider value={client}>{children}</AuthContext.Provider>;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/** Return type of useAuth() */
export interface UseAuthReturn {
  /** Current auth state */
  state: AuthState;
  /** Current user (null when not authenticated) */
  user: AuthUser | null;
  /** Whether the user is authenticated */
  isAuthenticated: boolean;
  /** Whether auth state is being determined */
  isLoading: boolean;
  /** The AuthFort client instance (for signIn, signOut, fetch, etc.) */
  client: AuthClient;
}

/**
 * React hook for AuthFort auth state.
 * Must be used inside an AuthProvider.
 */
export function useAuth(): UseAuthReturn {
  const client = useContext(AuthContext);
  if (!client) {
    throw new Error('useAuth() must be used inside <AuthProvider>');
  }

  const [state, setState] = useState<AuthState>('unauthenticated');
  const [user, setUser] = useState<AuthUser | null>(null);

  useEffect(() => {
    return client.onAuthStateChange((s, u) => {
      setState(s);
      setUser(u);
    });
  }, [client]);

  return {
    state,
    user,
    isAuthenticated: state === 'authenticated',
    isLoading: state === 'loading',
    client,
  };
}
