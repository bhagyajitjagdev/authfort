/**
 * Svelte stores for AuthFort.
 *
 * Usage:
 *   import { createAuthStore } from 'authfort-client/svelte';
 *
 *   // Create once (e.g., in auth.ts)
 *   export const authStore = createAuthStore(auth);
 *
 *   // Use in components
 *   const { state, user, isAuthenticated } = authStore;
 *   {#if $isAuthenticated} Hello {$user.email} {/if}
 */

import { writable, derived, type Readable } from 'svelte/store';
import type { AuthClient, AuthState, AuthUser } from '../types';

// ---------------------------------------------------------------------------
// Store factory
// ---------------------------------------------------------------------------

/** Return type of createAuthStore() */
export interface AuthStore {
  /** Current auth state (readable store) */
  state: Readable<AuthState>;
  /** Current user (readable store, null when not authenticated) */
  user: Readable<AuthUser | null>;
  /** Whether the user is authenticated (derived store) */
  isAuthenticated: Readable<boolean>;
  /** Whether auth state is being determined (derived store) */
  isLoading: Readable<boolean>;
  /** The AuthFort client instance */
  client: AuthClient;
}

/**
 * Create a Svelte store that tracks AuthFort auth state.
 * Call once at module level and export for use in components.
 */
export function createAuthStore(client: AuthClient): AuthStore {
  const state = writable<AuthState>('unauthenticated');
  const user = writable<AuthUser | null>(null);

  client.onAuthStateChange((s, u) => {
    state.set(s);
    user.set(u);
  });

  return {
    state: { subscribe: state.subscribe } as Readable<AuthState>,
    user: { subscribe: user.subscribe } as Readable<AuthUser | null>,
    isAuthenticated: derived(state, ($s) => $s === 'authenticated'),
    isLoading: derived(state, ($s) => $s === 'loading'),
    client,
  };
}
