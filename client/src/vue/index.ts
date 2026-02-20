/**
 * Vue composables for AuthFort.
 *
 * Usage:
 *   import { provideAuth, useAuth } from 'authfort-client/vue';
 *
 *   // In root component setup
 *   provideAuth(auth);
 *
 *   // In any child component
 *   const { user, isAuthenticated, client } = useAuth();
 */

import {
  ref,
  readonly,
  computed,
  inject,
  provide,
  onUnmounted,
  type Ref,
  type ComputedRef,
  type InjectionKey,
} from 'vue';
import type { AuthClient, AuthState, AuthUser } from '../types.js';

// ---------------------------------------------------------------------------
// Injection key
// ---------------------------------------------------------------------------

const AUTH_KEY: InjectionKey<AuthClient> = Symbol('authfort');

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/** Provide the AuthFort client to all descendant components. Call in root component's setup. Auto-calls initialize(). */
export function provideAuth(client: AuthClient): void {
  provide(AUTH_KEY, client);
  client.initialize();
}

// ---------------------------------------------------------------------------
// Composable
// ---------------------------------------------------------------------------

/** Return type of useAuth() */
export interface UseAuthReturn {
  /** Current auth state (readonly ref) */
  state: Readonly<Ref<AuthState>>;
  /** Current user (readonly ref, null when not authenticated) */
  user: Readonly<Ref<AuthUser | null>>;
  /** Whether the user is authenticated */
  isAuthenticated: ComputedRef<boolean>;
  /** Whether auth state is being determined */
  isLoading: ComputedRef<boolean>;
  /** The AuthFort client instance */
  client: AuthClient;
}

/**
 * Vue composable for AuthFort auth state.
 * Must be called inside a component whose ancestor called provideAuth().
 */
export function useAuth(): UseAuthReturn {
  const client = inject(AUTH_KEY);
  if (!client) {
    throw new Error('useAuth() requires provideAuth() in a parent component');
  }

  const state = ref<AuthState>('unauthenticated');
  const user = ref<AuthUser | null>(null);

  const unsubscribe = client.onAuthStateChange((s, u) => {
    state.value = s;
    user.value = u;
  });

  onUnmounted(unsubscribe);

  return {
    state: readonly(state),
    user: readonly(user) as Readonly<Ref<AuthUser | null>>,
    isAuthenticated: computed(() => state.value === 'authenticated'),
    isLoading: computed(() => state.value === 'loading'),
    client,
  };
}
