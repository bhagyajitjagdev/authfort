import { describe, it, expect, vi } from 'vitest';
import { defineComponent, h, nextTick } from 'vue';
import { mount } from '@vue/test-utils';
import { provideAuth, useAuth } from '../src/vue/index';
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

describe('Vue — provideAuth + useAuth', () => {
  it('provides initial unauthenticated state', () => {
    const { client } = createMockClient();

    const Child = defineComponent({
      setup() {
        const auth = useAuth();
        return () =>
          h('div', [
            h('span', { id: 'state' }, auth.state.value),
            h('span', { id: 'isAuth' }, String(auth.isAuthenticated.value)),
          ]);
      },
    });

    const Parent = defineComponent({
      setup() {
        provideAuth(client);
        return () => h(Child);
      },
    });

    const wrapper = mount(Parent);
    expect(wrapper.find('#state').text()).toBe('unauthenticated');
    expect(wrapper.find('#isAuth').text()).toBe('false');
  });

  it('provides authenticated state with user', () => {
    const { client } = createMockClient('authenticated', testUser);

    const Child = defineComponent({
      setup() {
        const auth = useAuth();
        return () =>
          h('div', [
            h('span', { id: 'state' }, auth.state.value),
            h('span', { id: 'email' }, auth.user.value?.email ?? 'none'),
          ]);
      },
    });

    const Parent = defineComponent({
      setup() {
        provideAuth(client);
        return () => h(Child);
      },
    });

    const wrapper = mount(Parent);
    expect(wrapper.find('#state').text()).toBe('authenticated');
    expect(wrapper.find('#email').text()).toBe('test@example.com');
  });

  it('updates reactively on state transition', async () => {
    const { client, emit } = createMockClient();

    const Child = defineComponent({
      setup() {
        const auth = useAuth();
        return () =>
          h('div', [
            h('span', { id: 'state' }, auth.state.value),
            h('span', { id: 'email' }, auth.user.value?.email ?? 'none'),
          ]);
      },
    });

    const Parent = defineComponent({
      setup() {
        provideAuth(client);
        return () => h(Child);
      },
    });

    const wrapper = mount(Parent);
    expect(wrapper.find('#state').text()).toBe('unauthenticated');

    emit('authenticated', testUser);
    await nextTick();

    expect(wrapper.find('#state').text()).toBe('authenticated');
    expect(wrapper.find('#email').text()).toBe('test@example.com');
  });

  it('shows loading state via computed', () => {
    const { client } = createMockClient('loading');

    const Child = defineComponent({
      setup() {
        const auth = useAuth();
        return () =>
          h('span', { id: 'isLoading' }, String(auth.isLoading.value));
      },
    });

    const Parent = defineComponent({
      setup() {
        provideAuth(client);
        return () => h(Child);
      },
    });

    const wrapper = mount(Parent);
    expect(wrapper.find('#isLoading').text()).toBe('true');
  });
});
