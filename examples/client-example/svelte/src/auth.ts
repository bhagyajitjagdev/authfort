import { createAuthClient } from 'authfort-client';
import { createAuthStore } from 'authfort-client/svelte';

const auth = createAuthClient({
  baseUrl: 'http://localhost:8000/auth',
  tokenMode: 'cookie',
});

auth.initialize();

export const authStore = createAuthStore(auth);
