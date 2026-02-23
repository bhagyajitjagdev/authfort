<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../.github/logo-dark.svg" width="60">
  <source media="(prefers-color-scheme: light)" srcset="../.github/logo-light.svg" width="60">
  <img alt="AuthFort" src="../.github/logo-light.svg" width="60">
</picture>

# authfort-client

[![npm](https://img.shields.io/npm/v/authfort-client)](https://www.npmjs.com/package/authfort-client)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docs](https://img.shields.io/badge/Docs-blue?logo=readthedocs&logoColor=white)](https://bhagyajitjagdev.github.io/authfort/client/)

</div>

TypeScript client SDK for AuthFort authentication.

## Install

```bash
npm install authfort-client
```

## Quick Start

```typescript
import { createAuthClient } from 'authfort-client';

const auth = createAuthClient({
  baseUrl: '/auth',
  tokenMode: 'cookie', // or 'bearer'
});

await auth.initialize();

// Sign up / sign in
await auth.signUp({ email: 'user@example.com', password: 'secret' });
await auth.signIn({ email: 'user@example.com', password: 'secret' });

// Authenticated fetch (auto-attaches credentials, retries on 401)
const res = await auth.fetch('/api/profile');

// OAuth (built-in or any generic provider)
auth.signInWithProvider('google');
auth.signInWithProvider('keycloak'); // generic providers work too

// Passwordless
await auth.requestMagicLink('user@example.com');
const user = await auth.verifyMagicLink(token);

await auth.requestOTP('user@example.com');
const user2 = await auth.verifyOTP('user@example.com', '123456');

// Listen for auth state changes
auth.onAuthStateChange((state, user) => {
  console.log(state, user);
});

// Sign out
await auth.signOut();
```

## React

```tsx
import { AuthProvider, useAuth } from 'authfort-client/react';

// Wrap your app
<AuthProvider client={auth}><App /></AuthProvider>

// In components
function Profile() {
  const { user, isAuthenticated, client } = useAuth();
  if (!isAuthenticated) return <p>Not signed in</p>;
  return <p>Hello {user.email}</p>;
}
```

## Vue

```vue
<script setup>
import { provideAuth, useAuth } from 'authfort-client/vue';

provideAuth(auth); // in root component

const { user, isAuthenticated } = useAuth(); // in any child
</script>
```

## Svelte

```svelte
<script>
import { createAuthStore } from 'authfort-client/svelte';

const { user, isAuthenticated, client } = createAuthStore(auth);
</script>

{#if $isAuthenticated}
  Hello {$user.email}
{/if}
```

## Authenticated Requests

`auth.fetch()` is native `fetch` with auth added — same `RequestInit`, same `Response`. Headers, streaming, AbortController all work as normal.

```typescript
// JSON POST
const res = await auth.fetch('/api/data', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'test' }),
});

// Streaming
const stream = await auth.fetch('/api/stream');
const reader = stream.body.getReader();

// AbortController
const controller = new AbortController();
await auth.fetch('/api/slow', { signal: controller.signal });
```

If a request gets a 401, it automatically refreshes the token and retries once. Multiple concurrent 401s share a single refresh call.

### Using with Axios / TanStack Query (bearer mode)

In cookie mode, any HTTP client works out of the box — the browser sends cookies automatically. In bearer mode, if you prefer your own HTTP client over `auth.fetch()`, use `getToken()` to get a valid token:

```typescript
// Axios interceptor
axios.interceptors.request.use(async (config) => {
  const token = await auth.getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// TanStack Query
const { data } = useQuery({
  queryKey: ['profile'],
  queryFn: async () => {
    const token = await auth.getToken();
    const res = await fetch('/api/profile', {
      headers: { Authorization: `Bearer ${token}` },
    });
    return res.json();
  },
});
```

`getToken()` automatically refreshes if the token is expired, and deduplicates concurrent refresh calls.

## Token Modes

- **cookie** (default) — httponly cookies, JS never touches tokens
- **bearer** — access token in memory, `Authorization: Bearer` header

## License

[MIT](../LICENSE)
