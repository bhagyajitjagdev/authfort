# AuthFort — Vanilla JS Example

A minimal example using the AuthFort client SDK without any framework.

## Setup

1. **Start the auth server** (see `examples/fastapi-example/server/`):
   ```bash
   cd examples/fastapi-example/server
   uvicorn main:app --reload --port 8000
   ```

2. **Build the client SDK**:
   ```bash
   cd client
   npm run build
   ```

3. **Serve this directory** (any static server works):
   ```bash
   cd examples/client-example/vanilla
   python -m http.server 3000
   ```

4. Open `http://localhost:3000` in your browser.

## What It Shows

- `createAuthClient()` with cookie mode
- `auth.signUp()` / `auth.signIn()` — email/password auth
- `auth.signOut()` — logout
- `auth.onAuthStateChange()` — reactive UI updates
- `auth.fetch()` — authenticated requests with auto 401 retry
- `auth.initialize()` — session recovery on page load
- `auth.signInWithProvider()` — OAuth redirect (commented out, enable if providers configured)

## Token Modes

Change `tokenMode` in the script to try different modes:

```javascript
// Cookie mode (default) — httponly cookies, most secure for browsers
const auth = createAuthClient({ baseUrl: '/auth', tokenMode: 'cookie' });

// Bearer mode — access token in memory, Authorization header
const auth = createAuthClient({ baseUrl: '/auth', tokenMode: 'bearer' });
```
