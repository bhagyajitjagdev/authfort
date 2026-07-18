/**
 * F6 (v0.0.31): the OAuth callback delivers mfa_token in the URL *fragment*
 * (kept out of logs / Referer). The client must read it from the fragment,
 * still accept the legacy query-string form, transition to 'mfa_pending', and
 * scrub the token from the visible URL.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createAuthClient } from '../src/client';
import type { AuthClient, AuthState } from '../src/types';

const BASE_URL = 'http://localhost:8000/auth';

let replaceStateSpy: ReturnType<typeof vi.fn>;

function mockLocation(opts: { pathname?: string; search?: string; hash?: string }) {
  const loc = {
    pathname: opts.pathname ?? '/callback',
    search: opts.search ?? '',
    hash: opts.hash ?? '',
    href: 'http://localhost:3000' + (opts.pathname ?? '/callback'),
  };
  vi.stubGlobal('location', loc);
  replaceStateSpy = vi.fn();
  vi.stubGlobal('history', { replaceState: replaceStateSpy });
  return loc;
}

describe('OAuth MFA redirect token parsing', () => {
  let client: AuthClient;

  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('reads mfa_token from the URL fragment and enters mfa_pending', async () => {
    mockLocation({ hash: '#mfa_token=frag-token-123' });
    client = createAuthClient({ baseUrl: BASE_URL });

    const states: AuthState[] = [];
    client.onAuthStateChange((s) => states.push(s));

    await client.initialize();

    expect(states).toContain('mfa_pending');
    // fetch must NOT be called — we short-circuit into the MFA step.
    expect((globalThis.fetch as ReturnType<typeof vi.fn>)).not.toHaveBeenCalled();
  });

  it('still reads mfa_token from the legacy query string', async () => {
    mockLocation({ search: '?mfa_token=query-token-456' });
    client = createAuthClient({ baseUrl: BASE_URL });

    const states: AuthState[] = [];
    client.onAuthStateChange((s) => states.push(s));

    await client.initialize();

    expect(states).toContain('mfa_pending');
  });

  it('strips the token from the URL via replaceState (fragment)', async () => {
    mockLocation({ pathname: '/callback', hash: '#mfa_token=frag-token-123' });
    client = createAuthClient({ baseUrl: BASE_URL });

    await client.initialize();

    expect(replaceStateSpy).toHaveBeenCalledTimes(1);
    const newUrl = replaceStateSpy.mock.calls[0][2] as string;
    expect(newUrl).not.toContain('mfa_token');
    expect(newUrl).toBe('/callback');
  });

  it('preserves other query params and fragment entries when stripping', async () => {
    mockLocation({
      pathname: '/callback',
      search: '?foo=bar',
      hash: '#mfa_token=frag-token-123&tab=security',
    });
    client = createAuthClient({ baseUrl: BASE_URL });

    await client.initialize();

    const newUrl = replaceStateSpy.mock.calls[0][2] as string;
    expect(newUrl).toContain('foo=bar');
    expect(newUrl).toContain('tab=security');
    expect(newUrl).not.toContain('mfa_token');
  });

  it('completes MFA login using the token captured from the fragment', async () => {
    mockLocation({ hash: '#mfa_token=frag-token-123' });
    client = createAuthClient({ baseUrl: BASE_URL });
    await client.initialize();

    const serverAuthResponse = {
      user: {
        id: '1', email: 'a@b.co', name: null, email_verified: true,
        avatar_url: null, roles: [], created_at: '2026-01-01T00:00:00Z',
        phone: null, mfa_enabled: true,
      },
      tokens: { access_token: 'a', refresh_token: 'r', expires_in: 900 },
    };
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true, status: 200, json: () => Promise.resolve(serverAuthResponse),
      headers: new Headers(),
    } as Response);

    await client.verifyMFA('123456');

    // The captured fragment token is sent to /mfa/verify.
    const [, options] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(JSON.parse(options.body).mfa_token).toBe('frag-token-123');
  });
});
