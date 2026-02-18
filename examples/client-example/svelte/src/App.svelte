<script lang="ts">
  import { authStore } from './auth';

  const { state, user, isAuthenticated, isLoading, client } = authStore;

  let signUpEmail = $state('');
  let signUpPassword = $state('');
  let signUpName = $state('');
  let signInEmail = $state('');
  let signInPassword = $state('');
  let error = $state('');
  let profile = $state('');

  async function handleSignUp() {
    error = '';
    try {
      await client.signUp({
        email: signUpEmail,
        password: signUpPassword,
        name: signUpName || undefined,
      });
    } catch (err: any) {
      error = err.message || 'Signup failed';
    }
  }

  async function handleSignIn() {
    error = '';
    try {
      await client.signIn({
        email: signInEmail,
        password: signInPassword,
      });
    } catch (err: any) {
      error = err.message || 'Signin failed';
    }
  }

  async function fetchProfile() {
    const res = await client.fetch('http://localhost:8000/profile');
    const data = await res.json();
    profile = JSON.stringify(data, null, 2);
  }

  async function handleSignOut() {
    await client.signOut();
    profile = '';
  }
</script>

<div style="max-width: 400px; margin: 40px auto; font-family: system-ui">
  <h1>AuthFort + Svelte</h1>

  {#if $isLoading}
    <p>Loading...</p>
  {:else if $isAuthenticated}
    <p>Signed in as <strong>{$user?.email}</strong></p>
    <p>Roles: {$user?.roles.join(', ') || 'none'}</p>

    <button onclick={fetchProfile}>Fetch Profile</button>
    <button onclick={handleSignOut} style="margin-left: 8px">Sign Out</button>

    {#if profile}
      <pre style="background: #f5f5f5; padding: 12px">{profile}</pre>
    {/if}
  {:else}
    {#if error}
      <p style="color: red">{error}</p>
    {/if}

    <h2>Sign Up</h2>
    <form onsubmit={e => { e.preventDefault(); handleSignUp(); }}>
      <input bind:value={signUpEmail} type="email" placeholder="Email" required /><br />
      <input bind:value={signUpPassword} type="password" placeholder="Password" required /><br />
      <input bind:value={signUpName} type="text" placeholder="Name (optional)" /><br />
      <button type="submit">Sign Up</button>
    </form>

    <h2>Sign In</h2>
    <form onsubmit={e => { e.preventDefault(); handleSignIn(); }}>
      <input bind:value={signInEmail} type="email" placeholder="Email" required /><br />
      <input bind:value={signInPassword} type="password" placeholder="Password" required /><br />
      <button type="submit">Sign In</button>
    </form>
  {/if}
</div>
