import { useState } from 'react';
import { useAuth } from 'authfort-client/react';

export default function App() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <p>Loading...</p>;
  }

  return isAuthenticated ? <Dashboard /> : <AuthForms />;
}

// ---------------------------------------------------------------------------
// Auth forms (sign up + sign in)
// ---------------------------------------------------------------------------

function AuthForms() {
  const { client } = useAuth();
  const [error, setError] = useState('');

  async function handleSignUp(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError('');
    const form = new FormData(e.currentTarget);
    try {
      await client.signUp({
        email: form.get('email') as string,
        password: form.get('password') as string,
        name: (form.get('name') as string) || undefined,
      });
    } catch (err: any) {
      setError(err.message || 'Signup failed');
    }
  }

  async function handleSignIn(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError('');
    const form = new FormData(e.currentTarget);
    try {
      await client.signIn({
        email: form.get('email') as string,
        password: form.get('password') as string,
      });
    } catch (err: any) {
      setError(err.message || 'Signin failed');
    }
  }

  return (
    <div style={{ maxWidth: 400, margin: '40px auto', fontFamily: 'system-ui' }}>
      <h1>AuthFort + React</h1>

      {error && <p style={{ color: 'red' }}>{error}</p>}

      <h2>Sign Up</h2>
      <form onSubmit={handleSignUp}>
        <input name="email" type="email" placeholder="Email" required />
        <br />
        <input name="password" type="password" placeholder="Password" required />
        <br />
        <input name="name" type="text" placeholder="Name (optional)" />
        <br />
        <button type="submit">Sign Up</button>
      </form>

      <h2>Sign In</h2>
      <form onSubmit={handleSignIn}>
        <input name="email" type="email" placeholder="Email" required />
        <br />
        <input name="password" type="password" placeholder="Password" required />
        <br />
        <button type="submit">Sign In</button>
      </form>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Dashboard (authenticated)
// ---------------------------------------------------------------------------

function Dashboard() {
  const { user, client } = useAuth();
  const [profile, setProfile] = useState('');

  async function fetchProfile() {
    const res = await client.fetch('http://localhost:8000/profile');
    const data = await res.json();
    setProfile(JSON.stringify(data, null, 2));
  }

  return (
    <div style={{ maxWidth: 400, margin: '40px auto', fontFamily: 'system-ui' }}>
      <h1>Dashboard</h1>
      <p>Signed in as <strong>{user?.email}</strong></p>
      <p>Roles: {user?.roles.join(', ') || 'none'}</p>

      <button onClick={fetchProfile}>Fetch Profile</button>
      <button onClick={() => client.signOut()} style={{ marginLeft: 8 }}>
        Sign Out
      </button>

      {profile && <pre style={{ background: '#f5f5f5', padding: 12 }}>{profile}</pre>}
    </div>
  );
}
