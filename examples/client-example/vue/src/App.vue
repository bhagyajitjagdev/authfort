<script setup lang="ts">
import { ref } from 'vue';
import type { AuthClient } from 'authfort-client';
import { provideAuth, useAuth } from 'authfort-client/vue';

const props = defineProps<{ authClient: AuthClient }>();
provideAuth(props.authClient);

const { state, user, isAuthenticated, isLoading, client } = useAuth();

// Form state
const signUpEmail = ref('');
const signUpPassword = ref('');
const signUpName = ref('');
const signInEmail = ref('');
const signInPassword = ref('');
const error = ref('');
const profile = ref('');

async function handleSignUp() {
  error.value = '';
  try {
    await client.signUp({
      email: signUpEmail.value,
      password: signUpPassword.value,
      name: signUpName.value || undefined,
    });
  } catch (err: any) {
    error.value = err.message || 'Signup failed';
  }
}

async function handleSignIn() {
  error.value = '';
  try {
    await client.signIn({
      email: signInEmail.value,
      password: signInPassword.value,
    });
  } catch (err: any) {
    error.value = err.message || 'Signin failed';
  }
}

async function fetchProfile() {
  const res = await client.fetch('http://localhost:8000/profile');
  const data = await res.json();
  profile.value = JSON.stringify(data, null, 2);
}

async function handleSignOut() {
  await client.signOut();
  profile.value = '';
}
</script>

<template>
  <div style="max-width: 400px; margin: 40px auto; font-family: system-ui">
    <h1>AuthFort + Vue</h1>

    <p v-if="isLoading">Loading...</p>

    <!-- Authenticated -->
    <template v-else-if="isAuthenticated">
      <p>Signed in as <strong>{{ user?.email }}</strong></p>
      <p>Roles: {{ user?.roles.join(', ') || 'none' }}</p>

      <button @click="fetchProfile">Fetch Profile</button>
      <button @click="handleSignOut" style="margin-left: 8px">Sign Out</button>

      <pre v-if="profile" style="background: #f5f5f5; padding: 12px">{{ profile }}</pre>
    </template>

    <!-- Unauthenticated -->
    <template v-else>
      <p v-if="error" style="color: red">{{ error }}</p>

      <h2>Sign Up</h2>
      <form @submit.prevent="handleSignUp">
        <input v-model="signUpEmail" type="email" placeholder="Email" required /><br />
        <input v-model="signUpPassword" type="password" placeholder="Password" required /><br />
        <input v-model="signUpName" type="text" placeholder="Name (optional)" /><br />
        <button type="submit">Sign Up</button>
      </form>

      <h2>Sign In</h2>
      <form @submit.prevent="handleSignIn">
        <input v-model="signInEmail" type="email" placeholder="Email" required /><br />
        <input v-model="signInPassword" type="password" placeholder="Password" required /><br />
        <button type="submit">Sign In</button>
      </form>
    </template>
  </div>
</template>
