import { createApp } from 'vue';
import { createAuthClient } from 'authfort-client';
import App from './App.vue';

const auth = createAuthClient({
  baseUrl: 'http://localhost:8000/auth',
  tokenMode: 'cookie',
});

auth.initialize();

const app = createApp(App, { authClient: auth });
app.mount('#app');
