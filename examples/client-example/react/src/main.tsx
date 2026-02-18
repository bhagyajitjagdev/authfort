import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { createAuthClient } from 'authfort-client';
import { AuthProvider } from 'authfort-client/react';
import App from './App';

const auth = createAuthClient({
  baseUrl: 'http://localhost:8000/auth',
  tokenMode: 'cookie',
});

// Check for existing session on load
auth.initialize();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AuthProvider client={auth}>
      <App />
    </AuthProvider>
  </StrictMode>,
);
