// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  site: 'https://bhagyajitjagdev.github.io',
  base: '/authfort',
  integrations: [
    starlight({
      title: 'AuthFort',
      logo: {
        light: './src/assets/logo-light.svg',
        dark: './src/assets/logo-dark.svg',
        replacesTitle: false,
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/bhagyajitjagdev/authfort',
        },
      ],
      editLink: {
        baseUrl: 'https://github.com/bhagyajitjagdev/authfort/edit/main/docs-site/',
      },
      components: {
        ThemeSelect: './src/components/ThemeToggle.astro',
      },
      customCss: ['./src/styles/global.css'],
      sidebar: [
        {
          label: 'Getting Started',
          items: [
            { label: 'Overview', slug: 'getting-started' },
            { label: 'Installation', slug: 'getting-started/installation' },
            { label: 'Quick Start', slug: 'getting-started/quickstart' },
            { label: 'Concepts', slug: 'getting-started/concepts' },
          ],
        },
        {
          label: 'Server',
          collapsed: true,
          items: [
            { label: 'Configuration', slug: 'server/configuration' },
            { label: 'Authentication', slug: 'server/authentication' },
            {
              label: 'OAuth Providers',
              collapsed: true,
              items: [
                { label: 'Overview', slug: 'server/oauth' },
                { label: 'Google', slug: 'server/oauth/google' },
                { label: 'GitHub', slug: 'server/oauth/github' },
                { label: 'Generic Providers', slug: 'server/oauth/generic' },
              ],
            },
            { label: 'Roles & Permissions', slug: 'server/roles' },
            { label: 'Sessions', slug: 'server/sessions' },
            { label: 'Password Management', slug: 'server/password-management' },
            { label: 'Email Verification', slug: 'server/email-verification' },
            { label: 'Magic Links', slug: 'server/magic-links' },
            { label: 'Email OTP', slug: 'server/otp' },
            { label: 'Events & Hooks', slug: 'server/events' },
            { label: 'Cookies & Bearer', slug: 'server/cookies-and-bearer' },
            { label: 'Database Setup', slug: 'server/database' },
            { label: 'Key Rotation', slug: 'server/key-rotation' },
            { label: 'Ban / Unban', slug: 'server/ban-users' },
            { label: 'Rate Limiting', slug: 'server/rate-limiting' },
            { label: 'User Management', slug: 'server/user-management' },
            { label: 'Cleanup', slug: 'server/cleanup' },
            { label: 'FastAPI Integration', slug: 'server/fastapi' },
          ],
        },
        {
          label: 'Service SDK',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'service' },
            { label: 'Configuration', slug: 'service/configuration' },
            { label: 'JWT Verification', slug: 'service/jwt-verification' },
            { label: 'Introspection', slug: 'service/introspection' },
            { label: 'FastAPI Integration', slug: 'service/fastapi' },
          ],
        },
        {
          label: 'Client SDK',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'client' },
            { label: 'Setup', slug: 'client/setup' },
            { label: 'Authentication', slug: 'client/authentication' },
            { label: 'Authenticated Fetch', slug: 'client/fetch' },
            { label: 'Auth State', slug: 'client/state' },
            { label: 'React', slug: 'client/react' },
            { label: 'Vue', slug: 'client/vue' },
            { label: 'Svelte', slug: 'client/svelte' },
            { label: 'Bearer Storage', slug: 'client/bearer-storage' },
          ],
        },
        {
          label: 'API Reference',
          collapsed: true,
          items: [
            { label: 'Server API', slug: 'reference/server-api' },
            { label: 'Server CLI & Helpers', slug: 'reference/server-cli' },
            { label: 'Server Config', slug: 'reference/server-config' },
            { label: 'Server Types', slug: 'reference/server-types' },
            { label: 'Server Events', slug: 'reference/server-events' },
            { label: 'Service API', slug: 'reference/service-api' },
            { label: 'Client API', slug: 'reference/client-api' },
          ],
        },
        {
          label: 'Recipes',
          collapsed: true,
          items: [
            { label: 'React SPA', slug: 'recipes/react-spa' },
            { label: 'React Native', slug: 'recipes/react-native' },
            { label: 'Multi-Service', slug: 'recipes/multi-service' },
          ],
        },
        { label: 'Changelog', slug: 'upgrading/changelog' },
        { label: 'Contributing', slug: 'contributing' },
      ],
    }),
  ],
  vite: {
    plugins: [tailwindcss()],
  },
});
