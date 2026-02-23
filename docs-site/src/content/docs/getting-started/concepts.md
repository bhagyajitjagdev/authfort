---
title: Concepts
description: Core concepts behind AuthFort's authentication system.
sidebar:
  order: 4
---

## Access Token

A short-lived JWT (default: 15 minutes) that contains the user's ID, email, roles, and token version. It's stateless — the server doesn't need a database lookup to verify it. Microservices can verify it using only the public key from the JWKS endpoint.

## Refresh Token

A long-lived opaque token (default: 30 days) stored as a hash in the database. When the access token expires, the client sends the refresh token to get a new access token. Refresh tokens are single-use — each refresh issues a new pair, and the old refresh token is revoked. If a revoked refresh token is reused (indicating possible theft), the entire token family is revoked.

## Token Version

An integer on the user record that's embedded in every access token. When you ban a user, change their password, or modify their roles with `immediate=True`, the token version is bumped. Any access token with an older version is rejected, even if it hasn't expired yet.

## JWKS (JSON Web Key Set)

The `/.well-known/jwks.json` endpoint publishes the server's public RSA keys. Microservices fetch these keys to verify JWTs locally without contacting the auth server on every request. Keys are cached and refreshed automatically.

## Key Rotation

AuthFort doesn't rotate keys automatically — you trigger rotation manually or via a scheduled task. During rotation, both old and new keys are published in JWKS so tokens signed with the old key remain valid until they expire. See the [Key Rotation](/authfort/server/key-rotation/) guide for details.

## Sessions

Each login creates a session backed by a refresh token. When a token is refreshed, the old refresh token is revoked and replaced by a new one — the session continues as a chain of linked tokens rather than creating a new session. Sessions track metadata like IP address, user agent, and creation time. Users can list their active sessions, revoke individual sessions, or revoke all sessions (with an option to keep the current one).

## Introspection

An optional endpoint (`/introspect`) that checks a token's validity in real-time against the database. Unlike JWKS verification (which only checks the signature and expiry), introspection checks ban status, token version, and session validity. Use it when you need immediate revocation checks at the cost of a network call.

## Providers

Authentication methods. AuthFort ships with email/password (default) and OAuth providers (Google, GitHub built-in — plus any provider via `GenericOAuthProvider` / `GenericOIDCProvider`). Providers handle the full OAuth 2.1 + PKCE flow. Multiple providers can be linked to the same user account via email matching.

## Cookie Mode vs Bearer Mode

In **cookie mode**, tokens are delivered as HttpOnly cookies. The browser handles them automatically — no JavaScript touches the tokens. Best for web applications.

In **bearer mode**, the access token is returned in the response body and sent via the `Authorization: Bearer` header. The client SDK manages token storage. Best for mobile apps or when cookies aren't available.
