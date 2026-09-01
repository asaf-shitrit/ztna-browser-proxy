import type { ExtensionConfig } from './config.js';

/**
 * OIDC authorization-code flow with PKCE.
 *
 * PKCE (not implicit, not a client secret) because a browser extension is a
 * public client: anything shipped in the bundle is readable by anyone who
 * installs it, so there is no secret to protect.
 */

export interface Tokens {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
}

export async function signIn(config: ExtensionConfig): Promise<Tokens> {
  const verifier = randomString(64);
  const challenge = await s256(verifier);
  const state = randomString(24);
  const redirectUri = chrome.identity.getRedirectURL('oidc');

  const authUrl = new URL(`${trimSlash(config.oidcIssuer)}/protocol/openid-connect/auth`);
  authUrl.searchParams.set('client_id', config.oidcClientId);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', 'openid profile email');
  authUrl.searchParams.set('code_challenge', challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('state', state);

  const redirected = await chrome.identity.launchWebAuthFlow({
    url: authUrl.toString(),
    interactive: true,
  });
  if (!redirected) throw new Error('sign-in was cancelled');

  const returned = new URL(redirected);
  const error = returned.searchParams.get('error');
  if (error) throw new Error(`identity provider returned: ${error}`);

  // Reject a mismatched state: this is the CSRF guard for the callback.
  if (returned.searchParams.get('state') !== state) {
    throw new Error('state mismatch on OIDC callback');
  }

  const code = returned.searchParams.get('code');
  if (!code) throw new Error('no authorization code in callback');

  return exchange(config, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
  });
}

/**
 * End the session at the IdP, not just locally.
 *
 * Clearing our own tokens is not signing out. Keycloak's SSO cookie lives in
 * the auth-flow context and survives, so the next `launchWebAuthFlow` completes
 * non-interactively — verified: after a local-only sign-out, clicking Sign in
 * reconnected with no auth window and no password at all. On a shared machine
 * that hands the next person the previous user's access to their private apps.
 *
 * This is the back-channel form (POST with the refresh token): it ends the SSO
 * session and revokes the refresh token without needing a browser redirect, so
 * sign-out stays a single click.
 */
export async function logout(
  config: ExtensionConfig,
  refreshToken: string,
): Promise<void> {
  const body = new URLSearchParams({
    client_id: config.oidcClientId,
    refresh_token: refreshToken,
  });

  const res = await fetch(`${trimSlash(config.oidcIssuer)}/protocol/openid-connect/logout`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  // 204 is the success case; Keycloak also returns 200 in some versions.
  if (!res.ok && res.status !== 204) {
    throw new Error(`logout endpoint returned ${res.status}`);
  }
}

export async function refresh(config: ExtensionConfig, refreshToken: string): Promise<Tokens> {
  return exchange(config, {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
  });
}

async function exchange(
  config: ExtensionConfig,
  params: Record<string, string>,
): Promise<Tokens> {
  const body = new URLSearchParams({ client_id: config.oidcClientId, ...params });

  const res = await fetch(`${trimSlash(config.oidcIssuer)}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!res.ok) {
    throw new Error(`token endpoint returned ${res.status}: ${await res.text()}`);
  }

  const json = (await res.json()) as {
    access_token: string;
    refresh_token?: string;
    expires_in: number;
  };

  return {
    accessToken: json.access_token,
    refreshToken: json.refresh_token,
    expiresAt: Date.now() + json.expires_in * 1000,
  };
}

function randomString(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return base64url(buf);
}

async function s256(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return base64url(new Uint8Array(digest));
}

function base64url(bytes: Uint8Array): string {
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function trimSlash(s: string): string {
  return s.replace(/\/$/, '');
}
