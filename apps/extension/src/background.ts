import { getConfig } from './config.js';
import {
  signIn as oidcSignIn,
  refresh as oidcRefresh,
  logout as oidcLogout,
  type Tokens,
} from './oidc.js';
import { applyPac, clearPac } from './pac.js';
import { isOurProxy } from './proxy-auth.js';
import { nextRefreshAt } from './refresh.js';
import { hasHostAccess } from './permissions.js';
import type { ExtensionState, Message, PopSession } from './types.js';

/**
 * MV3 service worker. It can be evicted at any time, so all durable state lives
 * in chrome.storage rather than module scope, and every entry point reloads it.
 *
 * Tokens go in `storage.session` (memory-backed, cleared when the browser
 * closes, never written to disk); only non-sensitive UI state goes in `local`.
 */

const REFRESH_ALARM = 'ztna-refresh';

interface Stored {
  tokens?: Tokens;
  session?: PopSession;
}

async function load(): Promise<Stored> {
  return (await chrome.storage.session.get(['tokens', 'session']));
}

async function save(patch: Stored): Promise<void> {
  await chrome.storage.session.set(patch);
}

async function clear(): Promise<void> {
  await chrome.storage.session.remove(['tokens', 'session']);
}

// ---------------------------------------------------------------- sign in

async function connect(): Promise<ExtensionState> {
  // Without host access the 407 challenge cannot be answered, so every
  // protected request would hang. Fail with a clear message instead.
  if (!(await hasHostAccess())) {
    throw new Error('Access to sites is required to route traffic to your apps.');
  }

  const config = await getConfig();
  await setStatus('connecting');

  const tokens = await oidcSignIn(config);
  await save({ tokens });

  const session = await fetchSession(tokens.accessToken);
  await save({ session });

  await applyPac(session.apps, session.proxy);
  await scheduleRefresh(tokens, session);

  return await setStatus('connected', { identity: session.identity, apps: session.apps, expiresAt: session.expiresAt });
}

async function fetchSession(accessToken: string): Promise<PopSession> {
  const config = await getConfig();

  const res = await fetch(`${config.popApiBase}/api/session`, {
    method: 'POST',
    headers: { authorization: `Bearer ${accessToken}` },
  });

  if (!res.ok) {
    throw new Error(`POP rejected the session request (${res.status})`);
  }
  return (await res.json()) as PopSession;
}

async function disconnect(): Promise<ExtensionState> {
  const { tokens } = await load();
  const config = await getConfig();

  // Revoke server-side first. Chrome caches proxy credentials for the browser
  // session and gives us no way to evict them, so sign-out MUST be enforced at
  // the POP — clearing local state alone would leave a usable credential.
  if (tokens?.accessToken) {
    try {
      await fetch(`${config.popApiBase}/api/session`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${tokens.accessToken}` },
      });
    } catch {
      // Best effort: the session still expires server-side on its own TTL.
    }
  }

  // Then end the IdP session. Without this the SSO cookie survives and the
  // next sign-in completes silently as the same user — see logout().
  if (tokens?.refreshToken) {
    try {
      await oidcLogout(config, tokens.refreshToken);
    } catch (err) {
      // Do not block sign-out on it: local state and the POP session are
      // already gone, which is the part that governs access.
      console.warn('ztna: IdP logout failed', err);
    }
  }

  await chrome.alarms.clear(REFRESH_ALARM);
  await clearPac();
  await clear();

  return await setStatus('disconnected', { apps: [] });
}

// ---------------------------------------------------------------- refresh

async function scheduleRefresh(tokens: Tokens, session: PopSession): Promise<void> {
  await chrome.alarms.create(REFRESH_ALARM, {
    when: nextRefreshAt(tokens.expiresAt, session.expiresAt),
  });
}

async function doRefresh(): Promise<void> {
  const { tokens } = await load();
  const config = await getConfig();

  if (!tokens?.refreshToken) {
    await setStatus('disconnected', { apps: [], error: 'session expired, sign in again' });
    await clearPac();
    return;
  }

  try {
    const next = await oidcRefresh(config, tokens.refreshToken);
    await save({ tokens: next });

    const session = await fetchSession(next.accessToken);
    await save({ session });

    // The app list can change between refreshes as group membership changes,
    // so the PAC is rebuilt every time rather than assumed stable.
    await applyPac(session.apps, session.proxy);
    await scheduleRefresh(next, session);
    await setStatus('connected', {
      identity: session.identity,
      apps: session.apps,
      expiresAt: session.expiresAt,
    });
  } catch (err) {
    await clearPac();
    await clear();
    await setStatus('error', {
      apps: [],
      error: err instanceof Error ? err.message : String(err),
    });
  }
}

// ---------------------------------------------------------------- proxy auth

/**
 * Answer the POP's 407 challenge.
 *
 * `asyncBlocking` on onAuthRequired is why the manifest needs the
 * `webRequestAuthProvider` permission — MV3 removed blocking webRequest in
 * general but kept this specific capability for credential providers.
 */
chrome.webRequest.onAuthRequired.addListener(
  (details, callback) => {
    if (!callback) return;

    // Only answer the *proxy's* challenge. A site's own 401 is none of our
    // business, and answering it would leak the proxy secret to that site.
    if (!details.isProxy) {
      callback({});
      return;
    }

    void load().then(({ session }) => {
      if (!session) {
        callback({});
        return;
      }

      // ...and only answer OUR proxy. `isProxy` alone says a proxy asked, not
      // which one: another extension's PAC, a system proxy, or a network
      // attacker able to force a 407 would otherwise be handed the secret
      // that authorizes access to every app this user can reach.
      if (!isOurProxy(details.challenger, session)) {
        console.warn('ztna: refusing proxy auth challenge from', details.challenger);
        callback({});
        return;
      }

      callback({
        authCredentials: {
          username: session.proxyUser,
          password: session.proxySecret,
        },
      });
    });
  },
  { urls: ['<all_urls>'] },
  ['asyncBlocking'],
);

// ---------------------------------------------------------------- state/UI

async function setStatus(
  status: ExtensionState['status'],
  extra: Partial<ExtensionState> = {},
): Promise<ExtensionState> {
  const state: ExtensionState = { status, apps: [], ...extra };
  await chrome.storage.local.set({ state });

  await chrome.action.setBadgeText({ text: status === 'connected' ? 'ON' : '' });
  await chrome.action.setBadgeBackgroundColor({ color: '#2f855a' });

  return state;
}

async function getState(): Promise<ExtensionState> {
  const stored = await chrome.storage.local.get('state');
  return (stored['state'] as ExtensionState | undefined) ?? { status: 'disconnected', apps: [] };
}

chrome.runtime.onMessage.addListener((message: Message, _sender, sendResponse) => {
  const run = async (): Promise<ExtensionState> => {
    switch (message.type) {
      case 'SIGN_IN':
        return await connect();
      case 'SIGN_OUT':
        return await disconnect();
      case 'GET_STATE':
        return await getState();
    }
  };

  run().then(sendResponse, async (err: unknown) => {
    const state = await setStatus('error', {
      apps: [],
      error: err instanceof Error ? err.message : String(err),
    });
    sendResponse(state);
  });

  return true; // keep the message channel open for the async response
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === REFRESH_ALARM) void doRefresh();
});

/**
 * A restarted browser (or an evicted worker) must not leave a PAC pointing at
 * a POP we have no credentials for — every request to a protected host would
 * hang on an unanswerable 407.
 */
chrome.runtime.onStartup.addListener(() => {
  void (async () => {
    const { session } = await load();
    if (!session) {
      await clearPac();
      await setStatus('disconnected', { apps: [] });
    }
  })();
});
