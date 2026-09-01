import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import type { ExtensionState, Message } from './types.js';
import './popup.css';

function send(message: Message): Promise<ExtensionState> {
  return chrome.runtime.sendMessage(message) as Promise<ExtensionState>;
}

function App(): JSX.Element {
  const [state, setState] = useState<ExtensionState | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void send({ type: 'GET_STATE' }).then(setState);
  }, []);

  const act = async (type: 'SIGN_IN' | 'SIGN_OUT'): Promise<void> => {
    setBusy(true);
    try {
      setState(await send({ type }));
    } finally {
      setBusy(false);
    }
  };

  if (!state) return <div className="panel loading">Loading…</div>;

  const connected = state.status === 'connected';

  return (
    <div className="panel">
      <header>
        <span className={`dot ${state.status}`} aria-hidden="true" />
        <div>
          <h1>ZTNA Access</h1>
          <p className="status">{label(state)}</p>
        </div>
      </header>

      {state.identity && (
        <p className="identity">
          {state.identity.name ?? state.identity.email ?? state.identity.sub}
          {state.identity.groups.length > 0 && (
            <span className="groups">{state.identity.groups.join(' · ')}</span>
          )}
        </p>
      )}

      {state.error && <p className="error">{state.error}</p>}

      {connected && (
        <section>
          <h2>Available applications</h2>
          {state.apps.length === 0 ? (
            <p className="empty">No applications are assigned to you.</p>
          ) : (
            <ul>
              {state.apps.map((app) => (
                <li key={app.id}>
                  <button
                    type="button"
                    onClick={() => {
                      const host = app.hosts[0];
                      if (host) void chrome.tabs.create({ url: `https://${host}` });
                    }}
                  >
                    <span className="app-id">{app.id}</span>
                    <span className="app-host">{app.hosts.join(', ')}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      <footer>
        <button
          type="button"
          className={connected ? 'secondary' : 'primary'}
          disabled={busy}
          onClick={() => void act(connected ? 'SIGN_OUT' : 'SIGN_IN')}
        >
          {busy ? 'Working…' : connected ? 'Sign out' : 'Sign in'}
        </button>
      </footer>
    </div>
  );
}

function label(state: ExtensionState): string {
  switch (state.status) {
    case 'connected':
      return 'Connected — private apps are reachable';
    case 'connecting':
      return 'Connecting…';
    case 'error':
      return 'Something went wrong';
    default:
      return 'Disconnected — sign in to reach private apps';
  }
}

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
