#!/usr/bin/env node
/**
 * Drive the real extension in a real Chrome over the DevTools Protocol.
 *
 * Exercises what no unit test can: chrome.identity PKCE against Keycloak,
 * chrome.proxy installing the PAC, and onAuthRequired answering the POP's 407.
 *
 * Uses a throwaway profile and Node's built-in WebSocket — no dependencies.
 */
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

/**
 * Chrome for Testing, not the installed Chrome.
 *
 * Chrome 137 disabled the --load-extension switch and 152 removed the
 * DisableLoadExtensionCommandLineSwitch escape hatch, so regular Chrome
 * silently ignores the flag — the extension simply never loads and the only
 * service workers present are Chrome's own component extensions.
 * Run scripts/fetch-chrome-for-testing.sh to install it.
 */
const ARCH = process.arch === 'x64' ? 'mac-x64' : 'mac-arm64';
const CHROME = path.resolve(
  `.cache/chrome-${ARCH}/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing`,
);
const PORT = 9333;
const EXT = path.resolve('apps/extension/dist');
const HEADLESS = process.env.HEADLESS === '1';

/**
 * Compute the extension id up front. This matters twice over: Chrome ships
 * component extensions (Google Hangouts, Contextual Tasks) whose service
 * workers are also named background.js, so matching by filename picks the
 * wrong one; and the OIDC redirect URI is derived from this id.
 *
 * With a `key` in the manifest the id is the digest of that public key and is
 * stable everywhere; without one it is the digest of the install path.
 */
function extensionId(dir) {
  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const material = manifest.key
    ? Buffer.from(manifest.key, 'base64')
    : Buffer.from(dir, 'utf8');
  const hash = createHash('sha256').update(material).digest();
  let id = '';
  for (let i = 0; i < 16; i += 1) {
    id += String.fromCharCode(97 + (hash[i] >> 4));
    id += String.fromCharCode(97 + (hash[i] & 0x0f));
  }
  return id;
}

const EXT_ID = extensionId(EXT);
const profile = mkdtempSync(path.join(tmpdir(), 'ztna-chrome-'));
const results = [];
let chrome;

const ok = (name, detail = '') => {
  results.push([true, name, detail]);
  console.log(`  \x1b[32m✓\x1b[0m ${name}${detail ? '  ' + detail : ''}`);
};
const bad = (name, detail = '') => {
  results.push([false, name, detail]);
  console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? '  ' + detail : ''}`);
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function targets() {
  const res = await fetch(`http://127.0.0.1:${PORT}/json/list`);
  return res.json();
}

async function waitFor(fn, { timeout = 30000, interval = 300, what = 'condition' } = {}) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await fn();
    if (value) return value;
    await sleep(interval);
  }
  throw new Error(`timed out waiting for ${what}`);
}

/** Minimal CDP session over a target's WebSocket debugger URL. */
class Session {
  #ws;
  #id = 0;
  #pending = new Map();

  static async attach(wsUrl) {
    const s = new Session();
    s.#ws = new WebSocket(wsUrl);
    s.#ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      const p = s.#pending.get(msg.id);
      if (p) {
        s.#pending.delete(msg.id);
        msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
      }
    });
    await new Promise((resolve, reject) => {
      s.#ws.addEventListener('open', resolve, { once: true });
      s.#ws.addEventListener('error', () => reject(new Error('ws error')), { once: true });
    });
    return s;
  }

  send(method, params = {}) {
    const id = ++this.#id;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#ws.send(JSON.stringify({ id, method, params }));
      setTimeout(() => {
        if (this.#pending.delete(id)) reject(new Error(`${method} timed out`));
      }, 45000);
    });
  }

  /** Surface page console output and errors, which are otherwise invisible. */
  onConsole(handler) {
    this.#ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.method === 'Runtime.consoleAPICalled') {
        handler(msg.params.args.map((a) => a.value ?? a.description ?? '').join(' '));
      } else if (msg.method === 'Runtime.exceptionThrown') {
        handler('EXCEPTION ' + (msg.params.exceptionDetails?.exception?.description ?? ''));
      } else if (msg.method === 'Log.entryAdded') {
        handler(`${msg.params.entry.level.toUpperCase()} ${msg.params.entry.text}`);
      }
    });
  }

  /** Evaluate an async expression and return its awaited value. */
  async eval(expression) {
    const r = await this.send('Runtime.evaluate', {
      expression,
      awaitPromise: true,
      returnByValue: true,
      userGesture: true,
    });
    if (r.exceptionDetails) {
      throw new Error(r.exceptionDetails.exception?.description ?? 'eval failed');
    }
    return r.result.value;
  }

  close() {
    try { this.#ws.close(); } catch { /* already gone */ }
  }
}

async function main() {
  console.log('\nZTNA extension — real browser test');
  console.log('═'.repeat(72));

  const args = [
    `--user-data-dir=${profile}`,
    `--remote-debugging-port=${PORT}`,
    `--load-extension=${EXT}`,
    `--disable-extensions-except=${EXT}`,
    // Our demo CA is not in the system keychain; Chrome will not use an
    // untrusted HTTPS proxy otherwise.
    '--ignore-certificate-errors',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-features=DialMediaRouteProvider',
    'about:blank',
  ];
  if (HEADLESS) args.unshift('--headless=new');

  chrome = spawn(CHROME, args, { stdio: 'ignore', detached: false });

  await waitFor(async () => {
    try { return (await targets()).length >= 0; } catch { return false; }
  }, { what: 'chrome devtools', timeout: 20000 });
  ok('Chrome launched with the unpacked extension');

  // The service worker target tells us the generated extension id.
  await waitFor(
    async () =>
      (await targets()).find(
        (t) => t.type === 'service_worker' && t.url.startsWith(`chrome-extension://${EXT_ID}/`),
      ),
    { what: 'ZTNA service worker' },
  );
  const extId = EXT_ID;
  ok('MV3 service worker registered', extId);

  // Drive the real popup UI rather than poking the worker directly.
  await fetch(`http://127.0.0.1:${PORT}/json/new?${encodeURIComponent(`chrome-extension://${extId}/popup.html`)}`, { method: 'PUT' });
  const popupTarget = await waitFor(
    async () => (await targets()).find((t) => t.url.includes('popup.html')),
    { what: 'popup page' },
  );
  const popup = await Session.attach(popupTarget.webSocketDebuggerUrl);
  popup.onConsole((text) => console.log(`      [popup] ${text}`));
  await popup.send('Runtime.enable');
  await popup.send('Log.enable');
  await sleep(1200);

  const initial = await popup.eval(`document.querySelector('.status')?.textContent ?? ''`);
  initial.includes('Disconnected')
    ? ok('Popup renders disconnected state', JSON.stringify(initial))
    : bad('Popup renders disconnected state', JSON.stringify(initial));

  // Click "Sign in" — this triggers chrome.identity.launchWebAuthFlow.
  await popup.eval(`
    (async () => {
      const btn = [...document.querySelectorAll('footer button')].find(b => /sign in/i.test(b.textContent));
      btn.click();
      return true;
    })()
  `);
  ok('Clicked Sign in (launchWebAuthFlow)');

  // Keycloak login opens in its own window.
  const kcTarget = await waitFor(
    async () => (await targets()).find((t) => t.url.includes('localhost:8080') && t.type === 'page'),
    { what: 'Keycloak login window', timeout: 25000 },
  );
  ok('Keycloak authorization page opened');

  const kc = await Session.attach(kcTarget.webSocketDebuggerUrl);
  await kc.send('Runtime.enable');
  await waitFor(async () => {
    try { return await kc.eval(`!!document.querySelector('#username')`); } catch { return false; }
  }, { what: 'Keycloak login form' });

  await kc.eval(`
    (() => {
      document.querySelector('#username').value = 'alice';
      document.querySelector('#password').value = 'alice';
      document.querySelector('#kc-form-login').submit();
      return true;
    })()
  `);
  ok('Submitted credentials as alice');
  kc.close();

  // Back in the popup: the service worker should complete the flow.
  const connected = await waitFor(async () => {
    try {
      const text = await popup.eval(`document.querySelector('.status')?.textContent ?? ''`);
      return text.includes('Connected') ? text : false;
    } catch { return false; }
  }, { what: 'popup to report connected', timeout: 40000 });
  ok('Popup reports connected', JSON.stringify(connected));

  const identity = await popup.eval(`document.querySelector('.identity')?.textContent ?? ''`);
  identity.toLowerCase().includes('alice')
    ? ok('Popup shows the signed-in identity', JSON.stringify(identity))
    : bad('Popup shows the signed-in identity', JSON.stringify(identity));

  const apps = await popup.eval(`[...document.querySelectorAll('.app-id')].map(e => e.textContent).join(',')`);
  apps.includes('wiki') && !apps.includes('payroll')
    ? ok('Popup lists only permitted apps', JSON.stringify(apps))
    : bad('Popup lists only permitted apps', JSON.stringify(apps));

  // The PAC must actually be installed in Chrome's proxy settings.
  const pac = await popup.eval(`
    new Promise(r => chrome.proxy.settings.get({}, c =>
      r(JSON.stringify({ mode: c.value?.mode, pac: c.value?.pacScript?.data?.slice(0, 200) }))))
  `);
  const pacObj = JSON.parse(pac);
  pacObj.mode === 'pac_script' && String(pacObj.pac).includes('wiki.internal')
    ? ok('PAC script installed via chrome.proxy', pacObj.mode)
    : bad('PAC script installed via chrome.proxy', pac);

  // --- The real test: browse to a private app through the tunnel ----------
  const visit = async (url) => {
    const res = await fetch(`http://127.0.0.1:${PORT}/json/new?${encodeURIComponent(url)}`, { method: 'PUT' });
    const t = await res.json();
    const s = await Session.attach(t.webSocketDebuggerUrl);
    await s.send('Runtime.enable');
    await sleep(3500);
    const body = await s.eval(`document.body ? document.body.innerText.slice(0, 400) : ''`);
    const title = await s.eval(`document.title`);
    s.close();
    await fetch(`http://127.0.0.1:${PORT}/json/close/${t.id}`);
    return { title, body };
  };

  const wiki = await visit('https://wiki.internal/');
  wiki.body.includes('PRIVATE NETWORK') || wiki.title.includes('Corporate Wiki')
    ? ok('Loaded https://wiki.internal through the tunnel', JSON.stringify(wiki.title))
    : bad('Loaded https://wiki.internal through the tunnel', JSON.stringify({ ...wiki, body: wiki.body.slice(0, 150) }));

  const payroll = await visit('https://payroll.internal/');
  !payroll.body.includes('PRIVATE NETWORK')
    ? ok('Denied https://payroll.internal (not in alice\'s policy)', JSON.stringify(payroll.title))
    : bad('Denied https://payroll.internal (not in alice\'s policy)', 'page loaded but should not have');

  const external = await visit('https://example.com/');
  external.body.length > 0
    ? ok('Ordinary browsing still works (DIRECT, not tunnelled)', JSON.stringify(external.title))
    : bad('Ordinary browsing still works (DIRECT, not tunnelled)', 'no content');

  // Sign out must clear the PAC.
  await popup.eval(`
    (async () => {
      const btn = [...document.querySelectorAll('footer button')].find(b => /sign out/i.test(b.textContent));
      btn.click();
      return true;
    })()
  `);
  await sleep(3000);
  const pacAfter = await popup.eval(`
    new Promise(r => chrome.proxy.settings.get({}, c => r(c.value?.mode ?? 'unset')))
  `);
  pacAfter !== 'pac_script'
    ? ok('Sign out reverted the proxy to DIRECT', String(pacAfter))
    : bad('Sign out reverted the proxy to DIRECT', String(pacAfter));

  // --- sign-out must end the IdP session, not just the local one ----------
  //
  // Regression guard: with local-only sign-out, this second sign-in completed
  // with no auth window and no password, handing the next person at this
  // browser the previous user's access.
  await popup.eval(`
    (async () => {
      const btn = [...document.querySelectorAll('footer button')].find(b => /sign in/i.test(b.textContent));
      btn.click();
      return true;
    })()
  `);

  let reprompted = false;
  try {
    const kc2 = await waitFor(
      async () => (await targets()).find((t) => t.url.includes('localhost:8080') && t.type === 'page'),
      { what: 'Keycloak re-prompt', timeout: 20000 },
    );
    const kcSession = await Session.attach(kc2.webSocketDebuggerUrl);
    await kcSession.send('Runtime.enable');
    reprompted = await waitFor(async () => {
      try { return await kcSession.eval(`!!document.querySelector('#username')`); } catch { return false; }
    }, { what: 'login form', timeout: 15000 }).then(() => true).catch(() => false);
    kcSession.close();
  } catch {
    reprompted = false;
  }

  reprompted
    ? ok('Sign out ends the IdP session (re-login is prompted)')
    : bad('Sign out ends the IdP session (re-login is prompted)', 'silent SSO re-login');

  popup.close();

  console.log('═'.repeat(72));
  const passed = results.filter(([p]) => p).length;
  const failed = results.length - passed;
  console.log(`  ${passed} passed, ${failed} failed\n`);
  return failed === 0 ? 0 : 1;
}

let code = 1;
try {
  code = await main();
} catch (err) {
  console.error(`\n  \x1b[31mFATAL\x1b[0m ${err.message}\n`);
  try {
    writeFileSync('/tmp/ztna-targets.json', JSON.stringify(await targets(), null, 2));
    console.error('  target dump: /tmp/ztna-targets.json');
  } catch { /* chrome gone */ }
} finally {
  if (chrome) chrome.kill('SIGKILL');
  await sleep(500);
  rmSync(profile, { recursive: true, force: true });
}
process.exit(code);
