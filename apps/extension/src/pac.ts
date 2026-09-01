import type { SessionApp } from './types.js';

/**
 * Build the PAC script installed via chrome.proxy.
 *
 * Only protected hostnames are steered to the POP; everything else returns
 * DIRECT. This is a ZTNA client, not a full-tunnel VPN — the user's ordinary
 * browsing never touches our infrastructure.
 *
 * The host list comes from the POP and is already filtered to what this
 * identity may reach, so an unauthorized user's PAC never even names an app
 * they cannot access.
 */
export function buildPacScript(
  apps: SessionApp[],
  proxy: { host: string; port: number },
): string {
  const exact: string[] = [];
  const suffixes: string[] = [];

  for (const app of apps) {
    for (const host of app.hosts) {
      if (host.startsWith('*.')) suffixes.push(host.slice(1).toLowerCase());
      else exact.push(host.toLowerCase());
    }
  }

  const proxyDirective = `HTTPS ${proxy.host}:${proxy.port}`;

  return `function FindProxyForURL(url, host) {
  var h = host.toLowerCase();
  var exact = ${JSON.stringify(exact)};
  var suffixes = ${JSON.stringify(suffixes)};

  for (var i = 0; i < exact.length; i++) {
    if (h === exact[i]) return ${JSON.stringify(proxyDirective)};
  }
  for (var j = 0; j < suffixes.length; j++) {
    var s = suffixes[j];
    if (h.length > s.length && h.slice(h.length - s.length) === s) {
      var label = h.slice(0, h.length - s.length);
      if (label.indexOf('.') === -1) return ${JSON.stringify(proxyDirective)};
    }
  }
  return "DIRECT";
}`;
}

export async function applyPac(
  apps: SessionApp[],
  proxy: { host: string; port: number },
): Promise<void> {
  await chrome.proxy.settings.set({
    scope: 'regular',
    value: {
      mode: 'pac_script',
      pacScript: { data: buildPacScript(apps, proxy), mandatory: false },
    },
  });
}

/** Restore normal browsing. Called on sign-out and on any fatal error. */
export async function clearPac(): Promise<void> {
  await chrome.proxy.settings.clear({ scope: 'regular' });
}
