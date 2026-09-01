import { describe, it, expect } from 'vitest';
import { buildPacScript } from '../src/pac.js';
import type { SessionApp } from '../src/types.js';

/**
 * The PAC script decides which of the user's traffic leaves their machine via
 * the POP and which goes direct. A mistake here either breaks access to a
 * private app or silently routes unrelated browsing through our infrastructure,
 * so the generated script is executed and probed rather than string-matched.
 */

const PROXY = { host: 'pop.ztna.test', port: 8443 };
const EXPECTED = 'HTTPS pop.ztna.test:8443';

function pacFor(apps: SessionApp[]): (url: string, host: string) => string {
  const source = buildPacScript(apps, PROXY);
  // Executing the generated script IS the test. A PAC file is JavaScript the
  // browser will run, so string-matching it would assert the wrong thing —
  // these cases (lookalike suffixes, multi-label wildcards) are exactly where
  // a regex that merely *looks* right routes traffic wrongly.
  // eslint-disable-next-line @typescript-eslint/no-implied-eval, @typescript-eslint/no-unsafe-call
  return new Function(`${source}; return FindProxyForURL;`)() as (
    url: string,
    host: string,
  ) => string;
}

const apps: SessionApp[] = [
  { id: 'wiki', hosts: ['wiki.internal'], ports: [443] },
  { id: 'tools', hosts: ['*.tools.internal'], ports: [443] },
];

describe('buildPacScript', () => {
  const find = pacFor(apps);

  it('routes an exact protected host through the POP', () => {
    expect(find('https://wiki.internal/', 'wiki.internal')).toBe(EXPECTED);
  });

  it('is case-insensitive', () => {
    expect(find('https://WIKI.Internal/', 'WIKI.Internal')).toBe(EXPECTED);
  });

  it('routes a single-label wildcard match through the POP', () => {
    expect(find('https://ci.tools.internal/', 'ci.tools.internal')).toBe(EXPECTED);
  });

  it('does not route multi-label hosts under a wildcard', () => {
    expect(find('https://a.b.tools.internal/', 'a.b.tools.internal')).toBe('DIRECT');
  });

  it('sends ordinary browsing DIRECT — this is not a full-tunnel VPN', () => {
    expect(find('https://example.com/', 'example.com')).toBe('DIRECT');
    expect(find('https://mail.google.com/', 'mail.google.com')).toBe('DIRECT');
  });

  it('does not route a lookalike suffix through the POP', () => {
    expect(find('https://evil-wiki.internal/', 'evil-wiki.internal')).toBe('DIRECT');
    expect(find('https://wiki.internal.attacker.com/', 'wiki.internal.attacker.com'))
      .toBe('DIRECT');
    expect(find('https://tools.internal.attacker.com/', 'tools.internal.attacker.com'))
      .toBe('DIRECT');
  });

  it('routes everything DIRECT when the user has no apps', () => {
    const none = pacFor([]);
    expect(none('https://wiki.internal/', 'wiki.internal')).toBe('DIRECT');
    expect(none('https://example.com/', 'example.com')).toBe('DIRECT');
  });
});
