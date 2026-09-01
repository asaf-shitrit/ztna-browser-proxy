import { describe, it, expect } from 'vitest';
import { findApp, isInCatalog } from '../src/handlers.js';
import type { CatalogApp } from '@ztna/tunnel';

/**
 * The connector's own guard. Policy lives in the POP, but the connector still
 * refuses anything it did not itself advertise — so a compromised POP cannot
 * use it to pivot around the private network.
 */

const apps: CatalogApp[] = [
  { id: 'wiki', hosts: ['wiki.internal'], ports: [80, 443] },
  {
    id: 'payroll',
    hosts: ['payroll.internal'],
    ports: [443],
    dial: { host: '127.0.0.1', port: 9444 },
  },
];

describe('connector catalog enforcement', () => {
  it('accepts a declared host and port', () => {
    expect(isInCatalog(apps, { host: 'wiki.internal', port: 443 })).toBe(true);
    expect(isInCatalog(apps, { host: 'wiki.internal', port: 80 })).toBe(true);
  });

  it('refuses an undeclared host', () => {
    expect(isInCatalog(apps, { host: 'secrets.internal', port: 443 })).toBe(false);
  });

  it('refuses a declared host on an undeclared port', () => {
    // The classic pivot: a legitimate host, but SSH instead of HTTPS.
    expect(isInCatalog(apps, { host: 'payroll.internal', port: 22 })).toBe(false);
  });

  it('refuses raw addresses that were never advertised', () => {
    expect(isInCatalog(apps, { host: '10.0.0.5', port: 443 })).toBe(false);
    expect(isInCatalog(apps, { host: '169.254.169.254', port: 80 })).toBe(false);
  });

  it('is case-insensitive on hostnames', () => {
    expect(isInCatalog(apps, { host: 'WIKI.Internal', port: 443 })).toBe(true);
  });

  it('exposes the dial override only for the app that declared it', () => {
    expect(findApp(apps, { host: 'payroll.internal', port: 443 })?.dial).toEqual({
      host: '127.0.0.1',
      port: 9444,
    });
    // wiki declared no override, so it is dialled by its own hostname.
    expect(findApp(apps, { host: 'wiki.internal', port: 443 })?.dial).toBeUndefined();
  });

  it('does not let a dial override widen what is reachable', () => {
    // The override changes where an ALLOWED target is dialled; it never makes
    // an undeclared target reachable.
    expect(findApp(apps, { host: '127.0.0.1', port: 9444 })).toBeUndefined();
  });
});
