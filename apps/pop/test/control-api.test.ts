import { describe, it, expect } from 'vitest';
import { canReadAudit, allowedOrigin, jwksUrl } from '../src/control-api.js';
import type { PopConfig } from '../src/config.js';
import type { Identity } from '@ztna/policy';

const alice: Identity = { sub: 'u-alice', email: 'a@x', groups: ['employees'] };
const admin: Identity = { sub: 'u-admin', email: 'b@x', groups: ['employees', 'ztna-admins'] };

/**
 * The audit trail records who reached which internal host. Leaking it hands an
 * attacker a map of the private estate plus the identities that can reach it,
 * so access is opt-in and group-gated.
 */
describe('canReadAudit', () => {
  it('denies everyone when no groups are configured', () => {
    expect(canReadAudit(admin, [])).toBe(false);
    expect(canReadAudit(alice, [])).toBe(false);
  });

  it('denies an ordinary authenticated user', () => {
    expect(canReadAudit(alice, ['ztna-admins'])).toBe(false);
  });

  it('allows a member of a configured group', () => {
    expect(canReadAudit(admin, ['ztna-admins'])).toBe(true);
  });

  it('denies an identity with no groups at all', () => {
    expect(canReadAudit({ sub: 'x', groups: [] }, ['ztna-admins'])).toBe(false);
  });
});

/**
 * A wildcard CORS origin would let any page the user visits read this API
 * cross-origin — including, before this was fixed, the whole audit log.
 */
describe('allowedOrigin', () => {
  it('allows the extension origin', () => {
    expect(allowedOrigin('chrome-extension://abcdef')).toBe('chrome-extension://abcdef');
  });

  it('refuses ordinary web origins', () => {
    expect(allowedOrigin('https://evil.example.com')).toBeNull();
    expect(allowedOrigin('http://localhost:3000')).toBeNull();
  });

  it('refuses a missing origin rather than defaulting to a wildcard', () => {
    expect(allowedOrigin(undefined)).toBeNull();
    expect(allowedOrigin('')).toBeNull();
  });

  it('does not match an origin that merely contains the scheme', () => {
    expect(allowedOrigin('https://evil.com/chrome-extension://x')).toBeNull();
  });
});

const base = {
  oidcIssuer: 'http://localhost:8080/realms/ztna',
  oidcAudience: 'ztna-extension',
} as unknown as PopConfig;

describe('jwksUrl', () => {
  it('derives from the issuer when no override is set', () => {
    expect(jwksUrl(base)).toBe('http://localhost:8080/realms/ztna/protocol/openid-connect/certs');
  });

  it('tolerates a trailing slash on the issuer', () => {
    expect(jwksUrl({ ...base, oidcIssuer: 'http://localhost:8080/realms/ztna/' })).toBe(
      'http://localhost:8080/realms/ztna/protocol/openid-connect/certs',
    );
  });

  it('uses the override so keys come from an internal name', () => {
    const config = {
      ...base,
      oidcJwksUrl: 'http://keycloak:8080/realms/ztna/protocol/openid-connect/certs',
    } as PopConfig;
    expect(config.oidcIssuer).toBe('http://localhost:8080/realms/ztna');
    expect(jwksUrl(config)).toBe('http://keycloak:8080/realms/ztna/protocol/openid-connect/certs');
  });
});

import { auditScope, visibleAuditRecords } from '../src/control-api.js';

/**
 * Full audit access maps the estate, so it stays group-gated. Reading your own
 * records reveals nothing you did not already do, so every authenticated user
 * gets that — which makes the log a transparency feature rather than a thing
 * only admins can see.
 */
describe('auditScope', () => {
  it('grants full access to a configured group', () => {
    expect(auditScope(admin, ['ztna-admins'])).toBe('all');
  });

  it('grants only self access to an ordinary user', () => {
    expect(auditScope(alice, ['ztna-admins'])).toBe('self');
  });

  it('grants only self access when no groups are configured', () => {
    expect(auditScope(admin, [])).toBe('self');
  });
});

describe('visibleAuditRecords', () => {
  const records = [
    { sub: 'u-alice', host: 'wiki.internal' },
    { sub: 'u-bob', host: 'payroll.internal' },
    { sub: undefined, host: 'wiki.internal' },
  ];

  it('returns everything for full scope', () => {
    expect(visibleAuditRecords(admin, 'all', records)).toHaveLength(3);
  });

  it('returns only the caller\'s own records for self scope', () => {
    const seen = visibleAuditRecords(alice, 'self', records);
    expect(seen).toEqual([{ sub: 'u-alice', host: 'wiki.internal' }]);
  });

  it('never leaks another identity through self scope', () => {
    const seen = visibleAuditRecords(alice, 'self', records);
    expect(seen.some((r) => r.sub === 'u-bob')).toBe(false);
    // Unauthenticated denials have no subject and must not fall through.
    expect(seen.some((r) => r.sub === undefined)).toBe(false);
  });

  it('returns nothing for none scope', () => {
    expect(visibleAuditRecords(alice, 'none', records)).toEqual([]);
  });
});
