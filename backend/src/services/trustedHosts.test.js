import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { isTrustedPrivateHost } from './trustedHosts.js';
import { validateHostLiteral, validateHost, resolveForConnection } from './hostValidation.js';

vi.mock('dns', () => ({
  promises: {
    resolve4: vi.fn().mockResolvedValue([]),
    resolve6: vi.fn().mockResolvedValue([]),
    lookup: vi.fn().mockRejectedValue(Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' })),
  },
}));

const { promises: dns } = await import('dns');

beforeEach(() => {
  dns.resolve4.mockReset();
  dns.resolve6.mockReset();
  dns.resolve4.mockResolvedValue([]);
  dns.resolve6.mockResolvedValue([]);
  delete process.env.TRUSTED_PRIVATE_HOSTS;
  delete process.env.OIDC_ISSUER_URL;
});

afterEach(() => {
  delete process.env.TRUSTED_PRIVATE_HOSTS;
  delete process.env.OIDC_ISSUER_URL;
});

describe('isTrustedPrivateHost', () => {
  it('trusts nothing when TRUSTED_PRIVATE_HOSTS is unset or blank', () => {
    expect(isTrustedPrivateHost('sso.example.com')).toBe(false);
    process.env.TRUSTED_PRIVATE_HOSTS = ' , ';
    expect(isTrustedPrivateHost('')).toBe(false);
    expect(isTrustedPrivateHost('sso.example.com')).toBe(false);
  });

  it('matches the listed names exactly, whatever their case or trailing dot', () => {
    process.env.TRUSTED_PRIVATE_HOSTS = 'SSO.example.com, vllm  10.0.0.5';
    expect(isTrustedPrivateHost('sso.example.com')).toBe(true);
    expect(isTrustedPrivateHost('sso.example.com.')).toBe(true);
    expect(isTrustedPrivateHost('VLLM')).toBe(true);
    expect(isTrustedPrivateHost('10.0.0.5')).toBe(true);
    expect(isTrustedPrivateHost('evil.sso.example.com')).toBe(false);
    expect(isTrustedPrivateHost('example.com')).toBe(false);
    expect(isTrustedPrivateHost('10.0.0.6')).toBe(false);
  });

  it('trusts the host of the issuer the environment configures, and only that host', () => {
    process.env.OIDC_ISSUER_URL = 'https://SSO.example.com:8443/application/o/mailflow/';
    expect(isTrustedPrivateHost('sso.example.com')).toBe(true);
    expect(isTrustedPrivateHost('example.com')).toBe(false);
    process.env.OIDC_ISSUER_URL = 'not a url';
    expect(isTrustedPrivateHost('not a url')).toBe(false);
  });

  it('matches a bracketed IPv6 literal against its bare form', () => {
    process.env.TRUSTED_PRIVATE_HOSTS = '[fd00::5]';
    expect(isTrustedPrivateHost('fd00::5')).toBe(true);
    expect(isTrustedPrivateHost('[fd00::5]')).toBe(true);
  });
});

describe('host validation with trusted private hosts', () => {
  it('lets a trusted name resolve to a private address', async () => {
    dns.resolve4.mockResolvedValue(['10.89.0.1']);
    expect(await validateHost('sso.example.com')).toMatch(/private/i);

    process.env.TRUSTED_PRIVATE_HOSTS = 'sso.example.com';
    expect(await validateHost('sso.example.com')).toBeNull();
    const resolved = await resolveForConnection('sso.example.com');
    expect(resolved).toMatchObject({ host: '10.89.0.1', servername: 'sso.example.com', addresses: ['10.89.0.1'] });
  });

  it('keeps refusing every other private host', async () => {
    process.env.TRUSTED_PRIVATE_HOSTS = 'sso.example.com';
    dns.resolve4.mockResolvedValue(['192.168.1.10']);
    expect(await validateHost('nas.example.com')).toMatch(/private/i);
    await expect(resolveForConnection('nas.example.com')).rejects.toThrow(/private/i);
    expect(validateHostLiteral('127.0.0.1')).toMatch(/private/i);
    expect(validateHostLiteral('mail.local')).toMatch(/local/i);
  });

  it('accepts a listed name that would otherwise count as local', () => {
    expect(validateHostLiteral('vllm.internal')).toMatch(/local/i);
    process.env.TRUSTED_PRIVATE_HOSTS = 'vllm.internal';
    expect(validateHostLiteral('vllm.internal')).toBeNull();
  });
});
