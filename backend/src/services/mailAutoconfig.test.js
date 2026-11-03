// Autoconfig for the add-account form: which domains are looked up, where, and which of the
// servers a config lists MailFlow can actually use.
import { describe, expect, it, vi } from 'vitest';

vi.mock('./safeFetch.js', () => ({ safeFetch: vi.fn() }));

const { safeFetch } = await import('./safeFetch.js');
const { autoconfigDomain, autoconfigUrls, parseAutoconfig, lookupAutoconfig, mxHosting, srvSettings, mxProviderDomains } = await import('./mailAutoconfig.js');

const server = (tag, type, { host, port, socket, username = '%EMAILADDRESS%', auth = ['password-cleartext'] }) =>
  `<${tag} type="${type}"><hostname>${host}</hostname><port>${port}</port><socketType>${socket}</socketType>` +
  `<username>${username}</username>${auth.map(a => `<authentication>${a}</authentication>`).join('')}</${tag}>`;
const imap = (o) => server('incomingServer', 'imap', o);
const pop3 = (o) => server('incomingServer', 'pop3', o);
const smtp = (o) => server('outgoingServer', 'smtp', o);
const config = (...servers) =>
  `<?xml version="1.0"?><clientConfig version="1.1"><emailProvider id="example.de"><domain>example.de</domain>` +
  `<displayName>Example Mail</displayName>${servers.join('')}</emailProvider></clientConfig>`;

const EMAIL = 'max@example.de';
const noMx = async () => { throw Object.assign(new Error('queryMx ENODATA'), { code: 'ENODATA' }); };
const noSrv = async () => { throw Object.assign(new Error('querySrv ENOTFOUND'), { code: 'ENOTFOUND' }); };
const noProbe = vi.fn(async () => ({ imap: null, smtp: null }));
// No DNS, no probe: every lookup test states which sources answer.
const OFFLINE = { resolveMx: noMx, resolveSrv: noSrv, probe: noProbe };
const mx = (...exchanges) => async () => exchanges.map(([exchange, priority]) => ({ exchange, priority }));

describe('autoconfigDomain', () => {
  it.each([
    ['max@example.de', 'example.de'],
    [' Max@Mail.Example.DE ', 'mail.example.de'],
    ['max@müller.de', 'xn--mller-kva.de'],
    ['"a@b"@example.de', 'example.de'],
  ])('takes %s', (email, domain) => expect(autoconfigDomain(email)).toBe(domain));

  it.each([
    'a@127.0.0.1', 'a@[::1]', 'a@example.de:8080', 'a@example.de/x', 'a@../x.de', 'a@localhost',
    'a@-x.de', '@example.de', 'example.de', '', null, ['a@example.de'], `a@${'x'.repeat(330)}.de`,
  ])('refuses %j', (email) => expect(autoconfigDomain(email)).toBeNull());
});

describe('autoconfigUrls', () => {
  it('asks the domain itself and Thunderbird\'s database, all over HTTPS', () => {
    expect(autoconfigUrls(EMAIL, 'example.de')).toEqual([
      { source: 'domain', url: 'https://autoconfig.example.de/mail/config-v1.1.xml?emailaddress=max%40example.de' },
      { source: 'domain', url: 'https://example.de/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=max%40example.de' },
      { source: 'ispdb', url: 'https://autoconfig.thunderbird.net/v1.1/example.de' },
    ]);
  });
});

describe('parseAutoconfig', () => {
  it('fills in the form from the first usable IMAP and SMTP servers', () => {
    expect(parseAutoconfig(config(
      imap({ host: 'imap.example.de', port: 993, socket: 'SSL' }),
      smtp({ host: 'smtp.example.de', port: 587, socket: 'STARTTLS' }),
    ), EMAIL)).toEqual({
      provider: 'Example Mail',
      settings: {
        imap_host: 'imap.example.de', imap_port: 993, auth_user: EMAIL,
        smtp_host: 'smtp.example.de', smtp_port: 587, smtp_tls: 'STARTTLS', smtp_auth_user: '',
      },
    });
  });

  it('skips what MailFlow cannot use: POP3, plaintext, OAuth2 only, port 25, a socket type that disagrees with the port', () => {
    const parsed = parseAutoconfig(config(
      pop3({ host: 'pop.example.de', port: 995, socket: 'SSL' }),
      imap({ host: 'plain.example.de', port: 143, socket: 'plain' }),
      imap({ host: 'oauth.example.de', port: 993, socket: 'SSL', auth: ['OAuth2'] }),
      imap({ host: 'mismatch.example.de', port: 993, socket: 'STARTTLS' }),
      imap({ host: 'imap.example.de', port: 143, socket: 'STARTTLS', auth: ['OAuth2', 'password-cleartext'] }),
      smtp({ host: 'mx.example.de', port: 25, socket: 'STARTTLS' }),
      smtp({ host: 'mismatch.example.de', port: 465, socket: 'STARTTLS' }),
      smtp({ host: 'smtp.example.de', port: 465, socket: 'SSL' }),
    ), EMAIL);
    expect(parsed.settings).toMatchObject({
      imap_host: 'imap.example.de', imap_port: 143,
      smtp_host: 'smtp.example.de', smtp_port: 465, smtp_tls: 'SSL',
    });
  });

  it('takes a nonstandard port only when the instance allows them', () => {
    const xml = config(imap({ host: 'imap.example.de', port: 1993, socket: 'SSL' }));
    expect(parseAutoconfig(xml, EMAIL)).toBeNull();
    expect(parseAutoconfig(xml, EMAIL, { allowNonstandardPorts: true }).settings.imap_port).toBe(1993);
  });

  it('replaces the placeholders, and keeps a different SMTP login', () => {
    const parsed = parseAutoconfig(config(
      imap({ host: 'imap.%EMAILDOMAIN%', port: 993, socket: 'SSL', username: '%EMAILLOCALPART%' }),
      smtp({ host: 'smtp.%EMAILDOMAIN%', port: 587, socket: 'STARTTLS', username: '%EMAILADDRESS%' }),
    ), EMAIL);
    expect(parsed.settings).toMatchObject({
      imap_host: 'imap.example.de', auth_user: 'max', smtp_host: 'smtp.example.de', smtp_auth_user: EMAIL,
    });
  });

  it('gives the IMAP side alone when no SMTP server is usable', () => {
    const parsed = parseAutoconfig(config(imap({ host: 'imap.example.de', port: 993, socket: 'SSL' })), EMAIL);
    expect(parsed.settings).toEqual({ imap_host: 'imap.example.de', imap_port: 993, auth_user: EMAIL });
  });

  it.each([
    ['no usable IMAP server', config(pop3({ host: 'pop.example.de', port: 995, socket: 'SSL' }))],
    ['a host that is not a DNS name', config(imap({ host: '10.0.0.5', port: 993, socket: 'SSL' }))],
    ['a host with a path', config(imap({ host: 'imap.example.de/x', port: 993, socket: 'SSL' }))],
    ['something that is not an autoconfig file', '<html><body>Not found</body></html>'],
    ['broken XML', '<clientConfig><emailProvider>'],
  ])('gives nothing for %s', (_, xml) => {
    expect(parseAutoconfig(xml, EMAIL)).toBeNull();
  });
});

describe('lookupAutoconfig', () => {
  const GOOD = config(imap({ host: 'imap.example.de', port: 993, socket: 'SSL' }));
  const ISPDB = config(imap({ host: 'imap.ispdb.example', port: 993, socket: 'SSL' }));
  const answers = (byUrl) => vi.fn(async (url) => {
    const a = Object.entries(byUrl).find(([prefix]) => url.startsWith(prefix))?.[1];
    if (a instanceof Error) throw a;
    return new Response(a ?? 'Not found', { status: a ? 200 : 404 });
  });

  it('goes through safeFetch by default', async () => {
    safeFetch.mockImplementation(answers({ 'https://autoconfig.example.de/': GOOD }));
    expect((await lookupAutoconfig(EMAIL, { ...OFFLINE })).source).toBe('domain');
    expect(safeFetch).toHaveBeenCalledTimes(3);
    for (const [url] of safeFetch.mock.calls) expect(url.startsWith('https://')).toBe(true);
  });

  it('prefers the domain\'s own config over the database', async () => {
    const fetchImpl = answers({ 'https://example.de/.well-known/': GOOD, 'https://autoconfig.thunderbird.net/': ISPDB });
    expect(await lookupAutoconfig(EMAIL, { fetchImpl, ...OFFLINE })).toMatchObject({ source: 'domain', settings: { imap_host: 'imap.example.de' } });
  });

  it('falls back to the database when the domain has nothing usable', async () => {
    const fetchImpl = answers({
      'https://autoconfig.example.de/': new Error('getaddrinfo ENOTFOUND'),
      'https://example.de/.well-known/': '<html>Welcome</html>',
      'https://autoconfig.thunderbird.net/': ISPDB,
    });
    expect(await lookupAutoconfig(EMAIL, { fetchImpl, ...OFFLINE })).toMatchObject({ source: 'ispdb', settings: { imap_host: 'imap.ispdb.example' } });
  });

  it('refuses a response larger than an autoconfig file can be', async () => {
    const fetchImpl = answers({ 'https://autoconfig.thunderbird.net/': GOOD + ' '.repeat(300 * 1024) });
    expect(await lookupAutoconfig(EMAIL, { fetchImpl, ...OFFLINE })).toBeNull();
  });

  it('gives null when nothing is found, and asks nobody for an address that is not one', async () => {
    const fetchImpl = answers({});
    expect(await lookupAutoconfig(EMAIL, { fetchImpl, ...OFFLINE })).toBeNull();
    fetchImpl.mockClear();
    expect(await lookupAutoconfig('a@10.0.0.5', { fetchImpl, ...OFFLINE })).toBeNull();
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe('mxHosting', () => {
  it.each([
    ['Google Workspace', [['aspmx.l.google.com', 1], ['alt1.aspmx.l.google.com', 5]], 'google', 'imap.gmail.com'],
    ['Google Workspace (single MX)', [['smtp.google.com.', 1]], 'google', 'imap.gmail.com'],
    ['Microsoft 365', [['example-de.mail.protection.outlook.com', 0]], 'microsoft', 'outlook.office365.com'],
  ])('recognises %s', async (_, records, signIn, imapHost) => {
    expect(await mxHosting('example.de', EMAIL, mx(...records))).toMatchObject({
      signIn, settings: { imap_host: imapHost, imap_port: 993, auth_user: EMAIL, smtp_port: 587, smtp_tls: 'STARTTLS' },
    });
  });

  it.each([
    ['a host of its own', [['mx.example.de', 10]]],
    ['a filtering gateway in front, with Google only as backup', [['mx1.gateway.example', 10], ['aspmx.l.google.com', 20]]],
    ['a lookalike name', [['mx.evilgoogle.com', 1]]],
    ['the provider name inside another domain', [['aspmx.l.google.com.attacker.example', 1]]],
    ['no records', []],
  ])('gives nothing for %s', async (_, records) => {
    expect(await mxHosting('example.de', EMAIL, mx(...records))).toBeNull();
  });

  it('gives nothing when DNS fails', async () => {
    expect(await mxHosting('example.de', EMAIL, noMx)).toBeNull();
  });
});

describe('lookupAutoconfig with MX', () => {
  const none = vi.fn(async () => new Response('Not found', { status: 404 }));

  it('falls back to the MX host when no config is published', async () => {
    expect(await lookupAutoconfig(EMAIL, { ...OFFLINE, fetchImpl: none, resolveMx: mx(['aspmx.l.google.com', 1]) })).toMatchObject({
      source: 'mx', signIn: 'google', provider: 'Google Workspace', settings: { imap_host: 'imap.gmail.com' },
    });
  });

  it('prefers a published config over the MX host', async () => {
    const fetchImpl = vi.fn(async (url) => url.startsWith('https://autoconfig.example.de/')
      ? new Response(config(imap({ host: 'imap.example.de', port: 993, socket: 'SSL' })), { status: 200 })
      : new Response('Not found', { status: 404 }));
    expect(await lookupAutoconfig(EMAIL, { ...OFFLINE, fetchImpl, resolveMx: mx(['aspmx.l.google.com', 1]) })).toMatchObject({ source: 'domain' });
  });
});

describe('srvSettings (RFC 6186)', () => {
  const srv = (byName) => async (name) => {
    if (!byName[name]) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    return byName[name].map(([n, port, priority = 0, weight = 0]) => ({ name: n, port, priority, weight }));
  };

  it('takes implicit TLS before STARTTLS, by priority', async () => {
    const resolveSrv = srv({
      '_imaps._tcp.example.de': [['imap2.example.de.', 993, 20], ['imap.example.de.', 993, 10]],
      '_imap._tcp.example.de': [['imap.example.de.', 143]],
      '_submission._tcp.example.de': [['smtp.example.de.', 587]],
    });
    expect(await srvSettings('example.de', EMAIL, { resolveSrv })).toEqual({
      provider: null,
      settings: { imap_host: 'imap.example.de', imap_port: 993, auth_user: EMAIL, smtp_host: 'smtp.example.de', smtp_port: 587, smtp_tls: 'STARTTLS', smtp_auth_user: '' },
    });
  });

  it('skips a service marked as not offered (".")', async () => {
    const resolveSrv = srv({ '_imaps._tcp.example.de': [['.', 0]], '_imap._tcp.example.de': [['imap.example.de', 143]] });
    expect((await srvSettings('example.de', EMAIL, { resolveSrv })).settings).toMatchObject({ imap_host: 'imap.example.de', imap_port: 143 });
  });

  it('gives nothing without an IMAP record', async () => {
    expect(await srvSettings('example.de', EMAIL, { resolveSrv: srv({ '_submission._tcp.example.de': [['smtp.example.de', 587]] }) })).toBeNull();
  });
});

describe('mxProviderDomains', () => {
  it.each([
    [['mx2ff3.netcup.net'], ['netcup.net']],
    [['aspmx.l.google.com', 'alt1.aspmx.l.google.com'], ['l.google.com', 'google.com', 'aspmx.l.google.com']],
    [['mx.example.de'], []],
    [['mail.provider.example', 'mx1.provider.example', 'mx2.provider.example', 'mx3.other.example'], ['provider.example']],
  ])('%j -> %j', (hosts, domains) => {
    expect(mxProviderDomains(hosts, 'example.de')).toEqual(domains);
  });
});

// webmaster@tanngrisnir.de: autoconfig.<domain> is a CNAME to a host that does not answer,
// Thunderbird's database knows neither the domain nor the provider, and the server is still there.
describe('lookupAutoconfig: SRV, the provider behind the MX, and the probe', () => {
  const none = vi.fn(async () => new Response('Not found', { status: 404 }));
  const NETCUP = config(imap({ host: 'mx2ff3.netcup.net', port: 993, socket: 'SSL' }), smtp({ host: 'mx2ff3.netcup.net', port: 465, socket: 'SSL' }));

  it('uses SRV records when the domain publishes no config', async () => {
    const resolveSrv = async (name) => {
      if (name === '_imaps._tcp.example.de') return [{ name: 'imap.example.de', port: 993, priority: 0, weight: 0 }];
      throw new Error('ENOTFOUND');
    };
    expect(await lookupAutoconfig(EMAIL, { ...OFFLINE, fetchImpl: none, resolveSrv })).toMatchObject({ source: 'srv', settings: { imap_host: 'imap.example.de' } });
  });

  it('asks Thunderbird\'s database for the provider behind the MX, with only that provider\'s domain', async () => {
    const fetchImpl = vi.fn(async (url) => url === 'https://autoconfig.thunderbird.net/v1.1/netcup.net'
      ? new Response(NETCUP.replace('Example Mail', 'netcup'), { status: 200 })
      : new Response('Not found', { status: 404 }));
    const found = await lookupAutoconfig('webmaster@tanngrisnir.de', { ...OFFLINE, fetchImpl, resolveMx: mx(['mx2ff3.netcup.net', 10]) });
    expect(found).toMatchObject({ source: 'mx', provider: 'netcup', settings: { imap_host: 'mx2ff3.netcup.net', smtp_port: 465 } });
    const ispdbUrls = fetchImpl.mock.calls.map(([url]) => url).filter(url => url.startsWith('https://autoconfig.thunderbird.net/'));
    expect(ispdbUrls).toEqual(['https://autoconfig.thunderbird.net/v1.1/tanngrisnir.de', 'https://autoconfig.thunderbird.net/v1.1/netcup.net']);
  });

  it('probes last, with the MX hosts and the instance\'s private-host policy', async () => {
    const probe = vi.fn(async () => ({
      imap: { host: 'mx2ff3.netcup.net', port: 993, socket: 'SSL' },
      smtp: { host: 'mx2ff3.netcup.net', port: 587, socket: 'STARTTLS' },
    }));
    const found = await lookupAutoconfig('webmaster@tanngrisnir.de', {
      ...OFFLINE, fetchImpl: none, resolveMx: mx(['mx2ff3.netcup.net', 10]), probe, allowPrivate: false,
    });
    expect(probe).toHaveBeenCalledWith('tanngrisnir.de', ['mx2ff3.netcup.net'], { allowPrivate: false });
    expect(found).toEqual({
      source: 'probe', provider: null,
      settings: { imap_host: 'mx2ff3.netcup.net', imap_port: 993, auth_user: 'webmaster@tanngrisnir.de', smtp_host: 'mx2ff3.netcup.net', smtp_port: 587, smtp_tls: 'STARTTLS', smtp_auth_user: '' },
    });
  });

  it('does not probe when another source knows the domain', async () => {
    const probe = vi.fn();
    const fetchImpl = vi.fn(async (url) => url.startsWith('https://autoconfig.example.de/')
      ? new Response(config(imap({ host: 'imap.example.de', port: 993, socket: 'SSL' })), { status: 200 })
      : new Response('Not found', { status: 404 }));
    await lookupAutoconfig(EMAIL, { ...OFFLINE, fetchImpl, probe });
    expect(probe).not.toHaveBeenCalled();
  });

  it('gives nothing when the probe finds no IMAP server', async () => {
    const probe = vi.fn(async () => ({ imap: null, smtp: { host: 'smtp.example.de', port: 587, socket: 'STARTTLS' } }));
    expect(await lookupAutoconfig(EMAIL, { ...OFFLINE, fetchImpl: none, probe })).toBeNull();
  });
});
