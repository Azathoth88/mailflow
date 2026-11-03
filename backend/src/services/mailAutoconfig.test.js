// Autoconfig for the add-account form: which domains are looked up, where, and which of the
// servers a config lists MailFlow can actually use.
import { describe, expect, it, vi } from 'vitest';

vi.mock('./safeFetch.js', () => ({ safeFetch: vi.fn() }));

const { safeFetch } = await import('./safeFetch.js');
const { autoconfigDomain, autoconfigUrls, parseAutoconfig, lookupAutoconfig } = await import('./mailAutoconfig.js');

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
    expect((await lookupAutoconfig(EMAIL)).source).toBe('domain');
    expect(safeFetch).toHaveBeenCalledTimes(3);
    for (const [url] of safeFetch.mock.calls) expect(url.startsWith('https://')).toBe(true);
  });

  it('prefers the domain\'s own config over the database', async () => {
    const fetchImpl = answers({ 'https://example.de/.well-known/': GOOD, 'https://autoconfig.thunderbird.net/': ISPDB });
    expect(await lookupAutoconfig(EMAIL, { fetchImpl })).toMatchObject({ source: 'domain', settings: { imap_host: 'imap.example.de' } });
  });

  it('falls back to the database when the domain has nothing usable', async () => {
    const fetchImpl = answers({
      'https://autoconfig.example.de/': new Error('getaddrinfo ENOTFOUND'),
      'https://example.de/.well-known/': '<html>Welcome</html>',
      'https://autoconfig.thunderbird.net/': ISPDB,
    });
    expect(await lookupAutoconfig(EMAIL, { fetchImpl })).toMatchObject({ source: 'ispdb', settings: { imap_host: 'imap.ispdb.example' } });
  });

  it('refuses a response larger than an autoconfig file can be', async () => {
    const fetchImpl = answers({ 'https://autoconfig.thunderbird.net/': GOOD + ' '.repeat(300 * 1024) });
    expect(await lookupAutoconfig(EMAIL, { fetchImpl })).toBeNull();
  });

  it('gives null when nothing is found, and asks nobody for an address that is not one', async () => {
    const fetchImpl = answers({});
    expect(await lookupAutoconfig(EMAIL, { fetchImpl })).toBeNull();
    fetchImpl.mockClear();
    expect(await lookupAutoconfig('a@10.0.0.5', { fetchImpl })).toBeNull();
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
