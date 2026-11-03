// The port probe, the last step of the add-account lookup.
//
// The case it was written for: mail.tanngrisnir.de answers on every port but presents the
// provider's certificate (*.netcup.net). The right name is in the reverse DNS of the address
// and is also the MX. Here every name points at 127.0.0.1 and the certificate (testdata/, for
// tests only) is valid for *.mailhost.test.
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns';
import { probeServer, probeMailServers, probeCandidates } from './mailServerProbe.js';

const key = fs.readFileSync(new URL('./testdata/mailhost-test-key.pem', import.meta.url));
const cert = fs.readFileSync(new URL('./testdata/mailhost-test-cert.pem', import.meta.url));
const secureContext = tls.createSecureContext({ key, cert });
const trusted = { ca: [cert] };
const ignore = () => {};

const toLocalhost = (_host, options, callback) => {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (options?.all) callback(null, [{ address: '127.0.0.1', family: 4 }]);
  else callback(null, '127.0.0.1', 4);
};
const resolve = async () => ({ lookup: toLocalhost });
const base = { resolve, timeoutMs: 2000 };

const open = new Set();
const track = (socket) => {
  socket.on('error', ignore);
  open.add(socket);
  socket.on('close', () => open.delete(socket));
  return socket;
};
const upgrade = (socket) => {
  const secure = track(new tls.TLSSocket(socket, { isServer: true, secureContext }));
  secure.on('data', () => secure.end());
};

const factories = {
  imapTls: () => tls.createServer({ key, cert }, (socket) => {
    track(socket);
    socket.write('* OK [CAPABILITY IMAP4rev1] ready\r\n');
    socket.on('data', () => socket.end('* BYE\r\nA9 OK\r\n'));
  }),
  imapStarttls: () => net.createServer((socket) => {
    track(socket);
    socket.write('* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n');
    socket.once('data', (data) => {
      if (!/^A1 STARTTLS/i.test(data.toString())) return socket.end();
      socket.write('* a note first\r\nA1 OK Begin TLS\r\n');
      upgrade(socket);
    });
  }),
  // Sends more right after the OK, then speaks TLS as if nothing happened: what a STARTTLS
  // injection looks like. The extra line would be read as if it came over TLS.
  imapInjected: () => net.createServer((socket) => {
    track(socket);
    socket.write('* OK ready\r\n');
    socket.once('data', () => {
      socket.write('A1 OK Begin TLS\r\n* injected\r\n');
      upgrade(socket);
    });
  }),
  smtpStarttls: () => net.createServer((socket) => {
    track(socket);
    socket.write('220-mail.mailhost.test ESMTP\r\n220 ready\r\n');
    const onData = (data) => {
      const line = data.toString();
      if (/^EHLO \[/i.test(line)) socket.write('250-mail.mailhost.test\r\n250-SIZE 52428800\r\n250 STARTTLS\r\n');
      else if (/^STARTTLS/i.test(line)) {
        socket.off('data', onData);
        socket.write('220 Go ahead\r\n');
        upgrade(socket);
      }
    };
    socket.on('data', onData);
  }),
  smtpNoTls: () => net.createServer((socket) => {
    track(socket);
    socket.write('220 ready\r\n');
    socket.on('data', () => socket.write('250-mail.mailhost.test\r\n250 AUTH PLAIN LOGIN\r\n'));
  }),
  ssh: () => net.createServer((socket) => { track(socket); socket.write('SSH-2.0-OpenSSH_9.6\r\n'); }),
  silent: () => net.createServer(track),
};

const servers = {};
const port = {};
beforeAll(async () => {
  await Promise.all(Object.entries(factories).map(([name, make]) => new Promise((ok) => {
    const s = make();
    s.on('tlsClientError', ignore);
    s.listen(0, '127.0.0.1', () => { servers[name] = s; port[name] = s.address().port; ok(); });
  })));
});
afterAll(async () => {
  for (const socket of open) socket.destroy();
  await Promise.all(Object.values(servers).map(s => new Promise(ok => s.close(ok))));
});

const probe = (kind, name, socket, options = {}) =>
  probeServer({ kind, host: 'mail.mailhost.test', port: port[name], socket }, { ...base, tlsOptions: trusted, ...options });

describe('probeServer', () => {
  it('finds IMAP over TLS, with a trusted certificate', async () => {
    const found = await probe('imap', 'imapTls', 'SSL');
    expect(found).toMatchObject({ kind: 'imap', port: port.imapTls, socket: 'SSL', chainValid: true, remoteAddress: '127.0.0.1' });
    expect(found.certificate.subject.CN).toBe('*.mailhost.test');
  });

  it('finds IMAP with STARTTLS', async () => {
    expect(await probe('imap', 'imapStarttls', 'STARTTLS')).toMatchObject({ socket: 'STARTTLS', chainValid: true });
  });

  it('refuses a server that sends more after STARTTLS', async () => {
    expect(await probe('imap', 'imapInjected', 'STARTTLS')).toBeNull();
  });

  it('finds SMTP with STARTTLS, and nothing where SMTP offers no TLS', async () => {
    expect(await probe('smtp', 'smtpStarttls', 'STARTTLS')).toMatchObject({ socket: 'STARTTLS', chainValid: true });
    expect(await probe('smtp', 'smtpNoTls', 'STARTTLS')).toBeNull();
  });

  it('finds nothing where something else answers, or nothing at all', async () => {
    expect(await probe('imap', 'ssh', 'STARTTLS')).toBeNull();
    expect(await probe('imap', 'silent', 'STARTTLS', { timeoutMs: 300 })).toBeNull();
  });

  it('reports a chain it cannot verify', async () => {
    expect(await probe('imap', 'imapTls', 'SSL', { tlsOptions: {} })).toMatchObject({ chainValid: false });
  });

  it('does not connect to a name without a checked address, even one the system would resolve', async () => {
    const unchecked = { resolve: async () => ({ host: 'localhost', servername: null }) };
    expect(await probeServer({ kind: 'imap', host: 'localhost', port: port.imapTls, socket: 'SSL' }, { ...base, ...unchecked })).toBeNull();
  });
});

// With the real resolveForConnection: a name pointing at a private address is not probed unless
// the instance allows private hosts.
describe('probeMailServers and the private-host policy', () => {
  it('probes a name that resolves to 127.0.0.1 only when private hosts are allowed', async () => {
    vi.spyOn(dns.promises, 'resolve4').mockImplementation(async (name) => {
      if (name.endsWith('.mailhost.test') || name === 'mailhost.test') return ['127.0.0.1'];
      throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    });
    vi.spyOn(dns.promises, 'resolve6').mockRejectedValue(Object.assign(new Error('ENODATA'), { code: 'ENODATA' }));
    const options = {
      ports: { imap: [{ port: port.imapTls, socket: 'SSL' }], smtp: [] },
      tlsOptions: trusted, timeoutMs: 2000, reverse: async () => [],
    };
    try {
      expect(await probeMailServers('mailhost.test', [], { ...options, allowPrivate: false })).toEqual({ imap: null, smtp: null });
      expect((await probeMailServers('mailhost.test', [], { ...options, allowPrivate: true })).imap)
        .toEqual({ host: 'imap.mailhost.test', port: port.imapTls, socket: 'SSL' });
    } finally {
      vi.restoreAllMocks();
    }
  });
});

describe('probeMailServers', () => {
  // Assigned in a hook: the ports exist only once beforeAll has run.
  let options;
  beforeAll(() => {
    options = {
      resolve, timeoutMs: 2000, tlsOptions: trusted,
      ports: {
        imap: [{ port: port.imapTls, socket: 'SSL' }, { port: port.imapStarttls, socket: 'STARTTLS' }],
        smtp: [{ port: port.smtpNoTls, socket: 'STARTTLS' }, { port: port.smtpStarttls, socket: 'STARTTLS' }],
      },
    };
  });

  it('offers the reverse DNS name the provider\'s certificate is for, implicit TLS first', async () => {
    const reverse = vi.fn(async () => ['mx2.mailhost.test.']);
    expect(await probeMailServers('tanngrisnir.test', ['mx2.mailhost.test'], { ...options, reverse })).toEqual({
      imap: { host: 'mx2.mailhost.test', port: port.imapTls, socket: 'SSL' },
      smtp: { host: 'mx2.mailhost.test', port: port.smtpStarttls, socket: 'STARTTLS' },
    });
    // Asked once per address, however many names point at it.
    expect(reverse).toHaveBeenCalledTimes(1);
  });

  it('offers nothing when no name fits the certificate', async () => {
    expect(await probeMailServers('tanngrisnir.test', [], { ...options, reverse: async () => ['host.elsewhere.test'] }))
      .toEqual({ imap: null, smtp: null });
  });

  it('offers nothing with an untrusted certificate, even for the right name', async () => {
    expect(await probeMailServers('mailhost.test', [], { ...options, tlsOptions: {}, reverse: async () => [] }))
      .toEqual({ imap: null, smtp: null });
  });
});

describe('probeCandidates', () => {
  it('tries the usual names, then the MX hosts, then the domain', () => {
    expect(probeCandidates('example.de', ['MX1.Provider.net.', 'mx2.provider.net', 'mx3.provider.net', 'mx4.provider.net'])).toEqual({
      imap: ['imap.example.de', 'mail.example.de', 'mx1.provider.net', 'mx2.provider.net', 'mx3.provider.net', 'example.de'],
      smtp: ['smtp.example.de', 'mail.example.de', 'mx1.provider.net', 'mx2.provider.net', 'mx3.provider.net', 'example.de'],
    });
  });
});
