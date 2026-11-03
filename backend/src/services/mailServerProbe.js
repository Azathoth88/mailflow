// The last step of the add-account lookup (mailAutoconfig.js): when neither the domain, its DNS
// nor Thunderbird's database know the servers, try the usual names on the usual ports and see
// whether an IMAP or SMTP server with TLS answers there. It never logs in and never sends a
// password: it reads the greeting, upgrades with STARTTLS where needed, and looks at the
// certificate.
//
// Shared hosting often answers under the customer's name with the provider's certificate
// (mail.<domain> presenting *.provider.net). The reverse DNS name of the address is then tried:
// that is the name the provider issued the certificate for, and the one the account must use.
// Only a server whose certificate is valid for the name it is offered under is returned, since
// MailFlow verifies certificates when it connects.
//
// Every target goes through resolveForConnection, so a name pointing at a private or reserved
// address is not probed, and the socket connects only to the address that was checked.

import net from 'node:net';
import tls from 'node:tls';
import { promises as dnsPromises } from 'node:dns';
import { resolveForConnection } from './hostValidation.js';

const TIMEOUT_MS = 5000;
const MAX_LINE_BYTES = 16 * 1024;
const MAX_REPLY_LINES = 100;
const MAX_MX_HOSTS = 3;

export const PROBE_PORTS = {
  imap: [{ port: 993, socket: 'SSL' }, { port: 143, socket: 'STARTTLS' }],
  smtp: [{ port: 465, socket: 'SSL' }, { port: 587, socket: 'STARTTLS' }],
};

const ignore = () => {};

// Lines from a socket. detach() unhooks it before a STARTTLS upgrade and says whether anything
// was left over: a server that sends more after "go ahead" is not trusted (STARTTLS injection).
function lineReader(socket) {
  let buffer = '';
  const lines = [];
  let waiting = null;
  let failure = null;
  const wake = () => {
    if (!waiting) return;
    const w = waiting;
    if (lines.length) { waiting = null; w.resolve(lines.shift()); }
    else if (failure) { waiting = null; w.reject(failure); }
  };
  const onData = (chunk) => {
    buffer += chunk.toString('latin1');
    let i;
    while ((i = buffer.indexOf('\n')) !== -1) {
      lines.push(buffer.slice(0, i).replace(/\r$/, ''));
      buffer = buffer.slice(i + 1);
    }
    if (buffer.length > MAX_LINE_BYTES) failure = new Error('line too long');
    wake();
  };
  const onEnd = () => { failure = failure || new Error('connection closed'); wake(); };
  const onError = (err) => { failure = failure || err; wake(); };
  socket.on('data', onData);
  socket.on('end', onEnd);
  socket.on('close', onEnd);
  socket.on('error', onError);
  return {
    line: () => new Promise((resolve, reject) => {
      if (lines.length) return resolve(lines.shift());
      if (failure) return reject(failure);
      waiting = { resolve, reject };
    }),
    detach: () => {
      socket.off('data', onData);
      socket.off('end', onEnd);
      socket.off('close', onEnd);
      socket.off('error', onError);
      return buffer.length > 0 || lines.length > 0;
    },
  };
}

async function smtpReply(reader) {
  const lines = [];
  for (let i = 0; i < MAX_REPLY_LINES; i++) {
    const line = await reader.line();
    const m = /^(\d{3})(?:([ -])|$)/.exec(line);
    if (!m) throw new Error('not an SMTP reply');
    lines.push(line);
    if (m[2] !== '-') return { code: Number(m[1]), lines };
  }
  throw new Error('SMTP reply too long');
}

async function greeting(kind, reader) {
  if (kind === 'imap') {
    if (!/^\* (OK|PREAUTH)\b/i.test(await reader.line())) throw new Error('not an IMAP server');
    return;
  }
  if ((await smtpReply(reader)).code !== 220) throw new Error('not an SMTP server');
}

async function startTls(kind, socket, reader) {
  if (kind === 'imap') {
    socket.write('A1 STARTTLS\r\n');
    for (let i = 0; i < MAX_REPLY_LINES; i++) {
      const line = await reader.line();
      if (/^A1 OK\b/i.test(line)) return;
      if (/^A1 /i.test(line)) throw new Error('STARTTLS refused');
    }
    throw new Error('no answer to STARTTLS');
  }
  // An address literal of our own as EHLO argument (RFC 5321 4.1.3).
  const own = socket.localAddress || '127.0.0.1';
  socket.write(`EHLO ${net.isIPv6(own) ? `[IPv6:${own}]` : `[${own}]`}\r\n`);
  const ehlo = await smtpReply(reader);
  if (ehlo.code !== 250 || !ehlo.lines.some(l => /^250[- ]STARTTLS\b/i.test(l))) throw new Error('no STARTTLS');
  socket.write('STARTTLS\r\n');
  if ((await smtpReply(reader)).code !== 220) throw new Error('STARTTLS refused');
}

// One host and port: { kind, host, port, socket, remoteAddress, chainValid, certificate } when a
// server of that kind answers there with TLS, else null.
export async function probeServer({ kind, host, port, socket: socketType }, { resolve, tlsOptions = {}, timeoutMs = TIMEOUT_MS } = {}) {
  // After STARTTLS the TLS socket owns the plain one; destroying both has crashed Node.
  const sockets = [];
  const track = (s, replaces) => {
    s.on('error', ignore);
    const i = replaces ? sockets.indexOf(replaces) : -1;
    if (i !== -1) sockets.splice(i, 1);
    sockets.push(s);
    return s;
  };
  const tcp = (lookup) => new Promise((ok, fail) => {
    const s = track(net.connect({ host, port, lookup }));
    s.once('connect', () => ok(s));
    s.once('error', fail);
  });
  const secure = (lookup, raw) => new Promise((ok, fail) => {
    const s = track(tls.connect({
      ...(raw ? { socket: raw } : { host, port, lookup }),
      servername: host,
      // Chain and name are judged separately afterwards: the name may only fit the reverse DNS
      // name, which a failed handshake would never let us see.
      rejectUnauthorized: false,
      checkServerIdentity: () => undefined,
      ...tlsOptions,
    }), raw);
    s.once('secureConnect', () => ok(s));
    s.once('error', fail);
  });

  const run = async () => {
    const target = await resolve(host);
    // No checked address (DNS has none): nothing to probe, and no unchecked fallback.
    if (!target?.lookup) return null;
    let s;
    let remoteAddress;
    if (socketType === 'SSL') {
      s = await secure(target.lookup);
      remoteAddress = s.remoteAddress;
      await greeting(kind, lineReader(s));
    } else {
      const raw = await tcp(target.lookup);
      remoteAddress = raw.remoteAddress;
      const reader = lineReader(raw);
      await greeting(kind, reader);
      await startTls(kind, raw, reader);
      if (reader.detach()) throw new Error('data after STARTTLS');
      s = await secure(target.lookup, raw);
    }
    const certificate = s.getPeerCertificate();
    try { s.write(kind === 'imap' ? 'A9 LOGOUT\r\n' : 'QUIT\r\n'); } catch { /* courtesy only */ }
    return {
      kind, host, port, socket: socketType, remoteAddress,
      chainValid: s.authorized === true,
      certificate: certificate && Object.keys(certificate).length ? certificate : null,
    };
  };

  let timer;
  const timeout = new Promise((_, fail) => { timer = setTimeout(() => fail(new Error('timeout')), timeoutMs); });
  try {
    return await Promise.race([run(), timeout]);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
    for (const s of sockets) s.destroy();
  }
}

const normalize = (name) => String(name || '').trim().toLowerCase().replace(/\.$/, '');

// The name a found server is offered under: the probed one when the certificate fits it, else a
// reverse DNS name of its address that it fits. null when the chain is not trusted or no name fits.
async function certifiedName(found, reverse) {
  if (!found.chainValid || !found.certificate) return null;
  if (!tls.checkServerIdentity(found.host, found.certificate)) return found.host;
  for (const name of (await reverse(found.remoteAddress)).map(normalize)) {
    if (name && !tls.checkServerIdentity(name, found.certificate)) return name;
  }
  return null;
}

function cachedReverse(reverse) {
  const cache = new Map();
  return (address) => {
    const ip = String(address || '').replace(/^::ffff:/i, '');
    if (!net.isIP(ip)) return Promise.resolve([]);
    if (!cache.has(ip)) cache.set(ip, Promise.resolve().then(() => reverse(ip)).catch(() => []));
    return cache.get(ip);
  };
}

// Names to try, in order of preference.
export function probeCandidates(domain, mxHosts = []) {
  const mx = mxHosts.slice(0, MAX_MX_HOSTS);
  const unique = (list) => [...new Set(list.map(normalize).filter(Boolean))];
  return {
    imap: unique([`imap.${domain}`, `mail.${domain}`, ...mx, domain]),
    smtp: unique([`smtp.${domain}`, `mail.${domain}`, ...mx, domain]),
  };
}

// The best IMAP and SMTP server found: { imap: { host, port, socket } | null, smtp: … | null }.
// Implicit TLS is preferred over STARTTLS, then the order of the candidate names.
export async function probeMailServers(domain, mxHosts = [], {
  allowPrivate = false,
  resolve = (host) => resolveForConnection(host, { allowPrivate }),
  reverse = (ip) => dnsPromises.reverse(ip),
  ports = PROBE_PORTS,
  tlsOptions,
  timeoutMs,
} = {}) {
  const names = probeCandidates(domain, mxHosts);
  const reverseOnce = cachedReverse(reverse);
  const attempts = [];
  for (const kind of ['imap', 'smtp']) {
    names[kind].forEach((host, rank) => {
      for (const { port, socket } of ports[kind]) attempts.push({ kind, host, port, socket, rank });
    });
  }
  const found = (await Promise.all(attempts.map(async (attempt) => {
    const result = await probeServer(attempt, { resolve, tlsOptions, timeoutMs });
    const host = result && await certifiedName(result, reverseOnce);
    return host ? { kind: attempt.kind, host, port: attempt.port, socket: attempt.socket, rank: attempt.rank } : null;
  }))).filter(Boolean);

  const best = (kind) => {
    const list = found.filter(f => f.kind === kind)
      .sort((a, b) => (a.socket === b.socket ? 0 : a.socket === 'SSL' ? -1 : 1) || a.rank - b.rank);
    return list.length ? { host: list[0].host, port: list[0].port, socket: list[0].socket } : null;
  };
  return { imap: best('imap'), smtp: best('smtp') };
}
