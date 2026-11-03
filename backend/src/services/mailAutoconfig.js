// Finds IMAP and SMTP settings for an address. Sources, in order of precedence:
//  1. the domain's own config (autoconfig.<domain>, then /.well-known/autoconfig)
//  2. its SRV records (RFC 6186)
//  3. Thunderbird's public database for the domain
//  4. its MX: Google Workspace and Microsoft 365, whose own sign-in the form offers, then
//     Thunderbird's entry for the provider behind the MX (one provider hosts many domains)
//  5. a port probe of the usual server names (mailServerProbe.js)
// 1-4 start together, so a source that does not answer costs its timeout once; the first usable
// one in that order wins. The probe runs only when none of them knows the domain.
//
// The result only fills in the add-account form; the user still confirms it and POST /accounts
// validates host and port as for anything typed by hand.
//
// HTTPS only, through safeFetch: the answer decides where the mailbox password goes, so a
// plaintext fetch would let anyone on the path substitute their own server. The domain comes
// from user input, so private and reserved targets are refused on every hop.

import { domainToASCII } from 'node:url';
import { Resolver } from 'node:dns/promises';
import { XMLParser } from 'fast-xml-parser';
import { safeFetch } from './safeFetch.js';
import { probeMailServers } from './mailServerProbe.js';

const TIMEOUT_MS = 4000;
// Real configs are a few KB.
const MAX_BYTES = 256 * 1024;
const ISPDB = 'https://autoconfig.thunderbird.net/v1.1/';

const IMAP_PORTS = new Set([143, 993]);
const SMTP_PORTS = new Set([465, 587]);

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const MAX_MX_PROVIDER_DOMAINS = 4;

// The domain of an address as an ASCII DNS name, or null. It is put into URLs, so anything that
// is not a plain name (IP literals, ports, paths) is refused here.
export function autoconfigDomain(email) {
  if (typeof email !== 'string' || email.length > 320) return null;
  const at = email.trim().lastIndexOf('@');
  if (at < 1) return null;
  const raw = email.trim().slice(at + 1).toLowerCase();
  // Checked before conversion: domainToASCII('example.de/x') quietly returns 'example.de'.
  if (!/^[\p{L}\p{M}\p{N}.-]+$/u.test(raw)) return null;
  const domain = domainToASCII(raw);
  return isDnsName(domain) ? domain : null;
}

function isDnsName(name) {
  if (!name || name.length > 253) return false;
  const labels = name.split('.');
  // A numeric top label is an IPv4 literal, not a name.
  return labels.length >= 2 && labels.every(l => LABEL.test(l)) && !/^[0-9]+$/.test(labels.at(-1));
}

export function autoconfigUrls(email, domain) {
  const q = `?emailaddress=${encodeURIComponent(email.trim())}`;
  return [
    { source: 'domain', url: `https://autoconfig.${domain}/mail/config-v1.1.xml${q}` },
    { source: 'domain', url: `https://${domain}/.well-known/autoconfig/mail/config-v1.1.xml${q}` },
    // Only the domain goes to Thunderbird's database, never the address.
    { source: 'ispdb', url: `${ISPDB}${domain}` },
  ];
}

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '',
  parseTagValue: false,
  isArray: (name) => ['emailProvider', 'incomingServer', 'outgoingServer', 'authentication'].includes(name),
});

function fill(value, email) {
  const address = email.trim();
  const at = address.lastIndexOf('@');
  return String(value ?? '')
    .replaceAll('%EMAILADDRESS%', address)
    .replaceAll('%EMAILLOCALPART%', address.slice(0, at))
    .replaceAll('%EMAILDOMAIN%', address.slice(at + 1))
    .trim();
}

// A server entry MailFlow can log in to with a password: TLS (implicit or STARTTLS), a port
// the add-account route accepts, and password authentication on offer. MailFlow derives
// implicit TLS for IMAP from the port (x993), and for SMTP from smtp_tls 'SSL' or port 465
// (smtpTransport.js), so the socket type has to agree with what that will choose.
function usable(server, email, { kind, allowNonstandardPorts }) {
  const host = fill(server.hostname, email).toLowerCase();
  const port = Number(server.port);
  const socket = String(server.socketType || '').toUpperCase();
  const auth = (server.authentication || []).map(a => String(a).trim());
  if (!isDnsName(host) || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  if (socket !== 'SSL' && socket !== 'STARTTLS') return null;
  if (auth.length && !auth.includes('password-cleartext')) return null;
  const implicitTls = kind === 'imap' ? port % 1000 === 993 : (socket === 'SSL' || port === 465);
  if (implicitTls !== (socket === 'SSL')) return null;
  if (!allowNonstandardPorts && !(kind === 'imap' ? IMAP_PORTS : SMTP_PORTS).has(port)) return null;
  return { host, port, socket, username: fill(server.username || '%EMAILADDRESS%', email) };
}

// The settings for the add-account form, or null when the config offers no IMAP server
// MailFlow can use. Entries are taken in the order the provider lists them.
export function parseAutoconfig(xml, email, { allowNonstandardPorts = false } = {}) {
  let doc;
  try { doc = parser.parse(xml); } catch { return null; }
  const provider = doc?.clientConfig?.emailProvider?.[0];
  if (!provider) return null;
  const servers = (list, type) => (list || []).filter(s => String(s?.type || '').toLowerCase() === type);
  const imap = servers(provider.incomingServer, 'imap')
    .map(s => usable(s, email, { kind: 'imap', allowNonstandardPorts })).find(Boolean);
  if (!imap) return null;
  const smtp = servers(provider.outgoingServer, 'smtp')
    .map(s => usable(s, email, { kind: 'smtp', allowNonstandardPorts })).find(Boolean);
  return {
    provider: typeof provider.displayName === 'string' ? provider.displayName.trim() : null,
    settings: settingsFrom(imap, smtp),
  };
}

function settingsFrom(imap, smtp) {
  return {
    imap_host: imap.host,
    imap_port: imap.port,
    auth_user: imap.username,
    ...(smtp ? {
      smtp_host: smtp.host,
      smtp_port: smtp.port,
      smtp_tls: smtp.socket,
      // Blank means "same login as IMAP" in the form.
      smtp_auth_user: smtp.username !== imap.username ? smtp.username : '',
    } : {}),
  };
}

// RFC 6186. Implicit TLS before STARTTLS; a target of "." means the service is not offered,
// which the DNS-name check drops.
const SRV_SERVICES = [
  ['imap', '_imaps', 'SSL'], ['imap', '_imap', 'STARTTLS'],
  ['smtp', '_submissions', 'SSL'], ['smtp', '_submission', 'STARTTLS'],
];

export async function srvSettings(domain, email, { resolveSrv, allowNonstandardPorts = false }) {
  const records = (await Promise.all(SRV_SERVICES.map(async ([kind, service, socketType]) => {
    const list = await resolveSrv(`${service}._tcp.${domain}`).catch(() => []);
    return [...(list || [])]
      .sort((a, b) => (a.priority - b.priority) || (b.weight - a.weight))
      .map(r => ({ kind, hostname: String(r.name || '').toLowerCase().replace(/\.$/, ''), port: r.port, socketType }));
  }))).flat();
  const pick = (kind) => records.filter(r => r.kind === kind)
    .map(r => usable(r, email, { kind, allowNonstandardPorts })).find(Boolean);
  const imap = pick('imap');
  return imap ? { provider: null, settings: settingsFrom(imap, pick('smtp')) } : null;
}

async function readCapped(res) {
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > MAX_BYTES) { await reader.cancel(); throw new Error('autoconfig response too large'); }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function fetchConfig(url, fetchImpl) {
  const res = await fetchImpl(url, {
    headers: { Accept: 'application/xml, text/xml' },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (res.status !== 200) {
    await res.body?.cancel().catch(() => {});
    throw new Error(`HTTP ${res.status}`);
  }
  return readCapped(res);
}

// Where a domain's mail is hosted, from its MX records: only the two hosts whose own sign-in the
// add-account form offers. A filtering gateway in front of either hides it, and is then simply
// not recognised. Their IMAP and SMTP servers are fixed, so the settings come from here; the
// form then shows its Google or Microsoft sign-in note for them.
const MX_HOSTS = [
  { suffixes: ['.google.com', '.googlemail.com'], signIn: 'google', provider: 'Google Workspace',
    settings: { imap_host: 'imap.gmail.com', imap_port: 993, smtp_host: 'smtp.gmail.com', smtp_port: 587, smtp_tls: 'STARTTLS' } },
  { suffixes: ['.mail.protection.outlook.com'], signIn: 'microsoft', provider: 'Microsoft 365',
    settings: { imap_host: 'outlook.office365.com', imap_port: 993, smtp_host: 'smtp.office365.com', smtp_port: 587, smtp_tls: 'STARTTLS' } },
];

const resolver = new Resolver({ timeout: 3000, tries: 2 });
const systemResolveMx = (domain) => resolver.resolveMx(domain);
const systemResolveSrv = (name) => resolver.resolveSrv(name);

// The domain's MX hosts, preferred first.
async function mxHostnames(domain, resolveMx) {
  let records;
  try { records = await resolveMx(domain); } catch { return []; }
  return [...(records || [])]
    .sort((a, b) => a.priority - b.priority)
    .map(r => String(r.exchange || '').toLowerCase().replace(/\.$/, ''))
    .filter(isDnsName);
}

function knownHosting(hosts, email) {
  const exchange = hosts[0] || '';
  const host = MX_HOSTS.find(h => h.suffixes.some(s => exchange.endsWith(s)));
  if (!host) return null;
  return {
    signIn: host.signIn,
    provider: host.provider,
    settings: { ...host.settings, auth_user: email.trim(), smtp_auth_user: '' },
  };
}

// { signIn, provider, settings } for the host of the domain's preferred MX, or null.
export async function mxHosting(domain, email, resolveMx = systemResolveMx) {
  return knownHosting(await mxHostnames(domain, resolveMx), email);
}

// The provider domains to look up in Thunderbird's database for MX hosts: the host without its
// first label, and its last two labels (mx2ff3.netcup.net -> netcup.net). The address' own
// domain has been asked already.
export function mxProviderDomains(hosts, domain) {
  const domains = [];
  for (const host of hosts.slice(0, 3)) {
    const labels = host.split('.');
    if (labels.length > 2) domains.push(labels.slice(1).join('.'));
    domains.push(labels.slice(-2).join('.'));
  }
  return [...new Set(domains)].filter(d => d !== domain && isDnsName(d)).slice(0, MAX_MX_PROVIDER_DOMAINS);
}

async function firstOf(pending) {
  for (const p of pending) {
    const found = await p;
    if (found) return found;
  }
  return null;
}

// { source: 'domain' | 'srv' | 'ispdb' | 'mx' | 'probe', provider, settings, signIn? } or null.
export async function lookupAutoconfig(email, {
  allowNonstandardPorts = false,
  allowPrivate = false,
  fetchImpl = safeFetch,
  resolveMx = systemResolveMx,
  resolveSrv = systemResolveSrv,
  probe = probeMailServers,
} = {}) {
  const domain = autoconfigDomain(email);
  if (!domain) return null;
  const options = { allowNonstandardPorts };
  const fromUrl = (url) => fetchConfig(url, fetchImpl).then(xml => parseAutoconfig(xml, email, options), () => null);
  const [own, wellKnown, ispdb] = autoconfigUrls(email, domain);
  const hosts = mxHostnames(domain, resolveMx);
  const sources = [
    ['domain', fromUrl(own.url)],
    ['domain', fromUrl(wellKnown.url)],
    ['srv', srvSettings(domain, email, { resolveSrv, ...options }).catch(() => null)],
    ['ispdb', fromUrl(ispdb.url)],
    ['mx', hosts.then(h => knownHosting(h, email))],
    ['mx', hosts.then(h => firstOf(mxProviderDomains(h, domain).map(via => fromUrl(`${ISPDB}${via}`))))],
  ];
  for (const [source, pending] of sources) {
    const found = await pending;
    if (found) return { source, ...found };
  }

  const probed = await probe(domain, await hosts, { allowPrivate }).catch(() => null);
  const asServer = (found, kind) => found
    && usable({ hostname: found.host, port: found.port, socketType: found.socket }, email, { kind, ...options });
  const imap = asServer(probed?.imap, 'imap');
  return imap ? { source: 'probe', provider: null, settings: settingsFrom(imap, asServer(probed?.smtp, 'smtp') || null) } : null;
}
