import { domainToASCII } from 'url';

// Hosts the operator names in TRUSTED_PRIVATE_HOSTS may resolve to private addresses without
// "Allow private / local hosts", which opens every host to every user. Behind a reverse proxy on
// the same machine, or in a container network, the operator's own services resolve privately.
function normalizeHost(host) {
  let h = String(host || '').trim();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (/[^\p{ASCII}]/u.test(h)) h = domainToASCII(h);
  return h.toLowerCase().replace(/\.+$/, '');
}

export function trustedPrivateHosts() {
  const hosts = new Set();
  for (const entry of (process.env.TRUSTED_PRIVATE_HOSTS || '').split(/[\s,]+/)) {
    const h = normalizeHost(entry);
    if (h) hosts.add(h);
  }
  return hosts;
}

export function isTrustedPrivateHost(host) {
  const h = normalizeHost(host);
  return h !== '' && trustedPrivateHosts().has(h);
}
