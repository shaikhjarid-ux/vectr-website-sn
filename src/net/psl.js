// Registrable-domain logic using the Public Suffix List (tldts), including
// private suffixes such as github.io. Never string-splitting.
import { getDomain, parse } from 'tldts';

const clean = (host) => String(host ?? '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');

/** @param {string} host @returns {string | null} */
export function registrableDomain(host) {
  const h = clean(host);
  if (!h) return null;
  return getDomain(h, { allowPrivateDomains: true });
}

/** @param {string} hostA @param {string} hostB */
export function crossesRegistrableDomain(hostA, hostB) {
  const a = clean(hostA), b = clean(hostB);
  const pa = parse(a, { allowPrivateDomains: true }), pb = parse(b, { allowPrivateDomains: true });
  if (pa.isIp || pb.isIp) return a !== b;
  const da = pa.domain, db = pb.domain;
  if (!da || !db) return a !== b;
  return da !== db;
}
