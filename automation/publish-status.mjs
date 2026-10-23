import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFile, writeFile, rename } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const MAX_FILE = 1024 * 1024;
const domain = 'TradingMeow.Licensing.v1\n';
function requireValue(condition, message) { if (!condition) throw new Error(message); }
function strictParse(bytes) {
  requireValue(bytes.length <= MAX_FILE, 'JSON file too large');
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); let i = 0;
  const space = () => { while (/[\t\n\r ]/.test(text[i] || '\0')) i++; };
  const string = () => {
    requireValue(text[i] === '"', 'Expected JSON string'); const start = i++;
    while (i < text.length) {
      if (text[i] === '\\') { i += 2; continue; }
      if (text[i++] === '"') return JSON.parse(text.slice(start, i));
    }
    throw new Error('Unterminated JSON string');
  };
  const value = depth => {
    requireValue(depth <= 16, 'JSON nesting too deep'); space();
    if (text[i] === '{') {
      i++; space(); const keys = new Set(); if (text[i] === '}') { i++; return; }
      while (true) { space(); const key = string(); requireValue(!keys.has(key), 'Duplicate JSON property'); keys.add(key); space(); requireValue(text[i++] === ':', 'Expected colon'); value(depth + 1); space(); if (text[i] === '}') { i++; return; } requireValue(text[i++] === ',', 'Expected comma'); }
    }
    if (text[i] === '[') {
      i++; space(); if (text[i] === ']') { i++; return; }
      while (true) { value(depth + 1); space(); if (text[i] === ']') { i++; return; } requireValue(text[i++] === ',', 'Expected comma'); }
    }
    if (text[i] === '"') { string(); return; }
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i));
    requireValue(match, 'Invalid JSON value'); i += match[0].length;
  };
  value(0); space(); requireValue(i === text.length, 'Trailing JSON content'); return JSON.parse(text);
}
function decode(value) {
  requireValue(typeof value === 'string' && value.length <= MAX_FILE * 2 && /^[A-Za-z0-9+/]*={0,2}$/.test(value), 'Invalid base64');
  const bytes = Buffer.from(value, 'base64');
  requireValue(bytes.toString('base64') === value && bytes.length <= MAX_FILE, 'Invalid base64');
  return bytes;
}
function date(value) {
  requireValue(typeof value === 'string' && /(?:Z|\+00:00)$/.test(value), 'Dates must be UTC');
  const time = Date.parse(value); requireValue(Number.isFinite(time), 'Invalid date'); return time;
}
function signedBytes(kind, keyId, payload) { return Buffer.concat([Buffer.from(domain + kind + '\n' + keyId + '\n'), payload]); }
function readSigned(document, kind, publicKey) {
  requireValue(document?.format === 1 && document.kind === kind && typeof document.keyId === 'string', 'Wrong document kind');
  const payload = decode(document.payload), signature = decode(document.signature);
  requireValue(signature.length === 64 && verify('sha256', signedBytes(kind, document.keyId, payload),
    { key: createPublicKey({ key: decode(publicKey), type: 'spki', format: 'der' }), dsaEncoding: 'ieee-p1363' }, signature), 'Invalid ' + kind + ' signature');
  return strictParse(payload);
}

export function createSnapshot({ catalogBytes, delegationBytes, trustBytes, privateKeyBase64, previousBytes, now = new Date() }) {
  requireValue(catalogBytes.length <= MAX_FILE && delegationBytes.length <= MAX_FILE && trustBytes.length <= MAX_FILE, 'File too large');
  const catalog = strictParse(catalogBytes), delegated = strictParse(delegationBytes), trust = strictParse(trustBytes);
  requireValue(trust.format === 1 && trust.rootKeys && Object.keys(trust.rootKeys).length > 0, 'Root trust is missing');
  const rootCatalog = trust.rootKeys[catalog.keyId], rootDelegation = trust.rootKeys[delegated.keyId];
  requireValue(rootCatalog && rootDelegation, 'Unknown root key');
  const entries = readSigned(catalog, 'catalog', rootCatalog);
  const delegation = readSigned(delegated, 'delegation', rootDelegation);
  const utc = now.getTime(), notBefore = date(delegation.notBeforeUtc), delegatedUntil = date(delegation.expiresUtc);
  requireValue(delegation.schema === 1 && delegation.purpose === 'status' && /^[A-Za-z0-9_-]{1,96}$/.test(delegation.keyId)
    && delegation.maxStatusLifetimeHours > 0 && delegation.maxStatusLifetimeHours <= 72
    && utc >= notBefore && utc < delegatedUntil && delegatedUntil - notBefore <= 90 * 86400000, 'Invalid or expired status-key delegation');
  requireValue(entries.schema === 1 && Number.isSafeInteger(entries.revision) && entries.revision > 0
    && date(entries.issuedUtc) <= utc && Array.isArray(entries.entries) && entries.entries.length <= 10000, 'Invalid catalog');
  const ids = new Set();
  for (const item of entries.entries) {
    requireValue(/^[A-Za-z0-9_-]{1,96}$/.test(item.licenseId) && !ids.has(item.licenseId)
      && ['active', 'revoked'].includes(item.state) && Number.isSafeInteger(item.revision) && item.revision > 0
      && /^[A-F0-9]{64}$/.test(item.grantSha256)
      && item.grantPath === `v1/grants/${item.licenseId}/${item.revision}.json`, 'Invalid catalog entry');
    ids.add(item.licenseId);
  }
  const key = createPrivateKey({ key: decode(privateKeyBase64.trim()), type: 'pkcs8', format: 'der' });
  requireValue(key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1', 'Status key must be ECDSA P-256');
  requireValue(createPublicKey(key).export({ type: 'spki', format: 'der' }).equals(decode(delegation.publicKey)), 'Status Secret does not match current delegation');
  let previousSequence = 0;
  if (previousBytes) {
    requireValue(previousBytes.length <= MAX_FILE, 'Previous status too large');
    const previous = strictParse(previousBytes);
    // On rotation an older key's snapshot is allowed; root-signed catalog still controls authorization.
    if (previous.keyId === delegation.keyId) {
      const payload = readSigned(previous, 'status', delegation.publicKey);
      requireValue(Number.isSafeInteger(payload.sequence) && payload.sequence > 0 && payload.sequence < Number.MAX_SAFE_INTEGER, 'Invalid previous sequence');
      requireValue(payload.catalogRevision <= entries.revision, 'Catalog rollback detected'); previousSequence = payload.sequence;
    }
  }
  const sequence = Math.max(previousSequence + 1, utc);
  const payload = Buffer.from(JSON.stringify({ schema: 1, sequence, catalogRevision: entries.revision,
    catalogSha256: createHash('sha256').update(catalogBytes).digest('hex').toUpperCase(),
    issuedUtc: now.toISOString(), expiresUtc: new Date(Math.min(utc + delegation.maxStatusLifetimeHours * 3600000, delegatedUntil)).toISOString() }));
  return Buffer.from(JSON.stringify({ format: 1, kind: 'status', keyId: delegation.keyId, payload: payload.toString('base64'),
    signature: sign('sha256', signedBytes('status', delegation.keyId, payload), { key, dsaEncoding: 'ieee-p1363' }).toString('base64') }));
}

async function main() {
  const directory = resolve(process.argv[2] || '.');
  const key = process.env.TRADINGMEOW_STATUS_PRIVATE_KEY;
  requireValue(key, 'Configure TRADINGMEOW_STATUS_PRIVATE_KEY in repository Actions Secrets');
  const read = name => readFile(resolve(directory, 'v1', name));
  const bytes = createSnapshot({ catalogBytes: await read('catalog.json'), delegationBytes: await read('delegation.json'),
    trustBytes: await read('trust.json'), privateKeyBase64: key, previousBytes: await read('status.json').catch(error => { if (error.code === 'ENOENT') return null; throw error; }) });
  const temporary = resolve(directory, 'v1/status.json.pending'); await writeFile(temporary, bytes);
  await rename(temporary, resolve(directory, 'v1/status.json'));
  console.log('Signed authorization status refreshed. No license grants were changed.');
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
