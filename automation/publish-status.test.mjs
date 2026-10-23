import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, verify, createPublicKey } from 'node:crypto';
import { createSnapshot } from './publish-status.mjs';

const now = new Date('2026-10-21T12:00:00Z');
function signed(kind, keyId, value, privateKey) {
  const payload = Buffer.from(JSON.stringify(value));
  const bytes = Buffer.concat([Buffer.from(`TradingMeow.Licensing.v1\n${kind}\n${keyId}\n`), payload]);
  return { format: 1, kind, keyId, payload: payload.toString('base64'),
    signature: sign('sha256', bytes, { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64') };
}
const encode = value => Buffer.from(JSON.stringify(value));
const publicSpki = key => key.export({ format: 'der', type: 'spki' }).toString('base64');
const privatePkcs8 = key => key.export({ format: 'der', type: 'pkcs8' }).toString('base64');
function fixture() {
  const root = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const online = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const catalogValue = { schema: 1, revision: 2, issuedUtc: '2026-10-21T11:00:00Z', entries: [{
    licenseId: 'license_1', grantPath: 'v1/grants/license_1/1.json', grantSha256: 'A'.repeat(64), state: 'active', revision: 1 }] };
  const delegationValue = { schema: 1, keyId: 'online', publicKey: publicSpki(online.publicKey), purpose: 'status',
    notBeforeUtc: '2026-10-20T12:00:00Z', expiresUtc: '2026-12-20T12:00:00Z', maxStatusLifetimeHours: 72 };
  const input = {
    catalogBytes: encode(signed('catalog', 'root', catalogValue, root.privateKey)),
    delegationBytes: encode(signed('delegation', 'root', delegationValue, root.privateKey)),
    trustBytes: encode({ format: 1, rootKeys: { root: publicSpki(root.publicKey) }, githubOwner: 'test-owner', githubRepo: 'test-licenses', productId: 'stock' }),
    privateKeyBase64: privatePkcs8(online.privateKey), previousBytes: null, now,
  };
  return { root, online, catalogValue, delegationValue, input };
}

test('snapshot is signed by the delegated key and hashes exact catalog bytes', () => {
  const { input, online } = fixture();
  const document = JSON.parse(createSnapshot(input));
  const payloadBytes = Buffer.from(document.payload, 'base64');
  const payload = JSON.parse(payloadBytes);
  assert.equal(document.kind, 'status'); assert.equal(document.keyId, 'online');
  assert.equal(payload.catalogSha256, createHash('sha256').update(input.catalogBytes).digest('hex').toUpperCase());
  assert.equal(Date.parse(payload.expiresUtc) - Date.parse(payload.issuedUtc), 72 * 3600000);
  assert.ok(verify('sha256', Buffer.concat([Buffer.from('TradingMeow.Licensing.v1\nstatus\nonline\n'), payloadBytes]),
    { key: online.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(document.signature, 'base64')));
});

test('unrelated status private key cannot publish', () => {
  const { input } = fixture();
  const wrong = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  assert.throws(() => createSnapshot({ ...input, privateKeyBase64: privatePkcs8(wrong.privateKey) }), /does not match/);
});

test('catalog tamper and an unknown root are rejected', () => {
  const { input } = fixture();
  const changed = JSON.parse(input.catalogBytes);
  changed.payload = Buffer.from('{"schema":1,"revision":999,"entries":[]}').toString('base64');
  assert.throws(() => createSnapshot({ ...input, catalogBytes: encode(changed) }), /signature/);
  const trust = JSON.parse(input.trustBytes); trust.rootKeys = { different: Object.values(trust.rootKeys)[0] };
  assert.throws(() => createSnapshot({ ...input, trustBytes: encode(trust) }), /Unknown root/);
});

test('expired, future and overlong delegations cannot publish', () => {
  const { input, root, delegationValue } = fixture();
  for (const changes of [
    { expiresUtc: '2026-10-21T11:59:59Z' },
    { notBeforeUtc: '2026-10-21T12:01:00Z' },
    { expiresUtc: '2027-10-21T12:00:00Z' },
    { maxStatusLifetimeHours: 73 },
  ]) {
    const delegationBytes = encode(signed('delegation', 'root', { ...delegationValue, ...changes }, root.privateKey));
    assert.throws(() => createSnapshot({ ...input, delegationBytes }), /delegation/);
  }
});

test('a signing key delegated for another purpose cannot publish status', () => {
  const { input, root, delegationValue } = fixture();
  const delegationBytes = encode(signed('delegation', 'root', { ...delegationValue, purpose: 'grant' }, root.privateKey));
  assert.throws(() => createSnapshot({ ...input, delegationBytes }), /delegation/);
});

test('status lifetime is shortened to the delegation deadline', () => {
  const { input, root, delegationValue } = fixture();
  const expiresUtc = '2026-10-22T12:00:00Z';
  const delegationBytes = encode(signed('delegation', 'root', { ...delegationValue, expiresUtc }, root.privateKey));
  const output = JSON.parse(createSnapshot({ ...input, delegationBytes }));
  assert.equal(JSON.parse(Buffer.from(output.payload, 'base64')).expiresUtc, new Date(expiresUtc).toISOString());
});

test('same-key previous snapshot prevents catalog rollback and advances sequence', () => {
  const { input, root, catalogValue } = fixture();
  const previousBytes = createSnapshot(input);
  const first = JSON.parse(Buffer.from(JSON.parse(previousBytes).payload, 'base64'));
  const second = JSON.parse(Buffer.from(JSON.parse(createSnapshot({ ...input, previousBytes })).payload, 'base64'));
  assert.equal(second.sequence, first.sequence + 1);
  const catalogBytes = encode(signed('catalog', 'root', { ...catalogValue, revision: 1 }, root.privateKey));
  assert.throws(() => createSnapshot({ ...input, previousBytes, catalogBytes }), /rollback/);
});

test('future catalog, duplicate ids and traversal grant paths are rejected', () => {
  const { input, root, catalogValue } = fixture();
  for (const changes of [
    { issuedUtc: '2026-10-21T12:00:01Z' },
    { entries: [catalogValue.entries[0], catalogValue.entries[0]] },
    { entries: [{ ...catalogValue.entries[0], grantPath: '../private.json' }] },
  ]) {
    const catalogBytes = encode(signed('catalog', 'root', { ...catalogValue, ...changes }, root.privateKey));
    assert.throws(() => createSnapshot({ ...input, catalogBytes }), /catalog/);
  }
});

test('a status signature cannot be relabeled as a root-signed catalog', () => {
  const { input, online, catalogValue } = fixture();
  const catalogBytes = encode(signed('status', 'root', catalogValue, online.privateKey));
  assert.throws(() => createSnapshot({ ...input, catalogBytes }), /kind/);
});

test('duplicate properties in outer envelopes, trust and previous status are rejected', () => {
  const { input } = fixture();
  const duplicateFormat = bytes => Buffer.from(bytes.toString('utf8').replace('"format":1', '"format":1,"format":1'));
  assert.throws(() => createSnapshot({ ...input, catalogBytes: duplicateFormat(input.catalogBytes) }), /Duplicate JSON property/);
  assert.throws(() => createSnapshot({ ...input, delegationBytes: duplicateFormat(input.delegationBytes) }), /Duplicate JSON property/);
  assert.throws(() => createSnapshot({ ...input, trustBytes: duplicateFormat(input.trustBytes) }), /Duplicate JSON property/);
  const previousBytes = duplicateFormat(createSnapshot(input));
  assert.throws(() => createSnapshot({ ...input, previousBytes }), /Duplicate JSON property/);
});

test('correctly signed duplicate and escaped duplicate payload fields are rejected', () => {
  const { input, root, catalogValue } = fixture();
  for (const injected of ['"revision":2,"revision":2', '"revision":2,"revis\\u0069on":2']) {
    const raw = Buffer.from(JSON.stringify(catalogValue).replace('"revision":2', injected));
    const signature = sign('sha256', Buffer.concat([Buffer.from('TradingMeow.Licensing.v1\ncatalog\nroot\n'), raw]),
      { key: root.privateKey, dsaEncoding: 'ieee-p1363' });
    const catalogBytes = encode({ format: 1, kind: 'catalog', keyId: 'root', payload: raw.toString('base64'), signature: signature.toString('base64') });
    assert.throws(() => createSnapshot({ ...input, catalogBytes }), /Duplicate JSON property/);
  }
});
