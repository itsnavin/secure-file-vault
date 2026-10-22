import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash, createCipheriv, createDecipheriv, pbkdf2Sync } from 'node:crypto';
import { encrypt, decrypt, parseHeader, safeName, utf8, decodeText, MAX_FILE, MAX_TEXT, MAX_CONTAINER, ITERATIONS } from '../src/crypto.js';
import { sealReference, openReference, publicPassword, publicText } from '../tools/reference.mjs';
const bytes = (text) => new TextEncoder().encode(text);
const password = publicPassword;

for (const bits of [256, 128]) {
  test(`AES-${bits}: binary, empty file, empty text, Unicode, independent Node interoperability`, async () => {
    for (const [data, kind] of [
      [new Uint8Array([0, 255, 254, 1, 128, 13, 10]), 0],
      [new Uint8Array(), 0], [new Uint8Array(), 1],
      [bytes(publicText), 1],
    ]) {
      const vault = await encrypt({ data, password, bits, kind, name: 'public.bin' });
      assert.equal(parseHeader(vault).bits, bits);
      assert.equal(parseHeader(vault).iterations, ITERATIONS);
      const opened = await decrypt({ data: vault, password });
      assert.deepEqual(opened.data, data);
      assert.equal(opened.kind, kind);
      assert.equal(opened.name, 'public.bin');
      assert.deepEqual(new Uint8Array(openReference(vault, password).data), data);
      const reference = sealReference({ data, password, bits, kind, name: 'public.bin' });
      assert.deepEqual((await decrypt({ data: new Uint8Array(reference), password })).data, data);
    }
  });
  test(`AES-${bits}: deterministic public cross-runtime fixture`, async () => {
    const fixture = JSON.parse(await readFile(new URL(`./fixtures/aes-${bits}.json`, import.meta.url)));
    const reference = sealReference({
      data: bytes(publicText), password, bits, salt: Buffer.from(fixture.saltHex, 'hex'),
      nonce: Buffer.from(fixture.nonceHex, 'hex'),
    });
    assert.equal(reference.toString('hex'), fixture.containerHex);
    assert.equal(createHash('sha256').update(reference).digest('hex'), fixture.sha256);
    assert.equal(decodeText((await decrypt({ data: new Uint8Array(reference), password })).data), publicText);
  });
}

test('fresh independent salt and nonce for every operation', async () => {
  const a = await encrypt({ data: bytes('public'), password });
  const b = await encrypt({ data: bytes('public'), password });
  assert.notDeepEqual(a, b);
  assert.notDeepEqual(a.slice(16, 32), b.slice(16, 32));
  assert.notDeepEqual(a.slice(32, 44), b.slice(32, 44));
});

test('every header byte, ciphertext byte, and tag byte is protected', async () => {
  const vault = await encrypt({ data: bytes('public'), password });
  for (let offset = 0; offset < vault.length; offset++) {
    const modified = vault.slice();
    modified[offset] ^= 1;
    await assert.rejects(decrypt({ data: modified, password }), `byte ${offset} must reject`);
  }
  const alternateCipher = vault.slice();
  alternateCipher[9] = 2; // Valid alternate ID must still authenticate.
  await assert.rejects(decrypt({ data: alternateCipher, password }), /Authentication failed/);
});

test('wrong password, whitespace, case, normalization, corruption release no plaintext', async () => {
  const vault = await encrypt({ data: bytes('public'), password: ' Public café test ' });
  for (const wrong of ['Public café test', ' public café test ', ' Public cafe\u0301 test ']) {
    await assert.rejects(decrypt({ data: vault, password: wrong }), /Authentication failed/);
  }
  await assert.rejects(decrypt({ data: vault, password: 'wrong public password' }), /Authentication failed/);
});

test('reject malformed lengths, unknown IDs, KDF downgrade/high costs before deriving', async () => {
  const vault = await encrypt({ data: bytes('public'), password });
  const oldDerive = crypto.subtle.deriveKey;
  let calls = 0;
  crypto.subtle.deriveKey = function (...args) { calls++; return oldDerive.apply(this, args); };
  try {
    const variants = [
      new Uint8Array(), vault.slice(0, 70), vault.slice(0, -1),
      new Uint8Array(MAX_CONTAINER + 1),
      new Uint8Array([...vault, 0]), new Uint8Array([...vault, ...vault]),
    ];
    for (const [offset, value] of [[0, 0], [8, 0], [8, 2], [9, 0], [9, 3], [10, 2], [11, 1]]) {
      const copy = vault.slice(); copy[offset] = value; variants.push(copy);
    }
    for (const iterations of [0, 1, 599999, 600001, 1000000, 0xffffffff]) {
      const copy = vault.slice(); new DataView(copy.buffer).setUint32(12, iterations); variants.push(copy);
    }
    for (const length of [0, 16, 0xffffffff]) {
      const copy = vault.slice(); new DataView(copy.buffer).setUint32(44, length); variants.push(copy);
    }
    for (const data of variants) await assert.rejects(decrypt({ data, password }));
    assert.equal(calls, 0);
  } finally { crypto.subtle.deriveKey = oldDerive; }
});

test('input and UTF-8 byte limits; no normalization or replacement', async () => {
  await assert.rejects(encrypt({ data: new Uint8Array(MAX_FILE + 1), password, kind: 0 }), /limit/);
  await assert.rejects(encrypt({ data: new Uint8Array(MAX_TEXT + 1), password, kind: 1 }), /limit/);
  await assert.rejects(encrypt({ data: bytes('public'), password: 'short' }), /12 characters/);
  await assert.rejects(encrypt({ data: bytes('public'), password: '🔑'.repeat(300) }), /byte limit/);
  await assert.rejects(encrypt({ data: bytes('public'), password: 'PUBLIC invalid \ud800' }), /Unicode/);
  await assert.rejects(encrypt({ data: new Uint8Array([255]), password, kind: 1 }));
  await assert.rejects(encrypt({ data: bytes('public'), password, bits: 192 }), /Unsupported/);
  assert.throws(() => utf8('é'.repeat(8), 15, 'Test'), /byte limit/);
  assert.throws(() => utf8('\udc00', 10, 'Test'), /Unicode/);
  assert.equal(decodeText(bytes('\ufeffpublic')), '\ufeffpublic');
  assert.throws(() => decodeText(new Uint8Array([0xc0, 0xaf])));
});

test('exact maximum-size binary output is bounded and independently recoverable', async () => {
  const data = new Uint8Array(MAX_FILE);
  data[0] = 255; data[data.length - 1] = 127;
  const vault = await encrypt({ data, password, kind: 0, name: '😀'.repeat(100) });
  assert.ok(vault.length <= MAX_CONTAINER);
  assert.deepEqual(new Uint8Array(openReference(vault, password).data), data);
});

test('authenticated malformed payloads and invalid UTF-8 rejected', async () => {
  // Reference encoder permits deliberately invalid payload kinds/text for negative testing.
  for (const reference of [
    sealReference({ data: bytes('public'), password, kind: 2 }),
    sealReference({ data: Buffer.from([255]), password, kind: 1 }),
  ]) await assert.rejects(decrypt({ data: new Uint8Array(reference), password }));
  const valid = sealReference({ data: bytes('public'), password });
  const key = pbkdf2Sync(password, valid.subarray(16, 32), 600000, 32, 'sha256');
  const decipher = createDecipheriv('aes-256-gcm', key, valid.subarray(32, 44));
  decipher.setAAD(valid.subarray(0, 48));
  decipher.setAuthTag(valid.subarray(-16));
  const payload = Buffer.concat([decipher.update(valid.subarray(48, -16)), decipher.final()]);
  for (const mutate of [
    (inner) => inner.writeUInt16BE(241, 1),
    (inner) => inner.writeUInt16BE(0xffff, 1),
    (inner) => inner.writeUInt32BE(0, 3),
    (inner) => inner.writeUInt32BE(MAX_TEXT + 1, 3),
    (inner) => inner.writeUInt32BE(0xffffffff, 3),
    (inner) => { inner[7] = 255; },
  ]) {
    const inner = Buffer.from(payload);
    mutate(inner);
    // Reuse here is confined to public negative test vectors, never app encryption.
    const cipher = createCipheriv('aes-256-gcm', key, valid.subarray(32, 44));
    cipher.setAAD(valid.subarray(0, 48));
    const forged = Buffer.concat([valid.subarray(0, 48), cipher.update(inner), cipher.final(), cipher.getAuthTag()]);
    await assert.rejects(decrypt({ data: new Uint8Array(forged), password }));
  }
  key.fill(0);
});

test('filenames are inert, bounded, path/control/reserved-character sanitized', () => {
  for (const name of ['../../private.html', 'CON.txt', 'NUL', ' . ', 'a\u0000\u202eb.svg', '🔐'.repeat(200)]) {
    const clean = safeName(name);
    assert.ok(clean.length > 0);
    assert.ok(bytes(clean).length <= 240);
    assert.doesNotMatch(clean, /[<>:"/\\|?*\u0000-\u001f\u202a-\u202e]/);
    assert.doesNotMatch(clean, /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i);
  }
});

test('NIST AES-GCM known-answer vectors, 128- and 256-bit zero key / nonce / block', async () => {
  for (const [bits, expected] of [
    [128, '0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf'],
    [256, 'cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919'],
  ]) {
    const key = await crypto.subtle.importKey('raw', new Uint8Array(bits / 8), 'AES-GCM', false, ['encrypt']);
    const output = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12), tagLength: 128 }, key, new Uint8Array(16));
    assert.equal(Buffer.from(output).toString('hex'), expected);
  }
});

test('PBKDF2-HMAC-SHA-256 known-answer vector (RFC 7914 section 11)', async () => {
  const key = await crypto.subtle.importKey('raw', bytes('passwd'), 'PBKDF2', false, ['deriveBits']);
  const output = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: bytes('salt'), iterations: 1 }, key, 512);
  assert.equal(Buffer.from(output).toString('hex'), '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783');
});

test('maximum UTF-8 text bytes are recoverable without exceeding container limit', async () => {
  const data = bytes('é'.repeat(MAX_TEXT / 2));
  const vault = await encrypt({ data, password, kind: 1 });
  assert.deepEqual((await decrypt({ data: vault, password })).data, data);
});

test('runtime source has no persistence, upload, clipboard, unsafe rendering or weak randomness', async () => {
  for (const path of ['app.js', 'worker.js', 'crypto.js']) {
    const source = await readFile(new URL(`../src/${path}`, import.meta.url), 'utf8');
    assert.doesNotMatch(source, /\b(localStorage|sessionStorage|indexedDB|fetch|XMLHttpRequest|WebSocket|sendBeacon|clipboard|innerHTML|outerHTML|eval)\b|Math\.random|console\./);
  }
});
