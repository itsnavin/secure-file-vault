import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const guide = await readFile(new URL('../linux.html', import.meta.url), 'utf8');
const app = await readFile(new URL('../index.html', import.meta.url), 'utf8');
const decode = (text) => text.replaceAll('&amp;', '&').replaceAll('&gt;', '>').replaceAll('&lt;', '<');
const commands = new Map([...guide.matchAll(/<code id="([^"]+-command)">([\s\S]*?)<\/code>/g)]
  .map(([, id, text]) => [id, decode(text)]));
const base = 'openssl enc -aes-256-cbc';
const kdf = '-pbkdf2 -iter 600000 -md sha256 -salt';
const flatten = (text) => text.replace(/\s*\\\r?\n\s*/g, ' ');

test('guide examples have exact matched crypto settings and no embedded passwords', () => {
  assert.equal(commands.size, 8);
  assert.equal(flatten(commands.get('encrypt-command')),
    `${base} -e ${kdf} -in './original.bin' -out './original.bin.enc'`);
  assert.equal(flatten(commands.get('decrypt-command')),
    `${base} -d ${kdf} -in './original.bin.enc' -out './recovered.bin'`);
  assert.equal(flatten(commands.get('base64-encrypt-command')),
    `${base} -e ${kdf} -a -in './original.bin' -out './original.bin.enc.b64'`);
  assert.equal(flatten(commands.get('base64-decrypt-command')),
    `${base} -d ${kdf} -a -in './original.bin.enc.b64' -out './recovered-base64.bin'`);
  for (const command of commands.values()) {
    assert.doesNotMatch(command, /-pass\b|-k\b|-K\b|-iv\b|-S\b|-nosalt\b|-nopad\b|-saltlen\b|-md md5|-ecb|\brm\b|\bsudo\b/);
  }
  assert.match(commands.get('version-command'), /openssl version\r?\nopenssl enc -help/);
  assert.match(commands.get('setup-command'), /umask 077/);
  assert.match(commands.get('setup-command'), /mktemp -d/);
  assert.match(commands.get('compare-command'), /cmp .* && printf/);
});

test('guide includes flow, complete flag explanations and prominent compatibility/authentication warnings', () => {
  for (const text of [
    'You cannot decrypt this site’s', 'This site cannot decrypt OpenSSL',
    'NO integrity or authentication', 'only for learning / existing OpenSSL compatibility',
    '600,000 iterations', '16-byte salt', '12-byte nonce', '128-bit tag',
    '32-byte AES key and 16-byte CBC IV', 'not a self-describing authenticated container',
    'partial or garbage plaintext', 'exit status of zero with changed plaintext',
    'Lost passphrases cannot be recovered', 'overwrites an existing file',
    'not a file integrity hash', 'about one third',
  ]) assert.ok(guide.includes(text), `Missing guide content: ${text}`);
  for (const flag of ['openssl', 'enc', '-aes-256-cbc', '-e', '-d', '-pbkdf2', '-iter 600000', '-md sha256', '-salt', "-in '…'", "-out '…'", '-a']) {
    assert.ok(guide.includes(`<th scope="row"><code>${flag}</code>`), `Missing explanation: ${flag}`);
  }
  assert.match(guide, /<ol class="flow"/);
  assert.match(guide, /<ol class="flow terminal-flow"/);
});

test('guide navigation and references point to existing local targets and official docs', async () => {
  assert.match(app, /href="\.\/linux\.html"/);
  assert.match(guide, /href="\.\/">← Back to browser vault/);
  for (const [, hash] of guide.matchAll(/href="#([^"]+)"/g)) {
    assert.ok(guide.includes(`id="${hash}"`), `Missing anchor: ${hash}`);
  }
  const ids = [...guide.matchAll(/\bid="([^"]+)"/g)].map(([, id]) => id);
  assert.equal(new Set(ids).size, ids.length);
  const copyTargets = [...guide.matchAll(/data-copy="([^"]+)"/g)].map(([, id]) => id);
  assert.deepEqual(copyTargets.sort(), [...commands.keys()].sort());
  const references = [...guide.matchAll(/href="(https:[^"]+)"/g)].map(([, url]) => new URL(url));
  assert.ok(references.some((url) => url.host === 'docs.openssl.org' && url.pathname.startsWith('/3.0/')));
  assert.ok(references.some((url) => url.host === 'docs.openssl.org' && url.pathname.startsWith('/3.5/')));
  for (const path of ['../src/guide.js', '../src/guide.css']) await readFile(new URL(path, import.meta.url));
  const build = await readFile(new URL('../tools/build.mjs', import.meta.url), 'utf8');
  assert.ok(build.includes("'linux.html'"));
});

test('guide scripts copy public commands only on explicit action; no execution, uploads or persistence', async () => {
  const source = await readFile(new URL('../src/guide.js', import.meta.url), 'utf8');
  assert.match(source, /button\.addEventListener\('click'/);
  assert.match(source, /writeText\(command\.textContent\)/);
  assert.match(source, /permission denied/);
  assert.doesNotMatch(source, /\b(eval|Function|fetch|XMLHttpRequest|WebSocket|localStorage|sessionStorage|indexedDB|innerHTML)\b/);
  assert.ok(guide.includes("connect-src 'none'"));
  assert.ok(guide.includes("worker-src 'none'"));
});
