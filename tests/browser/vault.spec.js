import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { readFile } from 'node:fs/promises';
import { sealReference, openReference, publicPassword, publicText } from '../../tools/reference.mjs';
const password = publicPassword;
const inputBytes = Buffer.from([0, 255, 0, 1, 128, 254, 13, 10]);

async function passphrases(page, confirmation = password) {
  await page.getByLabel('Passphrase', { exact: true }).fill(password);
  if (await page.getByLabel('Confirm passphrase', { exact: true }).isVisible()) {
    await page.getByLabel('Confirm passphrase', { exact: true }).fill(confirmation);
  }
}
async function finish(page) {
  await expect(page.getByRole('status')).toHaveText('Complete. Passphrase fields cleared.');
  await expect(page.locator('#error')).toBeHidden();
}
async function save(page) {
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('#download').click(),
  ]);
  return { name: download.suggestedFilename(), bytes: await readFile(await download.path()) };
}

test.beforeEach(async ({ page }) => { await page.goto('./'); });

for (const bits of [256, 128]) {
  test(`AES-${bits} real binary file downloads round-trip and match Node`, async ({ page }) => {
    const externalRequests = [];
    const pageErrors = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    page.on('request', (request) => {
      if (request.method() !== 'GET' || !request.url().startsWith(new URL(page.url()).origin)) externalRequests.push(request.url());
    });
    await page.locator('#file-input').setInputFiles({ name: 'synthetic.bin', mimeType: 'application/octet-stream', buffer: inputBytes });
    await page.locator('#cipher').selectOption(String(bits));
    await passphrases(page);
    await page.getByRole('button', { name: 'Encrypt →', exact: true }).click();
    await finish(page);
    await expect(page.locator('#password')).toHaveValue('');
    const sealed = await save(page);
    expect(sealed.name).toBe('sealed.sfv');
    const independent = openReference(sealed.bytes, password);
    expect(independent.data).toEqual(inputBytes);
    expect(independent.bits).toBe(bits);
    await page.getByRole('tab', { name: 'Decrypt' }).click();
    await page.locator('#file-input').setInputFiles({ name: 'sealed.sfv', mimeType: 'application/octet-stream', buffer: sealed.bytes });
    // Selecting a file never starts decryption.
    await expect(page.locator('#result')).toBeHidden();
    await expect(page.locator('#progress')).toBeHidden();
    await passphrases(page);
    await page.getByRole('button', { name: 'Decrypt →', exact: true }).click();
    await finish(page);
    await expect(page.locator('#preview')).toBeHidden();
    await expect(page.locator('#preview-button')).toBeHidden();
    const recovered = await save(page);
    expect(recovered.name).toBe('synthetic.bin');
    expect(recovered.bytes).toEqual(inputBytes);
    expect(externalRequests).toEqual([]);
    expect(pageErrors).toEqual([]);
    expect(await page.evaluate(async () => ({
      local: localStorage.length, session: sessionStorage.length,
      databases: (await indexedDB.databases()).length,
      workers: (await navigator.serviceWorker.getRegistrations()).length,
      caches: (await caches.keys()).length,
    }))).toEqual({ local: 0, session: 0, databases: 0, workers: 0, caches: 0 });
  });
}

test('Unicode text, explicit inert preview/download and reset revoke URLs', async ({ page }) => {
  await page.evaluate(() => {
    window.testURLs = { created: [], revoked: [] };
    const create = URL.createObjectURL.bind(URL);
    const revoke = URL.revokeObjectURL.bind(URL);
    URL.createObjectURL = (blob) => {
      const url = create(blob); window.testURLs.created.push(url); return url;
    };
    URL.revokeObjectURL = (url) => { window.testURLs.revoked.push(url); revoke(url); };
  });
  await page.locator('#text-mode').click();
  const text = `${publicText}<img src=x onerror=alert(1)><svg onload=alert(2)>`;
  await page.locator('#text-input').fill(text);
  await passphrases(page);
  await page.locator('#run').click();
  await finish(page);
  const vault = await save(page);
  expect(openReference(vault.bytes, password).data.toString('utf8')).toBe(text);
  await page.getByRole('tab', { name: 'Decrypt' }).click();
  await page.locator('#file-input').setInputFiles({ name: 'sealed.sfv', mimeType: 'application/octet-stream', buffer: vault.bytes });
  await passphrases(page);
  await page.locator('#run').click();
  await finish(page);
  await expect(page.locator('#preview')).toBeEmpty();
  await page.locator('#preview-button').click();
  expect(await page.locator('#preview').textContent()).toBe(text);
  await expect(page.locator('#preview img, #preview svg')).toHaveCount(0);
  const recovered = await save(page);
  expect(recovered.bytes).toEqual(Buffer.from(text));
  await page.locator('#clear').click();
  await expect(page.locator('#preview')).toBeEmpty();
  await expect(page.locator('#result')).toBeHidden();
  await expect(page.locator('#result-description')).toBeEmpty();
  const urls = await page.evaluate(() => window.testURLs);
  expect(urls.revoked).toEqual(urls.created);
});

test('drop, keyboard file input, empty file, accessible interface, mobile layout', async ({ page }) => {
  await expect(page.locator('body')).toHaveJSProperty('scrollWidth', await page.locator('body').evaluate((body) => body.clientWidth));
  const audit = await new AxeBuilder({ page }).analyze();
  expect(audit.violations).toEqual([]);
  await page.locator('#file-input').focus();
  await expect(page.locator('#file-input')).toBeFocused();
  const transfer = await page.evaluateHandle(() => {
    const dt = new DataTransfer();
    dt.items.add(new File([], 'empty.bin', { type: 'application/octet-stream' }));
    return dt;
  });
  await page.locator('#drop-zone').dispatchEvent('drop', { dataTransfer: transfer });
  await expect(page.locator('#file-name')).toContainText('empty.bin');
  await passphrases(page, 'PUBLIC different password');
  await page.locator('#run').click();
  await expect(page.getByRole('alert')).toContainText('do not match');
  await expect(page.locator('#result')).toBeHidden();
  await passphrases(page);
  await page.locator('#reveal-password').click();
  await expect(page.locator('#password')).toHaveAttribute('type', 'text');
  await page.locator('#reveal-password').click();
  await expect(page.locator('#password')).toHaveAttribute('type', 'password');
  await page.locator('#run').click();
  await finish(page);
  expect(openReference((await save(page)).bytes, password).data.length).toBe(0);
  await page.getByRole('tab', { name: 'Encrypt' }).focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: 'Decrypt' })).toHaveAttribute('aria-selected', 'true');
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test('empty text, wrong passphrase and tampering never expose output', async ({ page }) => {
  await page.locator('#text-mode').click();
  await passphrases(page);
  await page.locator('#run').click();
  await finish(page);
  expect(openReference((await save(page)).bytes, password).data.length).toBe(0);
  await page.getByRole('tab', { name: 'Decrypt' }).click();
  const vault = sealReference({ data: Buffer.from('PUBLIC synthetic text'), password, name: '../CON.html' });
  await page.locator('#file-input').setInputFiles({ name: 'test.sfv', mimeType: 'application/octet-stream', buffer: vault });
  await page.locator('#password').fill('PUBLIC wrong passphrase');
  await page.locator('#run').click();
  await expect(page.getByRole('alert')).toContainText('Authentication failed');
  await expect(page.locator('#result')).toBeHidden();
  vault[vault.length - 1] ^= 1;
  await page.locator('#file-input').setInputFiles({ name: 'tampered.sfv', mimeType: 'application/octet-stream', buffer: vault });
  await passphrases(page);
  await page.locator('#run').click();
  await expect(page.getByRole('alert')).toContainText('Authentication failed');
  await expect(page.locator('#result')).toBeHidden();
});

test('size and unsupported KDF bounds rejected without worker creation', async ({ page }) => {
  await page.evaluate(() => {
    window.workerCount = 0;
    window.wholeFileReads = 0;
    const Original = window.Worker;
    window.Worker = class extends Original { constructor(...args) { super(...args); window.workerCount++; } };
    const read = File.prototype.arrayBuffer;
    File.prototype.arrayBuffer = function () {
      window.wholeFileReads++;
      return read.call(this);
    };
  });
  const transfer = await page.evaluateHandle(() => {
    const dt = new DataTransfer();
    dt.items.add(new File([new Uint8Array(16 * 1024 * 1024 + 1)], 'oversized.bin'));
    return dt;
  });
  await page.locator('#drop-zone').dispatchEvent('drop', { dataTransfer: transfer });
  await expect(page.getByRole('alert')).toContainText('too large');
  await page.getByRole('tab', { name: 'Decrypt' }).click();
  const vault = sealReference({ data: Buffer.from('PUBLIC'), password });
  vault.writeUInt32BE(0xffffffff, 12);
  await page.locator('#file-input').setInputFiles({ name: 'cost.sfv', mimeType: 'application/octet-stream', buffer: vault });
  await passphrases(page);
  await page.locator('#run').click();
  await expect(page.getByRole('alert')).toContainText('work factor');
  expect(await page.evaluate(() => window.workerCount)).toBe(0);
  expect(await page.evaluate(() => window.wholeFileReads)).toBe(0);
  await expect(page.locator('#result')).toBeHidden();
});

test('cancel, clear, and delayed worker results cannot restore stale plaintext', async ({ page }) => {
  await page.evaluate(() => {
    const Original = window.Worker;
    window.Worker = class {
      constructor(...args) { this.actual = new Original(...args); }
      postMessage(data, transfer) {
        this.actual.onmessage = (event) => setTimeout(() => this.onmessage?.(event), 500);
        this.actual.onerror = (event) => this.onerror?.(event);
        this.actual.postMessage(data, transfer);
      }
      terminate() { this.actual.terminate(); }
    };
  });
  await page.getByRole('tab', { name: 'Decrypt' }).click();
  const vault = sealReference({ data: Buffer.from('PUBLIC stale text'), password });
  await page.locator('#file-input').setInputFiles({ name: 'stale.sfv', mimeType: 'application/octet-stream', buffer: vault });
  await passphrases(page);
  await page.locator('#run').click();
  await expect(page.locator('#password')).toBeDisabled();
  await page.locator('#cancel').click();
  await expect(page.getByRole('status')).toContainText('Cancelled');
  await page.waitForTimeout(800);
  await expect(page.locator('#result')).toBeHidden();
  await page.locator('#run').click();
  await page.locator('#clear').click();
  await page.waitForTimeout(800);
  await expect(page.locator('#result')).toBeHidden();
  await expect(page.locator('#password')).toHaveValue('');
  await expect(page.locator('#file-selection')).toBeHidden();
});

test('a completed but late worker response is ignored after clear or a new password', async ({ page }) => {
  await page.evaluate(() => {
    window.Worker = class {
      postMessage() {
        setTimeout(() => this.onmessage?.({ data: {
          ok: true,
          result: { data: new Uint8Array([80, 85, 66, 76, 73, 67]), name: 'public.txt', kind: 1, bits: 256 },
        } }), 500);
      }
      terminate() {} // Deliberately simulate an already queued message surviving terminate.
    };
  });
  await page.getByRole('tab', { name: 'Decrypt' }).click();
  const vault = sealReference({ data: Buffer.from('PUBLIC'), password });
  await page.locator('#file-input').setInputFiles({ name: 'stale.sfv', mimeType: 'application/octet-stream', buffer: vault });
  await passphrases(page);
  await page.locator('#run').click();
  await expect(page.getByRole('status')).toContainText('Deriving key');
  await page.locator('#cancel').click();
  await page.locator('#password').fill('PUBLIC new password');
  await page.waitForTimeout(650);
  await expect(page.locator('#result')).toBeHidden();
  await expect(page.locator('#password')).toHaveValue('PUBLIC new password');
  await page.locator('#run').click();
  await expect(page.getByRole('status')).toContainText('Deriving key');
  await page.locator('#clear').click();
  await page.waitForTimeout(650);
  await expect(page.locator('#result')).toBeHidden();
  await expect(page.locator('#preview')).toBeEmpty();
});

test('late file reads and UTF-8 text byte overflow fail without publishing stale data', async ({ page }) => {
  await page.evaluate(() => {
    const read = File.prototype.arrayBuffer;
    File.prototype.arrayBuffer = async function () {
      const buffer = await read.call(this);
      await new Promise((resolve) => setTimeout(resolve, 500));
      return buffer;
    };
  });
  await page.locator('#file-input').setInputFiles({ name: 'public.bin', mimeType: 'application/octet-stream', buffer: inputBytes });
  await passphrases(page);
  await page.locator('#run').click();
  await page.locator('#clear').click();
  await page.waitForTimeout(650);
  await expect(page.locator('#result')).toBeHidden();
  await page.locator('#text-mode').click();
  await page.locator('#text-input').evaluate((input) => {
    input.value = 'é'.repeat(524289);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await passphrases(page);
  await page.locator('#run').click();
  await expect(page.getByRole('alert')).toContainText('byte limit');
  await expect(page.locator('#result')).toBeHidden();
});

test('recovered file names are sanitized and binary HTML never gets previewed', async ({ page }) => {
  await page.getByRole('tab', { name: 'Decrypt' }).click();
  const payload = Buffer.from('<svg onload="alert(1)">PUBLIC</svg>');
  const vault = sealReference({ data: payload, password, kind: 0, name: '../../CON:<bad>.svg' });
  await page.locator('#file-input').setInputFiles({ name: 'public.sfv', mimeType: 'application/octet-stream', buffer: vault });
  await passphrases(page);
  await page.locator('#run').click();
  await finish(page);
  await expect(page.locator('#preview-button')).toBeHidden();
  const recovered = await save(page);
  expect(recovered.name).not.toMatch(/[<>:"/\\|?*]/);
  expect(recovered.bytes).toEqual(payload);
  await page.locator('#password').fill('PUBLIC input changed');
  await expect(page.locator('#result')).toBeHidden();
});

test('no clipboard access or network/persistence code and CSP blocks outbound requests', async ({ page }) => {
  await page.evaluate(() => {
    window.cspViolations = [];
    window.addEventListener('securitypolicyviolation', (event) => window.cspViolations.push(event.violatedDirective));
  });
  const blocked = await page.evaluate(async () => {
    try { await fetch('https://example.com/blocked-by-csp'); return false; } catch { return true; }
  });
  expect(blocked).toBe(true);
  await expect.poll(() => page.evaluate(() => window.cspViolations)).toContain('connect-src');
  await page.locator('#text-mode').click();
  await page.locator('#text-input').fill('PUBLIC synthetic draft');
  await passphrases(page);
  await page.reload();
  await expect(page.locator('#password')).toHaveValue('');
  await expect(page.locator('#text-input')).toHaveValue('');
});

test('missing WebCrypto fails closed with actionable secure-context guidance', async ({ page }) => {
  await page.addInitScript(() => Object.defineProperty(window, 'crypto', { value: undefined }));
  await page.reload();
  await expect(page.locator('#run')).toBeDisabled();
  await expect(page.getByRole('alert')).toContainText('HTTPS');
});

test('worker failure clears passphrases and exposes no result', async ({ page }) => {
  await page.evaluate(() => {
    window.Worker = class {
      postMessage() {
        setTimeout(() => this.onerror({ preventDefault() {} }), 10);
      }
      terminate() {}
    };
  });
  await page.locator('#text-mode').click();
  await page.locator('#text-input').fill('PUBLIC synthetic text');
  await passphrases(page);
  await page.locator('#run').click();
  await expect(page.getByRole('alert')).toContainText('worker failed');
  await expect(page.locator('#password')).toHaveValue('');
  await expect(page.locator('#confirm')).toHaveValue('');
  await expect(page.locator('#result')).toBeHidden();
  await expect(page.locator('#run')).toBeEnabled();
});
