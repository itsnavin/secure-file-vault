import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('guide is discoverable, separate from vault tabs, readable and accessible on desktop/mobile', async ({ page }) => {
  const errors = [];
  const requests = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('request', (request) => requests.push({ url: request.url(), method: request.method() }));
  await page.goto('./');
  await page.getByRole('link', { name: /Linux \/ OpenSSL guide/ }).click();
  await expect(page).toHaveTitle('Linux / OpenSSL guide — File Vault');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('From file to ciphertext.');
  await expect(page.getByRole('heading', { name: 'Two different formats. Not interchangeable.' })).toBeVisible();
  await expect(page.locator('.guide-warning').first()).toContainText('NO integrity or authentication');
  await expect(page.getByRole('tab')).toHaveCount(0);
  await expect(page.locator('body')).toHaveJSProperty('scrollWidth', await page.locator('body').evaluate((body) => body.clientWidth));
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.getByRole('link', { name: 'Every argument', exact: true }).click();
  await expect(page).toHaveURL(/#arguments$/);
  await expect(page.getByRole('heading', { name: 'Every argument, explained.' })).toBeInViewport();
  await page.getByText('Optional Base64 example (still unauthenticated CBC)', { exact: true }).click();
  await expect(page.locator('#base64-encrypt-command')).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.getByRole('link', { name: 'Back to browser vault', exact: false }).click();
  await expect(page.getByRole('tab', { name: 'Encrypt' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#password')).toHaveValue('');
  const origin = new URL(page.url()).origin;
  expect(requests.filter((request) => request.method !== 'GET' || !request.url.startsWith(origin))).toEqual([]);
  expect(errors).toEqual([]);
});

test('Copy requires a click and copies only exact displayed public commands', async ({ page }) => {
  await page.addInitScript(() => {
    window.testCopies = [];
    Object.defineProperty(navigator, 'clipboard', { value: {
      writeText: async (text) => { window.testCopies.push(text); },
    } });
  });
  await page.goto('./linux.html');
  expect(await page.evaluate(() => window.testCopies)).toEqual([]);
  for (const [name, id] of [
    ['Copy checks', 'version-command'], ['Copy setup', 'setup-command'],
    ['Copy sample', 'sample-command'], ['Copy encryption', 'encrypt-command'],
    ['Copy decryption', 'decrypt-command'], ['Copy comparison', 'compare-command'],
  ]) {
    await page.getByRole('button', { name, exact: true }).click();
    expect(await page.evaluate(() => window.testCopies.at(-1))).toBe(await page.locator(`#${id}`).textContent());
    await expect(page.getByRole('status')).toContainText('Public example copied');
  }
  expect(await page.evaluate(() => window.testCopies.length)).toBe(6);
});

test('clipboard denial has actionable manual-copy guidance without running commands', async ({ page }) => {
  await page.addInitScript(() => Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: async () => { throw new DOMException('Denied', 'NotAllowedError'); } },
  }));
  await page.goto('./linux.html');
  await page.getByRole('button', { name: 'Copy encryption', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('permission denied');
  await expect(page.locator('pre[aria-label="OpenSSL CBC file encryption command"]')).toBeFocused();
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })))
    .toEqual({ local: 0, session: 0 });
});
