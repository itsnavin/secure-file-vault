# File Vault

**[Open File Vault](https://itsnavin.github.io/secure-file-vault/)** -- browser-local file and text encryption with an original Material-inspired interface. No account, backend, uploads, telemetry, remote scripts, fonts, or runtime dependencies.

## Use it

1. Choose **Encrypt**, then drop/browse one file or select **Text**.
2. Keep the default **AES-256-GCM**, or choose **AES-128-GCM**. Use a strong, unique passphrase of at least 12 characters and confirm it. Length alone does not guarantee strength.
3. Click **Encrypt**, then **Download encrypted file**. Save `sealed.sfv` and keep the passphrase separately. **There is no password recovery.** Keep a tested backup.
4. To recover it, choose **Decrypt**, select the vault, enter the exact original passphrase, and click **Decrypt**. Nothing decrypts merely by selecting/dropping a file. Download recovered bytes explicitly. Text created with Text mode also has an explicit inert preview.

Spaces, case, Unicode normalization and a UTF-8 BOM are significant; passwords are never trimmed or normalized. Invalid/unpaired Unicode surrogates are rejected rather than silently substituted. Passphrases are limited to 1,024 UTF-8 bytes. Successful and worker-failed operations clear passphrase fields. The vault never copies private content to the clipboard; the separate Linux guide can copy public example commands only after a click. Recovered files may be malicious: download and open deliberately.

**Not OpenSSL `enc` compatible.** OpenSSL's `enc` interface does not support GCM. This application uses its own documented authenticated format, not an OpenSSL wrapper. AES-GCM is an established authenticated cipher, not a claim to be the universally "newest" or "best" encryption.

## Linux / OpenSSL learning guide

Open the in-app **[Linux / OpenSSL guide](https://itsnavin.github.io/secure-file-vault/linux.html)** from the vault's introduction. It explains both encryption flows, interactive passphrase prompts, exact file encryption/decryption commands, every command argument, optional Base64, shell quoting, isolated practice files, permissions, backups, version differences and failure cases. Copy buttons copy only the public displayed snippet after an explicit click; no commands are executed by the browser.

**The external terminal example is unauthenticated AES-256-CBC for learning / existing OpenSSL compatibility only.** Its `enc` output cannot be opened by this site's SFV reader; SFV downloads cannot be opened by `openssl enc`. CBC ciphertext can be maliciously modified and still decrypt without an error. Wrong-password errors are not a reliable integrity/password check, and OpenSSL may write partial or garbage plaintext even on failure. Keep important data in an established authenticated format instead. The guide does not introduce an untested CMS certificate workflow or imply that a round trip proves security.

The core commands use `openssl enc -aes-256-cbc -e` (or `-d`) with `-pbkdf2 -iter 600000 -md sha256 -salt`, distinct `-in`/`-out` filenames and no password arguments. Official OpenSSL 3.0 and 3.5 docs were reviewed on **2026-10-22**; neither example uses the newer `-saltlen` flag unavailable in 3.0. On Linux, run `python3 tests/openssl_guide.py` to execute the **actual snippets extracted from the page** in private temporary directories and pseudo-terminals with synthetic public passphrases. It checks interactive encryption confirmation, binary/Base64 round trips, private file permissions, CBC malleability (modified bytes with status 0), and a wrong-passphrase failure that leaves output, without claiming every wrong password will fail. It prints the exact installed OpenSSL version. The guide was locally exercised on Ubuntu 24.04 / OpenSSL **3.0.13 (30 Jan 2024)**; CI repeats it on its own installed Linux version. Patch-level age alone does not establish distribution support status: keep your vendor's package updated.

## Security model and limits

Native WebCrypto performs AES-GCM with a 128-bit authentication tag. Every encryption obtains a **fresh independent 16-byte salt and 12-byte nonce** from `crypto.getRandomValues`. Password-derived keys use **PBKDF2-HMAC-SHA-256, exactly 600,000 iterations**, matching OWASP's published minimum for PBKDF2-SHA-256 reviewed on **2026-10-22**. OWASP generally prefers Argon2id; native WebCrypto has PBKDF2, not Argon2id. PBKDF2 is **not memory-hard**. This choice does not imply FIPS certification. There is no weaker fallback or automatic algorithm negotiation. V1 rejects any other iteration count before key derivation; a future policy change needs an explicit new supported format policy, not silently weakening old vaults.

The complete header is authenticated as additional authenticated data (AAD). Original filenames and the file/text distinction are encrypted inside the payload. The outside reveals version, cipher, KDF, salt, nonce, length and approximate plaintext length; it does not hide that this is a vault. All plaintext is withheld until GCM authentication succeeds. Wrong passwords and ciphertext/tag corruption share one authentication error; structurally invalid/unsupported headers have actionable parser errors. Authentication proves knowledge of the secret, **not signing or sender identity**.

| Resource | Limit |
|---|---|
| Original file bytes | 16 MiB (16,777,216 bytes), including empty files |
| Text bytes | 1 MiB (1,048,576 bytes) UTF-8, including empty text |
| Encoded filename | 240 bytes, sanitized and truncated to at most 80 Unicode code points |
| Encrypted payload | At most 16,777,463 bytes (7 + 240 + file bytes) |
| Vault output / accepted encrypted input | At most 16,777,527 bytes (48-byte header + payload + 16-byte tag) |
| KDF work | Exactly 600,000 iterations; a single worker per tab |
| Passphrase | Nonempty on decryption; at least 12 Unicode code points on encryption; maximum 1,024 UTF-8 bytes |

This is **one-shot, in-memory processing, not streaming**. Several copies can exist in JS, worker messages, WebCrypto and download blobs; peak memory may be many times the input limit. Even these limits cannot guarantee low-memory devices won't run out of memory. Do not use this for large files. The UI checks file size and reads/validates only the 48-byte outer header before allocating the complete encrypted input; the worker validates it again before KDF. Authenticated inner lengths/types are validated before results are returned. Invalid/unknown versions, ciphers, KDF IDs, reserved fields, lengths, trailers, and concatenated containers are rejected.

Each operation runs in a dedicated module worker. Cancel/clear terminates that worker and increments an operation generation; late file reads/worker responses cannot restore stale results. WebCrypto work may continue internally despite cancellation; UI cancellation means **discarding results**, not guaranteed CPU interruption. Inputs are locked while busy. Edits invalidate existing results. The app has no automatic decrypt, preview or download.

No secrets are written by application code to local/session storage, IndexedDB, URLs/history, service workers, caches, logs, clipboard, or a server. Page requests (without content/passwords) still reach the hosting provider, and browsers can cache app assets. CSP denies connections, frames, forms, objects and third-party scripts. GitHub Pages does not allow custom HTTP security headers; the meta CSP cannot enforce `frame-ancestors` against framing, so **do not enter secrets into embedded copies**. There are no third-party runtime requests. Outbound source/documentation links require a deliberate navigation.

Clear removes selected files, text/passphrase inputs, results and preview references and revokes active Blob URLs on a best-effort basis. Result/payload byte arrays are overwritten where practical; JS strings, engine copies, garbage collection, OS swap and browser downloads cannot be reliably erased. This is **not secure memory erasure** and never deletes saved files. Object URLs are created only on a download click and revoked after 60 seconds or sooner on clear/input change/page exit. All downloads use `application/octet-stream`; filenames are treated as untrusted, stripped of paths/control/bidi/reserved characters, and never interpreted as markup. Binary files are never previewed, even if their filename claims HTML/SVG/text. Text-mode previews use strict UTF-8 and `textContent`, never HTML.

**Trust boundary:** a compromised origin/deployment, malicious update, browser, extension, device, password manager or OS can observe plaintext/passwords. Browser "local" does not remove that trust. There is no defense against weak/guessed passphrases, endpoint compromise, shoulder surfing, or loss of the passphrase/download. This project-specific format and implementation have **not been independently audited or certified**. Prefer established audited local encryption tools for high-risk or long-term archival needs.

## Develop and verify

Requires Node.js 22+ and a current browser with secure-context WebCrypto, module workers, AES-GCM and PBKDF2. Production needs HTTPS; `localhost`/loopback works for development. `file://` is unsupported. No packages are used at runtime.

```sh
npm ci
npx playwright install chromium
npm run dev
# http://127.0.0.1:4173
npm test
npm run build
npm run test:browser
npm audit --audit-level=high
# Linux only: exercise the exact terminal guide, including CBC failure caveats
python3 tests/openssl_guide.py
```

On Windows PowerShell where script execution is restricted, use `npm.cmd` and `npx.cmd`. `npm run check` combines unit/interoperability/guide-content tests, build, and Chromium desktop/mobile browser tests. The build copies only `index.html`, `linux.html`, `favicon.svg`, and `src/` into `dist/`; there is no transpilation or CDN. Dev-only dependencies and their transitive licenses are locked in `package-lock.json` (Playwright: Apache-2.0; axe-core: MPL-2.0). App code/artwork: MIT.

Coverage includes both ciphers, binary/Unicode/empty input, randomized salt/nonce uniqueness, mutation of **every byte** of a sample header/ciphertext/tag, wrong passwords, strict KDF/length/input bounds, maximum file size, filename sanitization, NIST AES-GCM known-answer vectors and the RFC 7914 PBKDF2-SHA-256 vector. Node's independent OpenSSL-backed `pbkdf2Sync` / `createCipheriv` / `createDecipheriv` APIs verify real app containers both ways (not just app-to-itself round trips). Fixed synthetic public fixtures are in `tests/fixtures`; `tools/reference.mjs` is the separate reference encoder/decoder. Never reuse its deterministic test salt/nonce outside test vectors.

Playwright exercises actual downloaded byte equality, both cipher choices, file input and drag/drop, text and deliberate preview, mismatch/reveal/error handling, empty inputs, cancellation/reset/stale-result invalidation, bounds before worker creation, no persistence/network uploads, CSP, secure-context failure, keyboard tabs and axe accessibility at desktop and mobile viewports. These are Chromium automation checks, **not a claim that physical iOS/Android devices, Safari or Firefox were tested**. All test data/passphrases are synthetic and public, not user secrets. No test videos, screenshots or traces are published.

## Format: SFV v1 (`.sfv`)

All integers are unsigned **big-endian**. There are no optional/duplicate fields, extensions, compression, alternate encodings, or trailing bytes.

| Header offset | Size | Meaning |
|---|---|---|
| 0 | 8 | Magic hex `53 46 56 41 55 4c 54 00` (`SFVAULT` followed by NUL) |
| 8 | 1 | Version: `1` |
| 9 | 1 | Cipher: `1` = AES-256-GCM, `2` = AES-128-GCM |
| 10 | 1 | KDF: `1` = PBKDF2-HMAC-SHA-256 |
| 11 | 1 | Reserved: must be zero |
| 12 | 4 | Iterations: exactly `600000` |
| 16 | 16 | Random salt |
| 32 | 12 | Random 96-bit GCM nonce |
| 44 | 4 | Ciphertext + tag length, must equal remaining file length |
| 48 | variable | GCM ciphertext followed by 16-byte tag |

The password is encoded as exact UTF-8 without normalization; PBKDF2 derives 32 bytes for cipher 1 or 16 bytes for cipher 2. The entire **48-byte header is AAD**, passed unchanged. GCM tag length is exactly 128 bits.

The authenticated decrypted payload is:

| Payload offset | Size | Meaning |
|---|---|---|
| 0 | 1 | Kind: `0` binary file, `1` UTF-8 text |
| 1 | 2 | UTF-8 filename length, max 240 |
| 3 | 4 | Content byte length, bounded by kind |
| 7 | filename length | Strict UTF-8 filename, sanitized again on recovery |
| 7 + filename length | content length | Exact original bytes |

Payload length must be exactly 7 + filename length + content length. No MIME is stored or trusted. Kind 1 must be valid UTF-8, and decoding preserves an initial BOM. Filename normalization/sanitization does **not** affect content or passwords. `message.txt` names text-mode downloads; encrypted downloads use neutral `sealed.sfv`.

### External verification example

`tools/reference.mjs` imports no application crypto code; it independently implements the tables above using Node crypto. `tests/fixtures/aes-256.json` and `aes-128.json` contain exact container hex, SHA-256 digest, fixed public salt/nonce, synthetic plaintext and a **public test-only passphrase**. Tests compare reference output to the committed bytes and decode through WebCrypto, then decrypt random WebCrypto output through Node.

```js
import { readFile } from 'node:fs/promises';
import { openReference, publicPassword } from './tools/reference.mjs';
const fixture = JSON.parse(await readFile('tests/fixtures/aes-256.json', 'utf8'));
const recovered = openReference(Buffer.from(fixture.containerHex, 'hex'), publicPassword);
// recovered.data equals Buffer.from(fixture.plaintextUtf8, 'utf8')
```

The reference is a verification aid, not a recommended secret-handling CLI. It has no password argument/logging interface. The primitive known-answer tests intentionally use test-only zero keys/IVs and low KDF iteration counts to match published vectors; production encryption cannot select those.

## Publishing

The public repository is [itsnavin/secure-file-vault](https://github.com/itsnavin/secure-file-vault). `.github/workflows/pages.yml` uses commit-pinned actions and runs locked installs, unit/reference/guide-content tests, desktop/mobile Chromium checks, the exact OpenSSL guide commands on Linux, the static build and a high-severity dependency audit. Only successful `main` pushes deploy `dist/` to GitHub Pages; PRs verify without deployment. After deployment a separate clean Linux job repeats all desktop/mobile browser tests against the actual live URL, including guide navigation/copy/accessibility and real vault downloads. Enable **Settings > Pages > Source: GitHub Actions**. No user files are committed or uploaded by the app or workflow.

## References

Reviewed **2026-10-22**:

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html): Argon2id preference, PBKDF2-HMAC-SHA-256 minimum of 600,000 iterations.
- [MDN AES-GCM parameters](https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams): 96-bit IV, AAD and 128-bit tags.
- [MDN deriveKey](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey): native password-based PBKDF2 derivation and secure-context requirements.
- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf): GCM authentication, nonce uniqueness and tag policy.
- [NIST GCM examples](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values): primitive test vectors.
- [RFC 7914 section 11](https://www.rfc-editor.org/rfc/rfc7914.html#section-11): PBKDF2-HMAC-SHA-256 test vectors.
- [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/): AES-GCM ciphertext/tag and PBKDF2 API semantics.
- [OpenSSL enc documentation](https://docs.openssl.org/master/man1/openssl-enc/): authenticated modes such as GCM are not supported by `enc`.
