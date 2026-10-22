import { MAX_FILE, MAX_TEXT, MAX_CONTAINER, HEADER_SIZE, utf8, inspectHeader, decodeText } from './crypto.js';

const $ = (id) => document.getElementById(id);
let mode = 'encrypt';
let inputMode = 'file';
let file = null;
let result = null;
let worker = null;
let generation = 0;
let busy = false;
const urls = new Map();
const available = Boolean(globalThis.isSecureContext && globalThis.crypto?.subtle && globalThis.Worker);

function status(message) { $('status').textContent = message; }
function error(message) { $('error').textContent = message; $('error').hidden = !message; }
function forgetResult() {
  result?.data.fill(0);
  result = null;
  $('result').hidden = true;
  $('result-title').textContent = '';
  $('result-description').textContent = '';
  $('preview').textContent = '';
  $('preview').hidden = true;
  for (const [url, timer] of urls) { clearTimeout(timer); URL.revokeObjectURL(url); }
  urls.clear();
}
function setBusy(value) {
  busy = value;
  $('vault-panel').setAttribute('aria-busy', String(value));
  for (const id of ['run', 'file-input', 'remove-file', 'text-input', 'file-mode', 'text-mode', 'password', 'confirm', 'cipher', 'encrypt-tab', 'decrypt-tab', 'reveal-password', 'reveal-confirm']) {
    $(id).disabled = value || (!available && id === 'run');
  }
  $('cancel').hidden = !value;
  $('progress').hidden = !value;
}
function invalidate() {
  generation++;
  worker?.terminate();
  worker = null;
  setBusy(false);
  forgetResult();
}
function changed() {
  invalidate();
  error('');
  status('Input changed. Ready for a new operation.');
}
function conceal() {
  for (const [id, label] of [['password', 'passphrase'], ['confirm', 'confirmation']]) {
    $(id).type = 'password';
    $(`reveal-${id}`).textContent = 'Show';
    $(`reveal-${id}`).setAttribute('aria-label', `Show ${label}`);
    $(`reveal-${id}`).setAttribute('aria-pressed', 'false');
  }
}
function showFile() {
  $('file-selection').hidden = !file;
  $('file-name').textContent = file ? `${file.name} · ${file.size.toLocaleString()} bytes` : '';
}
function renderMode() {
  const decrypting = mode === 'decrypt';
  for (const action of ['encrypt', 'decrypt']) {
    $(`${action}-tab`).setAttribute('aria-selected', String(action === mode));
    $(`${action}-tab`).tabIndex = action === mode ? 0 : -1;
  }
  $('vault-panel').setAttribute('aria-labelledby', `${mode}-tab`);
  $('action-heading').textContent = decrypting ? 'Bring it back to you.' : 'Let’s lock it up.';
  $('text-mode').hidden = decrypting;
  $('file-mode').setAttribute('aria-pressed', String(inputMode === 'file'));
  $('text-mode').setAttribute('aria-pressed', String(inputMode === 'text'));
  $('file-area').hidden = inputMode !== 'file';
  $('text-area').hidden = inputMode !== 'text';
  $('cipher-field').hidden = decrypting;
  $('decrypt-algorithm').hidden = !decrypting;
  $('confirm-field').hidden = decrypting;
  $('drop-title').textContent = decrypting ? 'Drop your .sfv vault here' : 'Drop a file here';
  $('file-input').accept = decrypting ? '.sfv' : '';
  $('file-limit').textContent = decrypting ? `SFV v1 · up to ${MAX_CONTAINER.toLocaleString()} bytes` : 'Any file type · up to 16 MiB';
  $('run').replaceChildren(document.createTextNode(decrypting ? 'Decrypt →' : 'Encrypt →'));
  $('password-help').textContent = decrypting
    ? 'Enter the original passphrase exactly, including spaces and case. Forgotten passphrases cannot be recovered. Up to 1,024 UTF-8 bytes.'
    : 'Use a strong, unique passphrase of 12+ characters (up to 1,024 UTF-8 bytes). Spaces and case matter. Forgotten passphrases cannot be recovered.';
}
function clear() {
  invalidate();
  file = null;
  $('file-input').value = '';
  $('text-input').value = '';
  $('password').value = '';
  $('confirm').value = '';
  $('cipher').value = '256';
  conceal();
  showFile();
  error('');
  status('Cleared from this tab, best effort. Saved downloads are not deleted.');
}
function selectFile(candidate) {
  if (busy) return;
  changed();
  file = null;
  $('file-input').value = '';
  if (candidate && candidate.size > (mode === 'encrypt' ? MAX_FILE : MAX_CONTAINER)) {
    error(mode === 'encrypt' ? 'File is too large. Choose a file of 16 MiB or less.' : 'Vault is too large. Only vaults for files up to 16 MiB are supported.');
  } else {
    file = candidate || null;
    if (file) status('File selected. Enter your passphrase, then start when ready.');
  }
  showFile();
}

for (const action of ['encrypt', 'decrypt']) {
  $(`${action}-tab`).addEventListener('click', () => {
    if (mode === action || busy) return;
    clear();
    mode = action;
    inputMode = 'file';
    renderMode();
    status('Ready when you are.');
  });
  $(`${action}-tab`).addEventListener('keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const target = event.key === 'Home' ? 'encrypt' : event.key === 'End' ? 'decrypt' : mode === 'encrypt' ? 'decrypt' : 'encrypt';
    $(`${target}-tab`).click();
    $(`${target}-tab`).focus();
  });
}
for (const type of ['file', 'text']) {
  $(`${type}-mode`).addEventListener('click', () => {
    if (busy || type === inputMode) return;
    changed();
    file = null;
    $('file-input').value = '';
    $('text-input').value = '';
    showFile();
    inputMode = type;
    renderMode();
  });
}
$('file-input').addEventListener('change', (event) => selectFile(event.target.files[0]));
$('remove-file').addEventListener('click', () => selectFile(null));
for (const id of ['text-input', 'password', 'confirm', 'cipher']) $(id).addEventListener('input', changed);
for (const [id, label] of [['password', 'passphrase'], ['confirm', 'confirmation']]) {
  $(`reveal-${id}`).addEventListener('click', () => {
    const reveal = $(id).type === 'password';
    $(id).type = reveal ? 'text' : 'password';
    $(`reveal-${id}`).textContent = reveal ? 'Hide' : 'Show';
    $(`reveal-${id}`).setAttribute('aria-label', `${reveal ? 'Hide' : 'Show'} ${label}`);
    $(`reveal-${id}`).setAttribute('aria-pressed', String(reveal));
  });
}
for (const event of ['dragenter', 'dragover']) $('drop-zone').addEventListener(event, (e) => {
  e.preventDefault();
  if (!busy) $('drop-zone').classList.add('dragover');
});
$('drop-zone').addEventListener('dragleave', () => $('drop-zone').classList.remove('dragover'));
$('drop-zone').addEventListener('drop', (event) => {
  event.preventDefault();
  $('drop-zone').classList.remove('dragover');
  if (busy) return;
  const files = event.dataTransfer.files;
  if (files.length !== 1) { changed(); error('Drop exactly one file at a time.'); return; }
  selectFile(files[0]);
});
// Do not let a drop outside the target navigate away from the vault.
window.addEventListener('dragover', (event) => event.preventDefault());
window.addEventListener('drop', (event) => event.preventDefault());
$('clear').addEventListener('click', clear);
$('cancel').addEventListener('click', () => {
  invalidate();
  status('Cancelled. Results were discarded; browser cryptographic work may continue internally.');
});

$('run').addEventListener('click', async () => {
  if (busy) return;
  invalidate();
  error('');
  const current = generation;
  const password = $('password').value;
  try {
    if (!available) throw new Error('WebCrypto or workers are unavailable. Use a current browser over HTTPS (or localhost). No weaker fallback is provided.');
    utf8(password, 1024, 'Passphrase');
    if (!password.length) throw new Error('Enter your passphrase.');
    if (mode === 'encrypt') {
      if (password !== $('confirm').value) throw new Error('Passphrases do not match. Enter the same passphrase in both fields.');
      if (Array.from(password).length < 12) throw new Error('Use a strong, unique passphrase of at least 12 characters.');
    }
    if (inputMode === 'file' && !file) throw new Error(mode === 'decrypt' ? 'Choose a .sfv vault to decrypt.' : 'Choose a file or switch to Text.');
    const selectedFile = file;
    setBusy(true);
    status('Reading input…');
    if (mode === 'decrypt') {
      const header = new Uint8Array(await selectedFile.slice(0, HEADER_SIZE).arrayBuffer());
      if (current !== generation) return;
      inspectHeader(header, selectedFile.size);
    }
    const data = inputMode === 'text' ? utf8($('text-input').value, MAX_TEXT, 'Text') : new Uint8Array(await selectedFile.arrayBuffer());
    if (current !== generation) return;
    const operationMode = mode;
    worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
    status(mode === 'encrypt' ? 'Deriving key and encrypting locally…' : 'Deriving key and authenticating locally…');
    worker.onerror = (event) => {
      event.preventDefault();
      if (current !== generation) return;
      invalidate();
      $('password').value = '';
      $('confirm').value = '';
      conceal();
      error('The local encryption worker failed. Reload over HTTPS in a current browser and try again.');
      status('Operation failed. No output released.');
    };
    worker.onmessage = ({ data: response }) => {
      if (current !== generation) return;
      worker.terminate();
      worker = null;
      setBusy(false);
      $('password').value = '';
      $('confirm').value = '';
      conceal();
      if (!response.ok) { error(response.error); status('Operation failed. No output released.'); return; }
      result = operationMode === 'encrypt'
        ? { data: response.result, name: 'sealed.sfv', kind: 0 }
        : response.result;
      $('result-title').textContent = operationMode === 'encrypt' ? 'Locked and ready to go.' : 'Authenticated and unlocked.';
      $('result-description').textContent = operationMode === 'encrypt'
        ? `${result.data.length.toLocaleString()} bytes · SFV v1. Download your vault and keep the passphrase separately.`
        : `${result.name} · ${result.data.length.toLocaleString()} bytes · AES-${result.bits}-GCM. Nothing is downloaded or previewed automatically.`;
      $('download').textContent = operationMode === 'encrypt' ? 'Download encrypted file' : 'Download decrypted file';
      $('preview-button').hidden = operationMode !== 'decrypt' || result.kind !== 1;
      $('preview-button').textContent = 'Show decrypted text';
      $('result').hidden = false;
      status('Complete. Passphrase fields cleared.');
    };
    worker.postMessage({
      mode, data, password, bits: Number($('cipher').value),
      kind: inputMode === 'text' ? 1 : 0, name: inputMode === 'text' ? 'message.txt' : selectedFile.name,
    }, [data.buffer]);
  } catch (failure) {
    if (current !== generation) return;
    invalidate();
    error(failure instanceof Error ? failure.message : 'Operation failed.');
    status('Operation failed. No output released.');
  }
});
$('download').addEventListener('click', () => {
  if (!result) return;
  const url = URL.createObjectURL(new Blob([result.data], { type: 'application/octet-stream' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = result.name;
  document.body.append(link);
  link.click();
  link.remove();
  const timer = setTimeout(() => { URL.revokeObjectURL(url); urls.delete(url); }, 60_000);
  urls.set(url, timer);
});
$('preview-button').addEventListener('click', () => {
  if (!result || result.kind !== 1) return;
  const show = $('preview').hidden;
  try {
    $('preview').textContent = show ? decodeText(result.data) : '';
    $('preview').hidden = !show;
    $('preview-button').textContent = show ? 'Hide decrypted text' : 'Show decrypted text';
  } catch {
    error('This content is not valid UTF-8 text. Download it as a file instead.');
  }
});
window.addEventListener('pagehide', clear);
// Clear restored form values after back/forward-cache navigation.
window.addEventListener('pageshow', (event) => { if (event.persisted) clear(); });
clear();
renderMode();
if (available) status('Ready when you are.');
else { status('Secure browser features required.'); error('Use HTTPS or localhost in a current browser with WebCrypto and module workers enabled.'); }
