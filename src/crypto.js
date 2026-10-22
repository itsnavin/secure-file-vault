export const MAX_FILE = 16 * 1024 * 1024;
export const MAX_TEXT = 1024 * 1024;
export const HEADER_SIZE = 48;
export const MAX_NAME = 240;
export const MAX_CONTAINER = HEADER_SIZE + 7 + MAX_NAME + MAX_FILE + 16;
export const ITERATIONS = 600_000;
const MAGIC = new Uint8Array([83, 70, 86, 65, 85, 76, 84, 0]);
const encoder = new TextEncoder();
const decoder = () => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export function utf8(value, max, label) {
  if (typeof value !== 'string') throw new Error(`${label} must be text.`);
  for (const character of value) {
    const point = character.codePointAt(0);
    if (point >= 0xd800 && point <= 0xdfff) {
      throw new Error(`${label} contains an invalid Unicode character.`);
    }
  }
  // Bound strings before creating a potentially large UTF-8 allocation.
  if (value.length > max) throw new Error(`${label} exceeds its byte limit.`);
  const bytes = encoder.encode(value);
  if (bytes.length > max) throw new Error(`${label} exceeds its byte limit.`);
  return bytes;
}

export function safeName(name) {
  let clean = name.normalize('NFC')
    .replace(/[\u0000-\u001f\u007f-\u009f<>:"/\\|?*\u202a-\u202e\u2066-\u2069]/g, '_')
    .replace(/^[. ]+|[. ]+$/g, '');
  if (/^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(clean)) clean = `_${clean}`;
  clean = Array.from(clean).slice(0, 80).join('');
  // 80 Unicode code points may exceed the format's UTF-8 filename budget.
  while (encoder.encode(clean).length > MAX_NAME) clean = Array.from(clean).slice(0, -1).join('');
  clean = clean.replace(/[. ]+$/g, '');
  return clean || 'recovered.bin';
}

function cipherBits(id) {
  if (id === 1) return 256;
  if (id === 2) return 128;
  throw new Error('Unsupported cipher. This file may need a newer version of File Vault.');
}

export function parseHeader(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error('Expected a binary vault file.');
  return inspectHeader(bytes.subarray(0, HEADER_SIZE), bytes.length);
}

export function inspectHeader(bytes, totalLength) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== HEADER_SIZE ||
      !Number.isSafeInteger(totalLength) || totalLength < HEADER_SIZE + 7 + 16 || totalLength > MAX_CONTAINER) {
    throw new Error('Invalid vault length. Vault files must be within the 16 MiB input limit plus format overhead.');
  }
  if (!MAGIC.every((byte, i) => bytes[i] === byte)) throw new Error('Not an SFV vault file. Choose a .sfv file created by File Vault.');
  if (bytes[8] !== 1) throw new Error('Unsupported vault version.');
  const bits = cipherBits(bytes[9]);
  if (bytes[10] !== 1 || bytes[11] !== 0) throw new Error('Unsupported KDF or reserved header fields.');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const iterations = view.getUint32(12);
  // Version 1 deliberately accepts exactly one work factor. No downgrade or unbounded costs.
  if (iterations !== ITERATIONS) throw new Error('Unsupported PBKDF2 work factor. Version 1 requires 600,000 iterations.');
  const ciphertextLength = view.getUint32(44);
  if (ciphertextLength !== totalLength - HEADER_SIZE) throw new Error('Invalid vault ciphertext length.');
  return { bits, iterations, salt: bytes.slice(16, 32), nonce: bytes.slice(32, 44) };
}

async function derive(password, salt, bits, usage) {
  if (!globalThis.crypto?.subtle) throw new Error('WebCrypto is unavailable. Open this app over HTTPS in a current browser.');
  const passwordBytes = utf8(password, 1024, 'Passphrase');
  if (!passwordBytes.length) throw new Error('Enter your passphrase.');
  try {
    const material = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', iterations: ITERATIONS, salt },
      material, { name: 'AES-GCM', length: bits }, false, [usage],
    );
  } finally {
    passwordBytes.fill(0);
  }
}

export async function encrypt({ data, password, bits = 256, name = 'message.txt', kind = 1 }) {
  if (!(data instanceof Uint8Array)) throw new Error('Expected binary input.');
  if (kind !== 0 && kind !== 1) throw new Error('Invalid input type.');
  if (data.length > (kind === 1 ? MAX_TEXT : MAX_FILE)) throw new Error('Input exceeds the file (16 MiB) or text (1 MiB UTF-8) limit.');
  if (bits !== 256 && bits !== 128) throw new Error('Unsupported cipher.');
  if (Array.from(password).length < 12) throw new Error('Use a strong, unique passphrase of at least 12 characters.');
  if (kind === 1) decoder().decode(data);
  const filename = utf8(safeName(name), MAX_NAME, 'Filename');
  const payload = new Uint8Array(7 + filename.length + data.length);
  payload[0] = kind;
  const payloadView = new DataView(payload.buffer);
  payloadView.setUint16(1, filename.length);
  payloadView.setUint32(3, data.length);
  payload.set(filename, 7);
  payload.set(data, 7 + filename.length);
  const header = new Uint8Array(HEADER_SIZE);
  header.set(MAGIC);
  header.set([1, bits === 256 ? 1 : 2, 1, 0], 8);
  new DataView(header.buffer).setUint32(12, ITERATIONS);
  crypto.getRandomValues(header.subarray(16, 32));
  crypto.getRandomValues(header.subarray(32, 44));
  new DataView(header.buffer).setUint32(44, payload.length + 16);
  try {
    const key = await derive(password, header.slice(16, 32), bits, 'encrypt');
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({
      name: 'AES-GCM', iv: header.slice(32, 44), additionalData: header, tagLength: 128,
    }, key, payload));
    const result = new Uint8Array(header.length + ciphertext.length);
    result.set(header);
    result.set(ciphertext, header.length);
    return result;
  } finally {
    payload.fill(0);
  }
}

export async function decrypt({ data, password }) {
  const { bits, salt, nonce } = parseHeader(data);
  const key = await derive(password, salt, bits, 'decrypt');
  let payload;
  try {
    payload = new Uint8Array(await crypto.subtle.decrypt({
      name: 'AES-GCM', iv: nonce, additionalData: data.subarray(0, HEADER_SIZE), tagLength: 128,
    }, key, data.subarray(HEADER_SIZE)));
  } catch (error) {
    if (error.name === 'OperationError') throw new Error('Authentication failed. The passphrase is incorrect or the vault is damaged or modified.');
    throw error;
  }
  try {
    if (payload.length < 7) throw new Error('Invalid encrypted payload.');
    const view = new DataView(payload.buffer);
    const kind = payload[0];
    const nameLength = view.getUint16(1);
    const dataLength = view.getUint32(3);
    if ((kind !== 0 && kind !== 1) || nameLength > MAX_NAME ||
        dataLength > (kind === 1 ? MAX_TEXT : MAX_FILE) ||
        payload.length !== 7 + nameLength + dataLength) throw new Error('Invalid encrypted payload lengths or type.');
    const name = safeName(decoder().decode(payload.subarray(7, 7 + nameLength)));
    const content = payload.slice(7 + nameLength);
    if (kind === 1) decoder().decode(content);
    return { data: content, name, kind, bits };
  } finally {
    payload.fill(0);
  }
}

export function decodeText(data) {
  return decoder().decode(data);
}
