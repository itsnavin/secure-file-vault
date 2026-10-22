// Independent format implementation using Node's OpenSSL-backed APIs, not WebCrypto.
// Only synthetic, public test data uses fixed salt/nonce values.
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';

const maxData = 16 * 1024 * 1024;
const maxContainer = maxData + 311;
export const publicPassword = 'PUBLIC test passphrase 🗝️ ';
export const publicText = '\ufeffPublic verification only: café / 日本語 / 🔐\n';
export function sealReference({ data, password, bits = 256, kind = 1, name = 'message.txt', salt = randomBytes(16), nonce = randomBytes(12) }) {
  if (![128, 256].includes(bits)) throw new Error('Unsupported cipher');
  if (salt.length !== 16 || nonce.length !== 12) throw new Error('Invalid salt/nonce');
  const filename = Buffer.from(name, 'utf8');
  if (filename.length > 240 || data.length > (kind === 1 ? 1048576 : maxData)) throw new Error('Limit exceeded');
  const payload = Buffer.alloc(7 + filename.length + data.length);
  payload[0] = kind;
  payload.writeUInt16BE(filename.length, 1);
  payload.writeUInt32BE(data.length, 3);
  filename.copy(payload, 7);
  Buffer.from(data).copy(payload, 7 + filename.length);
  const header = Buffer.alloc(48);
  header.write('SFVAULT\0', 0, 'ascii');
  header.set([1, bits === 256 ? 1 : 2, 1, 0], 8);
  header.writeUInt32BE(600000, 12);
  salt.copy(header, 16);
  nonce.copy(header, 32);
  header.writeUInt32BE(payload.length + 16, 44);
  const key = pbkdf2Sync(Buffer.from(password, 'utf8'), salt, 600000, bits / 8, 'sha256');
  const cipher = createCipheriv(`aes-${bits}-gcm`, key, nonce, { authTagLength: 16 });
  cipher.setAAD(header);
  const output = Buffer.concat([header, cipher.update(payload), cipher.final(), cipher.getAuthTag()]);
  key.fill(0);
  payload.fill(0);
  return output;
}

export function openReference(input, password) {
  const bytes = Buffer.from(input);
  if (bytes.length < 71 || bytes.length > maxContainer) throw new Error('Invalid size');
  if (!bytes.subarray(0, 8).equals(Buffer.from('SFVAULT\0', 'ascii')) ||
      bytes[8] !== 1 || ![1, 2].includes(bytes[9]) || bytes[10] !== 1 || bytes[11] !== 0 ||
      bytes.readUInt32BE(12) !== 600000 || bytes.readUInt32BE(44) !== bytes.length - 48) throw new Error('Invalid header');
  const bits = bytes[9] === 1 ? 256 : 128;
  const key = pbkdf2Sync(Buffer.from(password, 'utf8'), bytes.subarray(16, 32), 600000, bits / 8, 'sha256');
  const decipher = createDecipheriv(`aes-${bits}-gcm`, key, bytes.subarray(32, 44), { authTagLength: 16 });
  decipher.setAAD(bytes.subarray(0, 48));
  decipher.setAuthTag(bytes.subarray(-16));
  let partial;
  let payload;
  try {
    partial = decipher.update(bytes.subarray(48, -16));
    // Do not expose update()'s unauthenticated plaintext.
    const tail = decipher.final();
    payload = Buffer.concat([partial, tail]);
    if (payload.length < 7) throw new Error('Invalid payload');
    const kind = payload[0];
    const nameSize = payload.readUInt16BE(1);
    const dataSize = payload.readUInt32BE(3);
    if (![0, 1].includes(kind) || nameSize > 240 || dataSize > (kind === 1 ? 1048576 : maxData) ||
        payload.length !== 7 + nameSize + dataSize) throw new Error('Invalid payload');
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    const name = decoder.decode(payload.subarray(7, 7 + nameSize));
    const data = Buffer.from(payload.subarray(7 + nameSize));
    if (kind === 1) decoder.decode(data);
    return { data, kind, name, bits };
  } finally {
    key.fill(0);
    partial?.fill(0);
    payload?.fill(0);
  }
}
