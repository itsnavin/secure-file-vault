import { encrypt, decrypt } from './crypto.js';

self.onmessage = async ({ data: request }) => {
  try {
    if (request.mode !== 'encrypt' && request.mode !== 'decrypt') throw new Error('Unknown operation.');
    const result = request.mode === 'encrypt' ? await encrypt(request) : await decrypt(request);
    const bytes = request.mode === 'encrypt' ? result : result.data;
    self.postMessage({ ok: true, result }, [bytes.buffer]);
  } catch (error) {
    self.postMessage({ ok: false, error: error instanceof Error ? error.message : 'Encryption operation failed.' });
  }
};
