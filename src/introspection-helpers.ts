// FILE: auth-worker/src/introspection-helpers.ts

// --- Type Definitions (Minimal versions needed) ---
export interface Token {
  id: string;
  grantId: string;
  userId: string;
  createdAt: number;
  expiresAt: number;
  wrappedEncryptionKey: string;
  grant: {
    clientId: string;
    scope: string[];
    encryptedProps: string;
  };
}

// --- Cryptographic Constants and Helpers (Copied from oauth-provider.ts) ---

// Static HMAC key for wrapping key derivation
const WRAPPING_KEY_HMAC_KEY = new Uint8Array([
  0x22, 0x7e, 0x26, 0x86, 0x8d, 0xf1, 0xe1, 0x6d, 0x80, 0x70, 0xea, 0x17, 0x97, 0x5b, 0x47, 0xa6, 0x82, 0x18, 0xfa,
  0x87, 0x28, 0xae, 0xde, 0x85, 0xb5, 0x1d, 0x4a, 0xd9, 0x96, 0xca, 0xca, 0x43,
]);

/**
 * Generates a token ID by hashing the token value using SHA-256
 * @param token - The token to hash
 * @returns A hex string representation of the hash
 */
export async function generateTokenId(token: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

/**
 * Decodes a base64 string to an ArrayBuffer
 * @param base64 - The base64 string to decode
 * @returns The decoded ArrayBuffer
 */
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Derives a wrapping key from a token string
 * @param tokenStr - The token string to use as key material
 * @returns A Promise resolving to the derived CryptoKey
 */
async function deriveKeyFromToken(tokenStr: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    WRAPPING_KEY_HMAC_KEY,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const hmacResult = await crypto.subtle.sign('HMAC', hmacKey, encoder.encode(tokenStr));
  return await crypto.subtle.importKey(
    'raw',
    hmacResult,
    { name: 'AES-KW' },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

/**
 * Unwraps an encryption key using a token-derived key
 * @param tokenStr - The token string used for key wrapping
 * @param wrappedKeyBase64 - The wrapped key as a base64 string
 * @returns A Promise resolving to the unwrapped CryptoKey
 */
export async function unwrapKeyWithToken(tokenStr: string, wrappedKeyBase64: string): Promise<CryptoKey> {
  const wrappingKey = await deriveKeyFromToken(tokenStr);
  const wrappedKeyBuffer = base64ToArrayBuffer(wrappedKeyBase64);
  return await crypto.subtle.unwrapKey(
    'raw',
    wrappedKeyBuffer,
    wrappingKey,
    { name: 'AES-KW' },
    { name: 'AES-GCM' },
    true, // extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Decrypts encrypted props data using the provided key
 * @param key - The CryptoKey to use for decryption
 * @param encryptedData - The encrypted data as a base64 string
 * @returns The decrypted data object
 */
export async function decryptProps(key: CryptoKey, encryptedData: string): Promise<any> {
  const encryptedBuffer = base64ToArrayBuffer(encryptedData);
  const iv = new Uint8Array(12); // Constant IV used by the library
  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    encryptedBuffer
  );
  const decoder = new TextDecoder();
  const jsonData = decoder.decode(decryptedBuffer);
  return JSON.parse(jsonData);
}
