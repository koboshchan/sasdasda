// SHA-256 helpers. Every hash in this app is represented as a lowercase hex
// string - that's what gets concatenated (for the login proof and the PoW
// solve loop) and what gets RSA-encrypted (room ids, password hashes).
const encoder = new TextEncoder();

function bufToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** sha256 of a utf8 string, returned as lowercase hex. */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(input));
  return bufToHex(digest);
}

/** sha256 of raw bytes, returned as lowercase hex. */
export async function sha256HexBytes(input: Uint8Array | ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', input as BufferSource);
  return bufToHex(digest);
}
