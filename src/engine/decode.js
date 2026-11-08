// Body decoding: BOM, then the header charset, then <meta charset> in the first
// 1024 bytes, else UTF-8 with fellBack: true. Never throws.

function labelOf(bytes, contentType) {
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return { label: 'utf-8', skip: 3 };
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return { label: 'utf-16le', skip: 2 };
  if (bytes[0] === 0xfe && bytes[1] === 0xff) return { label: 'utf-16be', skip: 2 };
  const header = /charset\s*=\s*["']?([^\s;"']+)/i.exec(contentType ?? '');
  if (header) return { label: header[1], skip: 0 };
  const head = new TextDecoder('latin1').decode(bytes.subarray(0, 1024));
  const meta = /<meta[^>]*?charset\s*=\s*["']?\s*([a-z0-9_\-:.]+)/i.exec(head);
  if (meta) return { label: meta[1], skip: 0 };
  return { label: null, skip: 0 };
}

/**
 * @param {Uint8Array} bytes
 * @param {string} contentType
 * @returns {{text: string, charset: string, fellBack: boolean}}
 */
export function decodeBody(bytes, contentType) {
  const { label, skip } = labelOf(bytes, contentType);
  let decoder = null;
  if (label) {
    try { decoder = new TextDecoder(label); } catch { decoder = null; }
  }
  const fellBack = decoder === null;
  if (!decoder) decoder = new TextDecoder('utf-8');
  return { text: decoder.decode(bytes.subarray(skip)), charset: decoder.encoding, fellBack };
}
