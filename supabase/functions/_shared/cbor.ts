// Minimal CBOR decoder — just enough to parse an App Attest attestation object:
// maps, arrays, text strings, byte strings, unsigned/negative ints, simple
// values, and tags (tag content is returned, tag number ignored). Byte strings
// decode to Uint8Array; text strings to string; maps to plain objects keyed by
// their (string) keys. Indefinite-length items are not supported (App Attest
// uses definite lengths). Throws on anything unexpected (fail closed).

export type CborValue = number | string | boolean | null | Uint8Array | CborValue[] | { [k: string]: CborValue };

interface Cursor {
  readonly buf: Uint8Array;
  pos: number;
}

export function decodeFirstCbor(bytes: Uint8Array): CborValue {
  const c: Cursor = { buf: bytes, pos: 0 };
  return readItem(c);
}

function readUint(c: Cursor, info: number): number {
  if (info < 24) return info;
  if (info === 24) return readN(c, 1);
  if (info === 25) return readN(c, 2);
  if (info === 26) return readN(c, 4);
  if (info === 27) {
    // 64-bit: read as two 32-bit halves; App Attest lengths fit in 53 bits.
    const hi = readN(c, 4);
    const lo = readN(c, 4);
    return hi * 0x1_0000_0000 + lo;
  }
  throw new Error(`cbor: unsupported length info ${info}`);
}

function readN(c: Cursor, n: number): number {
  let v = 0;
  for (let i = 0; i < n; i++) {
    if (c.pos >= c.buf.length) throw new Error('cbor: truncated');
    v = v * 256 + c.buf[c.pos++];
  }
  return v;
}

function readItem(c: Cursor): CborValue {
  if (c.pos >= c.buf.length) throw new Error('cbor: truncated');
  const initial = c.buf[c.pos++];
  const major = initial >> 5;
  const info = initial & 0x1f;

  switch (major) {
    case 0: // unsigned int
      return readUint(c, info);
    case 1: // negative int
      return -1 - readUint(c, info);
    case 2: { // byte string
      const len = readUint(c, info);
      const slice = c.buf.slice(c.pos, c.pos + len);
      if (slice.length !== len) throw new Error('cbor: truncated bytes');
      c.pos += len;
      return slice;
    }
    case 3: { // text string
      const len = readUint(c, info);
      const slice = c.buf.slice(c.pos, c.pos + len);
      if (slice.length !== len) throw new Error('cbor: truncated text');
      c.pos += len;
      return new TextDecoder().decode(slice);
    }
    case 4: { // array
      const len = readUint(c, info);
      const arr: CborValue[] = [];
      for (let i = 0; i < len; i++) arr.push(readItem(c));
      return arr;
    }
    case 5: { // map
      const len = readUint(c, info);
      const obj: { [k: string]: CborValue } = {};
      for (let i = 0; i < len; i++) {
        const key = readItem(c);
        const val = readItem(c);
        obj[typeof key === 'string' ? key : String(key)] = val;
      }
      return obj;
    }
    case 6: // tag — ignore the tag, return the tagged content
      readUint(c, info);
      return readItem(c);
    case 7: // simple / float
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      throw new Error(`cbor: unsupported simple value ${info}`);
    default:
      throw new Error(`cbor: unknown major type ${major}`);
  }
}
