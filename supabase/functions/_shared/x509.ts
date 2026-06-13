// Minimal DER / X.509 helpers for App Attest certificate verification.
//
// ⚠️ PRODUCTION REVIEW REQUIRED (see appAttest.ts): this is a from-first-principles
// DER reader supporting only what App Attest certs need (ECDSA P-256/P-384 leaf
// and intermediate, the Apple nonce extension, SubjectPublicKeyInfo). It has NOT
// been validated against Apple's official sample certificates in this environment.
// It fails CLOSED (returns false/null on any parse mismatch). Validate against
// Apple test vectors — or swap in a maintained X.509 library — before production.

/** Accept a base64 string (CBOR x5c entries are byte strings → Uint8Array, or
 *  base64 in JSON) or raw DER bytes, and return DER bytes. */
export function extractCert(entry: unknown): Uint8Array {
  if (entry instanceof Uint8Array) return entry;
  if (typeof entry === 'string') {
    return Uint8Array.from(atob(entry.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')), (ch) => ch.charCodeAt(0));
  }
  throw new Error('x509: unsupported cert entry');
}

/* ── DER reader ──────────────────────────────────────────────────────────── */

interface TLV {
  tag: number;
  start: number; // offset of the value
  length: number;
  end: number; // offset just past the value
  headerStart: number; // offset of the tag byte
}

function readTLV(buf: Uint8Array, pos: number): TLV {
  const headerStart = pos;
  const tag = buf[pos++];
  let length = buf[pos++];
  if (length & 0x80) {
    const n = length & 0x7f;
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + buf[pos++];
  }
  return { tag, start: pos, length, end: pos + length, headerStart };
}

function children(buf: Uint8Array, seq: TLV): TLV[] {
  const out: TLV[] = [];
  let p = seq.start;
  while (p < seq.end) {
    const tlv = readTLV(buf, p);
    out.push(tlv);
    p = tlv.end;
  }
  return out;
}

// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
function parseCert(der: Uint8Array): { tbs: TLV; sigAlg: TLV; sig: TLV } {
  const cert = readTLV(der, 0);
  const [tbs, sigAlg, sig] = children(der, cert);
  return { tbs, sigAlg, sig };
}

/* ── OID encoding/decoding ──────────────────────────────────────────────── */

function oidToString(buf: Uint8Array, tlv: TLV): string {
  const bytes = buf.slice(tlv.start, tlv.end);
  const parts: number[] = [];
  let val = 0;
  for (let i = 0; i < bytes.length; i++) {
    val = val * 128 + (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) {
      if (parts.length === 0) {
        parts.push(Math.floor(val / 40));
        parts.push(val % 40);
      } else {
        parts.push(val);
      }
      val = 0;
    }
  }
  return parts.join('.');
}

/* ── Public extractions ─────────────────────────────────────────────────── */

const TAG_SEQUENCE = 0x30;
const TAG_OID = 0x06;
const TAG_OCTET_STRING = 0x04;
const TAG_BIT_STRING = 0x03;
const TAG_EXPLICIT_3 = 0xa3; // [3] extensions

/** Raw EC public key bytes (the uncompressed point) from SubjectPublicKeyInfo. */
export function getCertPublicKeyRaw(der: Uint8Array): Uint8Array | null {
  try {
    const { tbs } = parseCert(der);
    // tbs children: [version?]/serial/sigAlg/issuer/validity/subject/SPKI/...
    for (const child of children(der, tbs)) {
      if (child.tag === TAG_SEQUENCE) {
        const sub = children(der, child);
        // SPKI = SEQUENCE { AlgorithmIdentifier SEQUENCE, subjectPublicKey BIT STRING }
        if (sub.length === 2 && sub[0].tag === TAG_SEQUENCE && sub[1].tag === TAG_BIT_STRING) {
          // BIT STRING: first content byte is the unused-bits count (0).
          return der.slice(sub[1].start + 1, sub[1].end);
        }
      }
    }
    return null;
  } catch {
    return null;
  }
}

/** The octet payload of the extension with the given OID (e.g. Apple nonce). */
export function getExtensionOctets(der: Uint8Array, oid: string): Uint8Array | null {
  try {
    const { tbs } = parseCert(der);
    for (const child of children(der, tbs)) {
      if (child.tag !== TAG_EXPLICIT_3) continue; // extensions [3]
      const extSeq = children(der, child)[0]; // SEQUENCE OF Extension
      for (const ext of children(der, extSeq)) {
        const parts = children(der, ext); // OID, [critical BOOL], OCTET STRING
        const oidPart = parts.find((p) => p.tag === TAG_OID);
        const octet = parts.find((p) => p.tag === TAG_OCTET_STRING);
        if (!oidPart || !octet) continue;
        if (oidToString(der, oidPart) === oid) {
          // The extnValue OCTET STRING wraps a DER value; Apple's is
          // SEQUENCE { [1] EXPLICIT OCTET STRING nonce }. Return the innermost
          // octet string content.
          const inner = readTLV(der, octet.start);
          const innerKids = children(der, inner);
          const ctx1 = innerKids[0];
          if (ctx1) {
            const oct = readTLV(der, ctx1.start);
            return der.slice(oct.start, oct.end);
          }
          return der.slice(octet.start, octet.end);
        }
      }
    }
    return null;
  } catch {
    return null;
  }
}

/* ── Signature verification ─────────────────────────────────────────────── */

// Named-curve OIDs.
const OID_P256 = '1.2.840.10045.3.1.7';
const OID_P384 = '1.3.132.0.34';
const OID_EC_PUBKEY = '1.2.840.10045.2.1';

function spki(der: Uint8Array): { curve: 'P-256' | 'P-384'; spkiDer: Uint8Array } | null {
  const { tbs } = parseCert(der);
  for (const child of children(der, tbs)) {
    if (child.tag !== TAG_SEQUENCE) continue;
    const sub = children(der, child);
    if (sub.length === 2 && sub[0].tag === TAG_SEQUENCE && sub[1].tag === TAG_BIT_STRING) {
      const alg = children(der, sub[0]);
      const algOid = alg.find((p) => p.tag === TAG_OID);
      const curveOid = alg.filter((p) => p.tag === TAG_OID)[1];
      if (!algOid || oidToString(der, algOid) !== OID_EC_PUBKEY || !curveOid) continue;
      const curveStr = oidToString(der, curveOid);
      const curve = curveStr === OID_P256 ? 'P-256' : curveStr === OID_P384 ? 'P-384' : null;
      if (!curve) return null;
      return { curve, spkiDer: der.slice(child.headerStart, child.end) };
    }
  }
  return null;
}

/** Convert a DER ECDSA signature (SEQUENCE{ r INTEGER, s INTEGER }) to raw r‖s. */
function derSigToRaw(der: Uint8Array, sig: TLV, size: number): Uint8Array {
  const seq = readTLV(der, sig.start + 1); // BIT STRING content starts with unused-bits byte
  const [r, s] = children(der, seq);
  const out = new Uint8Array(size * 2);
  copyInt(der, r, out, 0, size);
  copyInt(der, s, out, size, size);
  return out;
}

function copyInt(der: Uint8Array, int: TLV, out: Uint8Array, offset: number, size: number): void {
  let start = int.start;
  let len = int.length;
  // Strip a leading 0x00 sign byte.
  while (len > size && der[start] === 0x00) {
    start++;
    len--;
  }
  out.set(der.slice(start, start + len), offset + (size - len));
}

/** Verify that `certDer` is signed by `issuerDer` (ECDSA P-256/P-384, SHA-256/384). */
export async function verifyCertSignedBy(certDer: Uint8Array, issuerDer: Uint8Array): Promise<boolean> {
  try {
    const { tbs, sig } = parseCert(certDer);
    const issuerKey = spki(issuerDer);
    if (!issuerKey) return false;
    const tbsBytes = certDer.slice(tbs.headerStart, tbs.end);
    const size = issuerKey.curve === 'P-256' ? 32 : 48;
    const rawSig = derSigToRaw(certDer, sig, size);
    const hash = issuerKey.curve === 'P-256' ? 'SHA-256' : 'SHA-384';
    const key = await crypto.subtle.importKey(
      'spki',
      issuerKey.spkiDer,
      { name: 'ECDSA', namedCurve: issuerKey.curve },
      false,
      ['verify'],
    );
    return await crypto.subtle.verify({ name: 'ECDSA', hash }, key, rawSig, tbsBytes);
  } catch {
    return false;
  }
}
