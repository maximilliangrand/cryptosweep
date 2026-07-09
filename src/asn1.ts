/**
 * Minimal, dependency-free DER/ASN.1 reader.
 *
 * cryptosweep's trust model is "parse, don't guess": we never conclude an
 * algorithm from a substring appearing somewhere in a certificate's bytes,
 * because those bytes can appear in extensions, subject fields, or the
 * signature value itself. Instead we walk the actual X.509 structure and read
 * the one field that defines the signing algorithm.
 *
 * We implement only the sliver of DER needed to reach that field:
 *
 *   Certificate ::= SEQUENCE {
 *     tbsCertificate       SEQUENCE { ... },      -- element 0, skipped
 *     signatureAlgorithm   SEQUENCE { OID, ... }, -- element 1, read the OID
 *     signatureValue       BIT STRING
 *   }
 *
 * Everything here is total: malformed input yields `null`, never a throw that
 * could crash a scan of a hostile certificate.
 */

const TAG_SEQUENCE = 0x30;
const TAG_OID = 0x06;

interface Tlv {
  tag: number;
  /** Offset of the first content byte. */
  contentStart: number;
  /** Offset one past the last content byte. */
  contentEnd: number;
  /** Offset of the next TLV after this one. */
  next: number;
}

/** Read one tag-length-value triple at `offset`. Returns null on any malformation. */
function readTlv(buf: Buffer, offset: number): Tlv | null {
  if (offset < 0 || offset + 2 > buf.length) return null;
  const tag = buf[offset];
  if (tag === undefined) return null;

  let pos = offset + 1;
  const first = buf[pos];
  if (first === undefined) return null;
  pos += 1;

  let length: number;
  if (first < 0x80) {
    length = first; // short form
  } else if (first === 0x80) {
    return null; // indefinite length is forbidden in DER
  } else {
    const numBytes = first & 0x7f;
    if (numBytes > 4 || pos + numBytes > buf.length) return null; // reject absurd lengths
    length = 0;
    for (let i = 0; i < numBytes; i += 1) {
      length = length * 256 + (buf[pos] ?? 0);
      pos += 1;
    }
  }

  const contentStart = pos;
  const contentEnd = contentStart + length;
  if (contentEnd > buf.length) return null;
  return { tag, contentStart, contentEnd, next: contentEnd };
}

/** Decode an OID's content bytes into dotted-decimal form (e.g. "1.2.840.113549.1.1.11"). */
function decodeOid(buf: Buffer, start: number, end: number): string | null {
  if (start >= end) return null;
  const arcs: number[] = [];
  let value = 0;
  let started = false;
  for (let i = start; i < end; i += 1) {
    const byte = buf[i] ?? 0;
    value = value * 128 + (byte & 0x7f);
    started = true;
    if ((byte & 0x80) === 0) {
      arcs.push(value);
      value = 0;
      started = false;
    }
  }
  if (started || arcs.length === 0) return null; // truncated final subidentifier
  // The first subidentifier encodes the first two arcs: 40*arc0 + arc1.
  const firstSubId = arcs[0] ?? 0;
  const arc0 = firstSubId < 40 ? 0 : firstSubId < 80 ? 1 : 2;
  const arc1 = firstSubId - arc0 * 40;
  return [arc0, arc1, ...arcs.slice(1)].join(".");
}

/**
 * Extract the outer `signatureAlgorithm` OID from a DER-encoded X.509
 * certificate. Returns the dotted OID string, or null if the structure cannot
 * be parsed.
 */
export function certificateSignatureOid(der: Buffer | undefined): string | null {
  if (!der || der.length === 0) return null;

  const certificate = readTlv(der, 0);
  if (!certificate || certificate.tag !== TAG_SEQUENCE) return null;

  // Element 0: tbsCertificate, read only to find where it ends, then skip it.
  const tbs = readTlv(der, certificate.contentStart);
  if (!tbs || tbs.tag !== TAG_SEQUENCE || tbs.next > certificate.contentEnd) return null;

  // Element 1: signatureAlgorithm, a SEQUENCE whose first element is the OID.
  const sigAlg = readTlv(der, tbs.next);
  if (!sigAlg || sigAlg.tag !== TAG_SEQUENCE || sigAlg.next > certificate.contentEnd) return null;

  const oid = readTlv(der, sigAlg.contentStart);
  if (!oid || oid.tag !== TAG_OID || oid.contentEnd > sigAlg.contentEnd) return null;

  return decodeOid(der, oid.contentStart, oid.contentEnd);
}

/** Human-readable name for a known signature-algorithm OID, or null if unrecognized. */
export function signatureAlgorithmName(oid: string | null): string | null {
  if (!oid) return null;
  return SIGNATURE_ALGORITHM_OIDS[oid] ?? null;
}

/**
 * Canonical X.509 signature-algorithm OIDs.
 * Sources: RFC 5758, RFC 8410 (EdDSA), RFC 4055 (RSASSA-PSS),
 * NIST CSOR / IETF LAMPS drafts for ML-DSA and SLH-DSA.
 */
const SIGNATURE_ALGORITHM_OIDS: Readonly<Record<string, string>> = {
  "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.113549.1.1.10": "rsassaPss",
  "1.2.840.10040.4.3": "dsaWithSHA1",
  "2.16.840.1.101.3.4.3.2": "dsaWithSHA256",
  "1.2.840.10045.4.1": "ecdsaWithSHA1",
  "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
  "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
  "1.2.840.10045.4.3.4": "ecdsaWithSHA512",
  "1.3.101.112": "Ed25519",
  "1.3.101.113": "Ed448",
  // NIST-standardized post-quantum signatures (FIPS 204 / 205).
  "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
  "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
  "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
  "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
};
