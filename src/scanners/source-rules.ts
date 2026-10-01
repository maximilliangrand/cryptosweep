/**
 * Source-scanner rule catalogue.
 *
 * Every detector the source scanner runs is one row here, keyed by a stable
 * rule id that becomes the finding's `ruleId`, so SARIF rules and CBOM grouping
 * never hang off a per-report counter. A row records the primitive it
 * inventories, how that primitive is used, the language it applies to, and the
 * confidence a match in live source can earn. The matchers below the catalogue
 * (a call table the JavaScript/TypeScript AST scanner interprets, and linear
 * regexes for Python, Go and the JVM) refer to rows by id, and `RuleId` makes a
 * dangling reference a compile error. Adding an API is a data change.
 *
 * Severity follows the rest of the tool: it grades classical strength, while
 * `pq` carries the quantum verdict. A sound RSA-2048 key-generation call is
 * `medium` and quantum-vulnerable; the same call with a 1024-bit modulus is
 * `high`, because it is breakable today.
 *
 * Every regex here must stay linear: bounded quantifiers only, and no two
 * adjacent repetitions that can match the same characters.
 */
import { REFS, curveFriendlyName } from "../crypto";
import type { Category, Confidence, CryptoUsage, PqStatus, Reference, Severity } from "../report";

export type RuleUsage =
  | "key-generation"
  | "signing"
  | "key-agreement"
  | "encryption"
  | "hashing"
  | "mac"
  | "key-material"
  | "coverage";

export type RuleLanguage = "javascript" | "python" | "go" | "java" | "any";

interface RuleSpec {
  readonly category: Category;
  /** Generic title; a finding appends its own detail in parentheses. */
  readonly title: string;
  /** The primitive (family) this rule inventories, e.g. `RSA`, `ECDH`, `MD5/SHA-1`. */
  readonly primitive: string;
  readonly usage: RuleUsage;
  /**
   * What the primitive is used for, in the report's vocabulary: it becomes the
   * finding's `usage`, which the risk engine reads to pick a threat model.
   * Empty when the rule cannot tell (an RSA or EC key-generation call can end
   * up signing or decrypting), so the engine assesses both threat models.
   */
  readonly findingUsage: readonly CryptoUsage[];
  readonly language: RuleLanguage;
  /** The library or API surface the rule matches, e.g. `node:crypto`, `WebCrypto`, `PyJWT`. */
  readonly api: string;
  /** Ceiling confidence of a match in live source (docs and tests are de-rated further). */
  readonly confidence: Confidence;
  /** Base severity for a classically sound instance; weak parameters raise it. */
  readonly severity: Severity;
  readonly pq: PqStatus;
  readonly recommendation: string;
  readonly references: readonly Reference[];
  /** Weak-hash rules: the digest's role in the surrounding code sets the severity. */
  readonly roleSensitive?: boolean;
}

/** Citations the shared REFS table does not carry. */
const CITE = {
  cwe321: { label: "CWE-321 (Use of Hard-coded Cryptographic Key)", url: "https://cwe.mitre.org/data/definitions/321.html" },
  cwe798: { label: "CWE-798 (Use of Hard-coded Credentials)", url: "https://cwe.mitre.org/data/definitions/798.html" },
  cwe347: {
    label: "CWE-347 (Improper Verification of Cryptographic Signature)",
    url: "https://cwe.mitre.org/data/definitions/347.html",
  },
  cwe328: { label: "CWE-328 (Use of Weak Hash)", url: "https://cwe.mitre.org/data/definitions/328.html" },
  rfc7518: { label: "RFC 7518 (JSON Web Algorithms)", url: "https://www.rfc-editor.org/rfc/rfc7518" },
  rfc8725: { label: "RFC 8725 (JSON Web Token Best Current Practices)", url: "https://www.rfc-editor.org/rfc/rfc8725" },
} as const satisfies Record<string, Reference>;

type AsymmetricUsage = "key-generation" | "signing" | "key-agreement" | "encryption";

const ADVICE: Record<AsymmetricUsage, (primitive: string) => string> = {
  "key-generation": (p) =>
    `${p} keys are broken by Shor's algorithm whatever they are used for. Inventory where these keys go, then plan ML-DSA (FIPS 204) for signatures and ML-KEM (FIPS 203) for key establishment.`,
  signing: (p) =>
    `${p} signatures become forgeable once a cryptographically relevant quantum computer exists (Shor's algorithm). Inventory the keys behind this call and plan the move to ML-DSA (FIPS 204), or a hybrid signature, on the NIST IR 8547 timeline.`,
  "key-agreement": (p) =>
    `${p} key agreement is a harvest-now-decrypt-later target: traffic recorded today can be decrypted once a quantum computer runs Shor's algorithm. Move to ML-KEM (FIPS 203), for example the X25519MLKEM768 hybrid.`,
  encryption: (p) =>
    `${p} encryption (key transport) is a harvest-now-decrypt-later target: ciphertext recorded today can be decrypted once a quantum computer runs Shor's algorithm. Replace it with ML-KEM (FIPS 203) encapsulation, or a hybrid KEM.`,
};

const ADVICE_REFS: Record<AsymmetricUsage, readonly Reference[]> = {
  "key-generation": [REFS.fips203, REFS.fips204, REFS.ir8547],
  signing: [REFS.fips204, REFS.ir8547, REFS.cnsa2],
  "key-agreement": [REFS.fips203, REFS.ir8547, REFS.cnsa2],
  encryption: [REFS.fips203, REFS.ir8547, REFS.cnsa2],
};

/**
 * The finding usage implied by an asymmetric row. Key generation implies a use
 * only through its advice (DSA and EdDSA keys sign, X25519 and DH keys agree),
 * which is why `asymmetric()` takes it from the advice, not the rule usage.
 */
const FINDING_USAGE: Record<AsymmetricUsage, readonly CryptoUsage[]> = {
  "key-generation": [],
  signing: ["signature"],
  "key-agreement": ["key-establishment"],
  encryption: ["encryption"],
};

/** Regex-matched languages earn `medium`; the JS/TS AST can earn `confirmed`. */
function ceilingFor(language: RuleLanguage): Confidence {
  return language === "javascript" ? "confirmed" : "medium";
}

function asymmetric(
  api: string,
  language: RuleLanguage,
  primitive: string,
  usage: AsymmetricUsage,
  title: string,
  advice: AsymmetricUsage = usage,
): RuleSpec {
  return {
    category: "source",
    title,
    primitive,
    usage,
    findingUsage: FINDING_USAGE[advice],
    language,
    api,
    confidence: ceilingFor(language),
    severity: "medium",
    pq: "vulnerable",
    recommendation: ADVICE[advice](primitive),
    references: ADVICE_REFS[advice],
  };
}

const WEAK_HASH_ADVICE =
  "MD5 and SHA-1 are broken for collision resistance. That matters wherever the digest protects something: signatures, certificates, integrity checks, password storage, or any digest over attacker-influenced input. Use SHA-256 or SHA-3 there.";

/**
 * Resolving the API proves MD5/SHA-1 is called, not that anything depends on
 * its collision resistance, and the role the AST infers from names is a
 * heuristic. So a weak-hash finding tops out at `high`, never `confirmed`.
 */
function weakHashCeiling(language: RuleLanguage): Confidence {
  return language === "javascript" ? "high" : "medium";
}

function weakHash(api: string, language: RuleLanguage, title: string): RuleSpec {
  return {
    category: "source",
    title,
    primitive: "MD5/SHA-1",
    usage: "hashing",
    findingUsage: ["hashing"],
    language,
    api,
    confidence: weakHashCeiling(language),
    severity: "medium",
    pq: "vulnerable",
    recommendation: WEAK_HASH_ADVICE,
    references: [REFS.cwe327, CITE.cwe328, REFS.sp800131a],
    roleSensitive: true,
  };
}

function weakHashNonSecurity(api: string, language: RuleLanguage, title: string): RuleSpec {
  return {
    category: "source",
    title,
    primitive: "MD5/SHA-1",
    usage: "hashing",
    findingUsage: ["hashing"],
    language,
    api,
    confidence: weakHashCeiling(language),
    severity: "low",
    pq: "unknown",
    recommendation:
      "Collision resistance is not relied on for an identifier such as an ETag, cache key or git object id, and SP 800-131A still permits SHA-1 outside digital signatures, so this is low priority. Switch to SHA-256 if an attacker can choose the input.",
    references: [REFS.sp800131a],
  };
}

function weakCipher(api: string, language: RuleLanguage, title: string): RuleSpec {
  return {
    category: "source",
    title,
    primitive: "DES/3DES/RC4/RC2",
    usage: "encryption",
    findingUsage: ["encryption"],
    language,
    api,
    confidence: ceilingFor(language),
    severity: "high",
    pq: "vulnerable",
    recommendation: "Replace DES/3DES/RC4/RC2 with AES-256-GCM and re-key affected data.",
    references: [REFS.cwe327],
  };
}

function coverage(title: string, recommendation: string): RuleSpec {
  return {
    category: "source",
    title,
    primitive: "none",
    usage: "coverage",
    findingUsage: [],
    language: "any",
    api: "cryptosweep",
    confidence: "confirmed",
    severity: "info",
    pq: "unknown",
    recommendation,
    references: [],
  };
}

export type JwtClass =
  | "alg-none"
  | "hmac"
  | "rsa"
  | "ecdsa"
  | "eddsa"
  | "rsa-key-transport"
  | "ecdh-key-agreement"
  | "algorithm-unresolved";

type JwtClassSpec = Pick<
  RuleSpec,
  "title" | "primitive" | "usage" | "findingUsage" | "severity" | "pq" | "recommendation" | "references"
>;

const JWT_CLASSES: Record<JwtClass, JwtClassSpec> = {
  "alg-none": {
    title: "Unsigned JWT (alg none)",
    primitive: "none",
    usage: "signing",
    findingUsage: ["authentication"],
    severity: "critical",
    pq: "vulnerable",
    recommendation: 'JWT "alg: none" disables signature verification, remove it.',
    references: [CITE.cwe347, CITE.rfc8725],
  },
  hmac: {
    title: "JWT HMAC algorithm",
    primitive: "HMAC",
    usage: "mac",
    findingUsage: ["authentication"],
    severity: "low",
    pq: "safe",
    recommendation:
      "HMAC JWT is symmetric and quantum-resistant if the key is at least 256 bits; rotate and protect the secret.",
    references: [CITE.rfc7518],
  },
  rsa: {
    title: "JWT RSA signature algorithm",
    primitive: "RSA",
    usage: "signing",
    findingUsage: ["signature"],
    severity: "high",
    pq: "vulnerable",
    recommendation:
      "RS*/PS* tokens rely on RSA signatures, which Shor's algorithm breaks; plan a PQ-signature migration (ML-DSA, FIPS 204).",
    references: [REFS.fips204, CITE.rfc7518],
  },
  ecdsa: {
    title: "JWT ECDSA signature algorithm",
    primitive: "ECDSA",
    usage: "signing",
    findingUsage: ["signature"],
    severity: "high",
    pq: "vulnerable",
    recommendation:
      "ES* tokens rely on ECDSA signatures, which Shor's algorithm breaks; plan a PQ-signature migration (ML-DSA, FIPS 204).",
    references: [REFS.fips204, CITE.rfc7518],
  },
  eddsa: {
    title: "JWT EdDSA signature algorithm",
    primitive: "EdDSA",
    usage: "signing",
    findingUsage: ["signature"],
    severity: "high",
    pq: "vulnerable",
    recommendation:
      "EdDSA tokens rely on Ed25519/Ed448 elliptic-curve signatures, which Shor's algorithm breaks; plan a PQ-signature migration (ML-DSA, FIPS 204).",
    references: [REFS.fips204, CITE.rfc7518],
  },
  "rsa-key-transport": {
    title: "JWE RSA key transport",
    primitive: "RSA",
    usage: "encryption",
    findingUsage: ["encryption"],
    severity: "high",
    pq: "vulnerable",
    recommendation:
      "RSA1_5/RSA-OAEP key management is a harvest-now-decrypt-later target: a token recorded today can be decrypted once a quantum computer runs Shor's algorithm. Plan ML-KEM (FIPS 203) based key management.",
    references: [REFS.fips203, CITE.rfc7518],
  },
  "ecdh-key-agreement": {
    title: "JWE ECDH-ES key agreement",
    primitive: "ECDH",
    usage: "key-agreement",
    findingUsage: ["key-establishment"],
    severity: "high",
    pq: "vulnerable",
    recommendation:
      "ECDH-ES key agreement is a harvest-now-decrypt-later target: a token recorded today can be decrypted once a quantum computer runs Shor's algorithm. Plan ML-KEM (FIPS 203) based key management.",
    references: [REFS.fips203, CITE.rfc7518],
  },
  "algorithm-unresolved": {
    title: "JWT call whose algorithm is not statically known",
    primitive: "unknown",
    usage: "signing",
    findingUsage: [],
    severity: "info",
    pq: "unknown",
    recommendation:
      "The algorithm is chosen at runtime or left to the library's key-based default, so this call site could not be classified. Pin an explicit algorithm (an allow-list on verify): that makes it inventoriable and closes off algorithm-confusion attacks.",
    references: [CITE.rfc8725],
  },
};

type JwtLibrary = "jsonwebtoken" | "jose" | "pyjwt";

/**
 * The algorithm classes each library can produce. jsonwebtoken and PyJWT do
 * JWS only, so they carry no JWE rules, and only the AST can see a runtime
 * (unresolved) algorithm.
 */
const JWS_CLASSES = ["alg-none", "hmac", "rsa", "ecdsa", "eddsa"] as const;
const JWT_LIBRARY_CLASSES = {
  jsonwebtoken: [...JWS_CLASSES, "algorithm-unresolved"],
  jose: [...JWS_CLASSES, "rsa-key-transport", "ecdh-key-agreement", "algorithm-unresolved"],
  pyjwt: JWS_CLASSES,
} as const satisfies Record<JwtLibrary, readonly JwtClass[]>;

type JwtRuleKey<L extends JwtLibrary> = `jwt/${L}/${(typeof JWT_LIBRARY_CLASSES)[L][number]}`;

function jwtRules<L extends JwtLibrary>(library: L, api: string, language: RuleLanguage): Record<JwtRuleKey<L>, RuleSpec> {
  const rules: Partial<Record<string, RuleSpec>> = {};
  for (const name of JWT_LIBRARY_CLASSES[library]) {
    const spec = JWT_CLASSES[name];
    rules[`jwt/${library}/${name}`] = {
      ...spec,
      category: "jwt",
      title: `${spec.title} via ${api}`,
      language,
      api,
      confidence: ceilingFor(language),
    };
  }
  return rules as Record<JwtRuleKey<L>, RuleSpec>;
}

const NODE = "node:crypto";
const WEBCRYPTO = "WebCrypto";
const PYCA = "pyca/cryptography";
const PYCRYPTODOME = "PyCryptodome";
const HASHLIB = "hashlib";
const GO = "Go crypto";
const JCA = "Java Cryptography Architecture";

const CATALOGUE = {
  // ---------- node:crypto ----------
  "source/node-crypto/keygen-rsa": asymmetric(NODE, "javascript", "RSA", "key-generation", "RSA key-pair generation via node:crypto"),
  "source/node-crypto/keygen-dsa": asymmetric(NODE, "javascript", "DSA", "key-generation", "DSA key-pair generation via node:crypto", "signing"),
  "source/node-crypto/keygen-ec": asymmetric(NODE, "javascript", "EC", "key-generation", "Elliptic-curve key-pair generation via node:crypto"),
  "source/node-crypto/keygen-eddsa": asymmetric(NODE, "javascript", "EdDSA", "key-generation", "Ed25519/Ed448 key-pair generation via node:crypto", "signing"),
  "source/node-crypto/keygen-xdh": asymmetric(NODE, "javascript", "X25519/X448", "key-generation", "X25519/X448 key-pair generation via node:crypto", "key-agreement"),
  "source/node-crypto/keygen-dh": asymmetric(NODE, "javascript", "DH", "key-generation", "Diffie-Hellman key-pair generation via node:crypto", "key-agreement"),
  "source/node-crypto/signature": asymmetric(NODE, "javascript", "RSA/DSA/ECDSA", "signing", "RSA, DSA or ECDSA signature via node:crypto"),
  "source/node-crypto/ecdh": asymmetric(NODE, "javascript", "ECDH", "key-agreement", "ECDH key agreement via node:crypto"),
  "source/node-crypto/dh": asymmetric(NODE, "javascript", "DH", "key-agreement", "Finite-field Diffie-Hellman via node:crypto"),
  "source/node-crypto/key-agreement": asymmetric(NODE, "javascript", "DH/ECDH/X25519", "key-agreement", "Diffie-Hellman key agreement via node:crypto diffieHellman()"),
  "source/node-crypto/rsa-encryption": asymmetric(NODE, "javascript", "RSA", "encryption", "RSA public-key encryption via node:crypto"),
  "source/node-crypto/rsa-private-encrypt": asymmetric(NODE, "javascript", "RSA", "signing", "Raw RSA private-key operation via node:crypto"),
  "source/node-crypto/weak-hash": weakHash(NODE, "javascript", "Weak hash algorithm via node:crypto"),
  "source/node-crypto/weak-hash-non-security": weakHashNonSecurity(NODE, "javascript", "Weak hash in a non-security role via node:crypto"),
  "source/node-crypto/weak-cipher": weakCipher(NODE, "javascript", "Weak symmetric cipher via node:crypto"),
  "source/node-crypto/legacy-digest": {
    category: "source",
    title: "MD5/SHA-1 inside HMAC or a KDF via node:crypto",
    primitive: "MD5/SHA-1",
    usage: "mac",
    findingUsage: ["authentication"],
    language: "javascript",
    api: NODE,
    confidence: "confirmed",
    severity: "low",
    pq: "unknown",
    recommendation:
      "HMAC-MD5, HMAC-SHA1 and PBKDF2/HKDF over them are not broken the way bare MD5/SHA-1 are, but they are legacy choices outside current NIST guidance. Prefer SHA-256 when this code is next touched.",
    references: [REFS.cwe327],
  },

  // ---------- WebCrypto (crypto.subtle) ----------
  "source/webcrypto/keygen-rsa": asymmetric(WEBCRYPTO, "javascript", "RSA", "key-generation", "RSA key generation or import via WebCrypto"),
  "source/webcrypto/keygen-ec": asymmetric(WEBCRYPTO, "javascript", "EC", "key-generation", "ECDSA/ECDH key generation or import via WebCrypto"),
  "source/webcrypto/keygen-eddsa": asymmetric(WEBCRYPTO, "javascript", "EdDSA", "key-generation", "Ed25519/Ed448 key generation or import via WebCrypto", "signing"),
  "source/webcrypto/keygen-xdh": asymmetric(WEBCRYPTO, "javascript", "X25519/X448", "key-generation", "X25519/X448 key generation or import via WebCrypto", "key-agreement"),
  "source/webcrypto/rsa-signature": asymmetric(WEBCRYPTO, "javascript", "RSA", "signing", "RSA signature via WebCrypto"),
  "source/webcrypto/ecdsa": asymmetric(WEBCRYPTO, "javascript", "ECDSA", "signing", "ECDSA signature via WebCrypto"),
  "source/webcrypto/eddsa": asymmetric(WEBCRYPTO, "javascript", "EdDSA", "signing", "Ed25519/Ed448 signature via WebCrypto"),
  "source/webcrypto/key-agreement": asymmetric(WEBCRYPTO, "javascript", "ECDH/X25519/X448", "key-agreement", "ECDH/X25519 key agreement via WebCrypto"),
  "source/webcrypto/rsa-oaep": asymmetric(WEBCRYPTO, "javascript", "RSA", "encryption", "RSA-OAEP encryption via WebCrypto"),

  // ---------- JSON Web Tokens ----------
  ...jwtRules("jsonwebtoken", "jsonwebtoken", "javascript"),
  ...jwtRules("jose", "jose", "javascript"),
  ...jwtRules("pyjwt", "PyJWT/python-jose", "python"),

  // ---------- Python: pyca/cryptography ----------
  "source/python-cryptography/keygen-rsa": asymmetric(PYCA, "python", "RSA", "key-generation", "RSA key generation via pyca/cryptography"),
  "source/python-cryptography/keygen-ec": asymmetric(PYCA, "python", "EC", "key-generation", "Elliptic-curve key generation via pyca/cryptography"),
  "source/python-cryptography/keygen-dsa": asymmetric(PYCA, "python", "DSA", "key-generation", "DSA key generation via pyca/cryptography", "signing"),
  "source/python-cryptography/keygen-eddsa": asymmetric(PYCA, "python", "EdDSA", "key-generation", "Ed25519/Ed448 key generation via pyca/cryptography", "signing"),
  "source/python-cryptography/dh": asymmetric(PYCA, "python", "DH", "key-agreement", "Diffie-Hellman parameters via pyca/cryptography"),
  "source/python-cryptography/xdh": asymmetric(PYCA, "python", "X25519/X448", "key-agreement", "X25519/X448 key agreement via pyca/cryptography"),
  "source/python-cryptography/ecdh": asymmetric(PYCA, "python", "ECDH", "key-agreement", "ECDH key agreement via pyca/cryptography"),
  "source/python-cryptography/ecdsa": asymmetric(PYCA, "python", "ECDSA", "signing", "ECDSA signature via pyca/cryptography"),
  "source/python-cryptography/rsa-signature": asymmetric(PYCA, "python", "RSA", "signing", "RSA signature padding via pyca/cryptography"),
  "source/python-cryptography/rsa-oaep": asymmetric(PYCA, "python", "RSA", "encryption", "RSA-OAEP encryption via pyca/cryptography"),

  // ---------- Python: PyCryptodome ----------
  "source/pycryptodome/keygen-rsa": asymmetric(PYCRYPTODOME, "python", "RSA", "key-generation", "RSA key generation via PyCryptodome"),
  "source/pycryptodome/keygen-ec": asymmetric(PYCRYPTODOME, "python", "EC", "key-generation", "Elliptic-curve key generation via PyCryptodome"),
  "source/pycryptodome/keygen-dsa": asymmetric(PYCRYPTODOME, "python", "DSA", "key-generation", "DSA key generation via PyCryptodome", "signing"),
  "source/pycryptodome/rsa-oaep": asymmetric(PYCRYPTODOME, "python", "RSA", "encryption", "RSA-OAEP encryption via PyCryptodome"),
  "source/pycryptodome/rsa-signature": asymmetric(PYCRYPTODOME, "python", "RSA", "signing", "RSA signature via PyCryptodome"),
  "source/pycryptodome/dss": asymmetric(PYCRYPTODOME, "python", "ECDSA/DSA", "signing", "ECDSA/DSA signature via PyCryptodome"),
  "source/pycryptodome/weak-hash": weakHash(PYCRYPTODOME, "python", "Weak hash algorithm via PyCryptodome"),
  "source/pycryptodome/weak-cipher": weakCipher(PYCRYPTODOME, "python", "Weak symmetric cipher via PyCryptodome"),

  // ---------- Python: hashlib ----------
  "source/python-hashlib/weak-hash": weakHash(HASHLIB, "python", "Weak hash algorithm via hashlib"),
  "source/python-hashlib/weak-hash-non-security": weakHashNonSecurity(HASHLIB, "python", "Weak hash declared non-security via hashlib"),

  // ---------- Go ----------
  "source/go/keygen-rsa": asymmetric(GO, "go", "RSA", "key-generation", "RSA key generation via Go crypto/rsa"),
  "source/go/rsa-signature": asymmetric(GO, "go", "RSA", "signing", "RSA signature via Go crypto/rsa"),
  "source/go/rsa-encryption": asymmetric(GO, "go", "RSA", "encryption", "RSA encryption via Go crypto/rsa"),
  "source/go/keygen-ec": asymmetric(GO, "go", "EC", "key-generation", "ECDSA key generation via Go crypto/ecdsa", "signing"),
  "source/go/ecdsa": asymmetric(GO, "go", "ECDSA", "signing", "ECDSA signature via Go crypto/ecdsa"),
  "source/go/ecdh": asymmetric(GO, "go", "ECDH/X25519", "key-agreement", "ECDH/X25519 key agreement via Go crypto/ecdh"),
  "source/go/elliptic": asymmetric(GO, "go", "EC", "key-agreement", "Low-level elliptic-curve use via Go crypto/elliptic"),
  "source/go/dsa": asymmetric(GO, "go", "DSA", "signing", "DSA via Go crypto/dsa"),
  "source/go/ed25519": asymmetric(GO, "go", "EdDSA", "signing", "Ed25519 via Go crypto/ed25519"),
  "source/go/curve25519": asymmetric(GO, "go", "X25519", "key-agreement", "X25519 via golang.org/x/crypto/curve25519"),
  "source/go/weak-hash": weakHash(GO, "go", "Weak hash algorithm via Go crypto/md5 or crypto/sha1"),
  "source/go/weak-cipher": weakCipher(GO, "go", "Weak symmetric cipher via Go crypto/des or crypto/rc4"),

  // ---------- JVM (Java, Kotlin, Scala) ----------
  "source/java/keygen-rsa": asymmetric(JCA, "java", "RSA", "key-generation", "RSA key-pair generation via JCA KeyPairGenerator"),
  "source/java/keygen-ec": asymmetric(JCA, "java", "EC", "key-generation", "Elliptic-curve key-pair generation via JCA KeyPairGenerator"),
  "source/java/keygen-dsa": asymmetric(JCA, "java", "DSA", "key-generation", "DSA key-pair generation via JCA KeyPairGenerator", "signing"),
  "source/java/keygen-dh": asymmetric(JCA, "java", "DH", "key-generation", "Diffie-Hellman key-pair generation via JCA KeyPairGenerator", "key-agreement"),
  "source/java/keygen-eddsa": asymmetric(JCA, "java", "EdDSA", "key-generation", "EdDSA key-pair generation via JCA KeyPairGenerator", "signing"),
  "source/java/keygen-xdh": asymmetric(JCA, "java", "XDH", "key-generation", "X25519/X448 key-pair generation via JCA KeyPairGenerator", "key-agreement"),
  "source/java/rsa-signature": asymmetric(JCA, "java", "RSA", "signing", "RSA signature via JCA Signature"),
  "source/java/ecdsa": asymmetric(JCA, "java", "ECDSA", "signing", "ECDSA signature via JCA Signature"),
  "source/java/dsa-signature": asymmetric(JCA, "java", "DSA", "signing", "DSA signature via JCA Signature"),
  "source/java/eddsa": asymmetric(JCA, "java", "EdDSA", "signing", "EdDSA signature via JCA Signature"),
  "source/java/key-agreement": asymmetric(JCA, "java", "ECDH/DH/XDH", "key-agreement", "Key agreement via JCA KeyAgreement"),
  "source/java/rsa-encryption": asymmetric(JCA, "java", "RSA", "encryption", "RSA encryption via JCA Cipher"),
  "source/java/weak-hash": weakHash(JCA, "java", "Weak hash algorithm via JCA MessageDigest"),
  "source/java/weak-cipher": weakCipher(JCA, "java", "Weak symmetric cipher via JCA Cipher"),

  // ---------- Key material (every language) ----------
  "keys/private-key-block": {
    category: "keys",
    title: "Hardcoded private key block",
    primitive: "private key",
    usage: "key-material",
    findingUsage: ["secret-material"],
    language: "any",
    api: "PEM",
    confidence: "confirmed",
    severity: "critical",
    pq: "vulnerable",
    recommendation: "Remove the key from source, rotate it immediately, and load secrets from a vault/KMS.",
    references: [CITE.cwe321, CITE.cwe798],
  },
  "keys/public-key-block": {
    category: "keys",
    title: "Embedded PEM public key",
    primitive: "public key",
    usage: "key-material",
    // What the key is for follows from its parsed algorithm (the risk engine reads it).
    findingUsage: [],
    language: "any",
    api: "PEM",
    confidence: "confirmed",
    severity: "medium",
    pq: "vulnerable",
    recommendation:
      "Inventory the key: a pinned classical public key is a trust anchor that needs a post-quantum migration plan (ML-DSA, FIPS 204).",
    references: [REFS.fips204, REFS.ir8547],
  },

  // ---------- Coverage (a gap is never silent) ----------
  "source/unreadable-path": coverage(
    "Paths that could not be read",
    "Grant the scanning user read access to these paths (or exclude them deliberately) so they are not a silent gap in the inventory.",
  ),
  "source/scan-truncated": coverage(
    "Source scan stopped at a resource limit",
    "Some files were not analyzed. Raise maxFiles/maxTotalBytes or scan subdirectories individually for full coverage.",
  ),
  "source/file-too-large": coverage(
    "Files above the per-file size limit were not analysed",
    "Large files (minified bundles, vendored libraries, data dumps) can hold crypto and keys. Raise maxFileBytes or scan them separately.",
  ),
  "source/binary-skipped": coverage(
    "Binary-looking files were not analysed",
    "Binary files (DER keys, keystores, archives, compiled code) are not parsed. Check that none of them is key material.",
  ),
  "source/directories-skipped": coverage(
    "Dependency, build, virtual-environment and cache directories skipped by default",
    "These directories hold installed dependencies, build output, Python virtual environments or tool caches, not the project's own code; installed dependencies are covered by the manifest scan instead. To include one, scan it directly (the same defaults then apply below it).",
  ),
  "source/non-code-skipped": coverage(
    "Source maps and non-code binary files not analysed",
    "Source maps repeat the sources they were generated from, and images, fonts, media, WebAssembly and Python bytecode hold no source code or PEM text to match. They are listed for completeness and are not a coverage gap.",
  ),
  "source/findings-capped": coverage(
    "Files with more matches than the per-file cap",
    "Only the first matches in these files are reported. Review each file as a whole.",
  ),
  "source/ast-fallback": coverage(
    "JavaScript/TypeScript files not analysed by the AST",
    "Files that did not parse (syntax the parser does not accept, or over the parse-size limit) were matched by the lower-confidence regex sweep, which does not exclude comments or resolve imports; files over the per-file size limit were not read at all. Dependency findings are not reconciled against incomplete source evidence.",
  ),
} satisfies Record<string, RuleSpec>;

export type RuleId = keyof typeof CATALOGUE;

export interface SourceRule extends RuleSpec {
  readonly id: RuleId;
}

/** The full catalogue, in declaration order. */
export const SOURCE_RULES: readonly SourceRule[] = (Object.keys(CATALOGUE) as RuleId[]).map((id) => ({
  id,
  ...CATALOGUE[id],
}));

const RULES_BY_ID: ReadonlyMap<string, SourceRule> = new Map(SOURCE_RULES.map((rule) => [rule.id, rule]));

export function sourceRule(id: RuleId): SourceRule {
  const rule = RULES_BY_ID.get(id);
  if (!rule) throw new Error(`Unknown source rule: ${id}`);
  return rule;
}

// ---------------------------------------------------------------------------
// Selections and assessment (shared by the AST and regex paths)
// ---------------------------------------------------------------------------

export type HashRole = "security" | "non-security";

/** What a matcher concluded about one call site, before file-context calibration. */
export interface RuleSelection {
  readonly rule: RuleId;
  /** Canonical primitive label for inventory, e.g. `RSA-2048`, `ECDH-P-256`, `SHA-1`, `JWT-RS256`. */
  readonly algorithm?: string;
  /** Short detail appended to the rule title. */
  readonly detail?: string;
  /** RSA/DSA/DH size in bits, when statically known. */
  readonly bits?: number;
  /** Elliptic curve (friendly name), when statically known. */
  readonly curve?: string;
  /** Digest named alongside a signature algorithm, when statically known. */
  readonly digest?: string;
  /** Role the surrounding code gives a weak digest. */
  readonly role?: HashRole;
  /** The name or keyword that established `role`. */
  readonly roleSignal?: string;
  /** Confidence ceiling below the rule's own (a library default, a heuristic). */
  readonly tierCap?: Confidence;
  /** Overrides for parsed key material, whose verdict comes from the key itself. */
  readonly severity?: Severity;
  readonly pq?: PqStatus;
  readonly note?: string;
}

/** One match, located in the file and carrying the evidence tier the matcher earned. */
export interface RuleHit {
  readonly index: number;
  readonly tier: Confidence;
  readonly selection: RuleSelection;
}

export interface Assessment {
  readonly rule: SourceRule;
  readonly title: string;
  readonly severity: Severity;
  readonly pq: PqStatus;
  readonly confidence: Confidence;
  readonly algorithm?: string;
  /** Why the parameters are broken classically today, when they are (see `Finding.classicalBreak`). */
  readonly classicalBreak?: string;
  readonly recommendation: string;
  readonly references: Reference[];
}

const SEVERITY_RANK: readonly Severity[] = ["info", "low", "medium", "high", "critical"];
const CONFIDENCE_RANK: readonly Confidence[] = ["low", "medium", "high", "confirmed"];

function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK.indexOf(a) >= SEVERITY_RANK.indexOf(b) ? a : b;
}

export function minConfidence(a: Confidence, b: Confidence): Confidence {
  return CONFIDENCE_RANK.indexOf(a) <= CONFIDENCE_RANK.indexOf(b) ? a : b;
}

const WEAK_DIGEST = /md[245]|sha-?1(?!\d)/i;

/** Bits of security implied by a curve name (`P-256`, `secp384r1`, `brainpoolP256r1`). */
function curveBits(curve: string): number | null {
  const match = /(\d{3})/.exec(curve);
  return match?.[1] ? Number(match[1]) : null;
}

/**
 * Turn a selection into the finding's severity, verdict and advice. Weak
 * parameters are graded here, once, for every language: a modulus under 2048
 * bits or a curve under 224 bits is breakable today (SP 800-131A), and a
 * signature over MD5/SHA-1 is forgeable today.
 */
export function assess(hit: RuleHit): Assessment {
  const selection = hit.selection;
  const rule = sourceRule(selection.rule);
  let severity = selection.severity ?? rule.severity;
  let confidence = minConfidence(hit.tier, rule.confidence);
  const notes: string[] = selection.note ? [selection.note] : [];
  const breaks: string[] = [];
  const references = [...rule.references];
  const cite = (ref: Reference): void => {
    if (!references.some((r) => r.label === ref.label)) references.push(ref);
  };

  if (selection.bits !== undefined && selection.bits < 2048) {
    severity = maxSeverity(severity, selection.bits < 1024 ? "critical" : "high");
    notes.push(
      `The ${selection.bits}-bit size is below the SP 800-131A minimum of 2048 bits, so it is breakable without a quantum computer; replace it now.`,
    );
    breaks.push(`the ${selection.bits}-bit size is below the SP 800-131A minimum of 2048 bits`);
    cite(REFS.sp800131a);
  }
  const strength = selection.curve ? curveBits(selection.curve) : null;
  if (selection.curve && strength !== null && strength < 224) {
    severity = maxSeverity(severity, "high");
    notes.push(`The ${selection.curve} curve is below the SP 800-131A minimum of 224 bits and is weak today; replace it now.`);
    breaks.push(`the ${selection.curve} curve is below the SP 800-131A minimum of 224 bits`);
    cite(REFS.sp800131a);
  }
  if (selection.digest && WEAK_DIGEST.test(selection.digest)) {
    severity = maxSeverity(severity, "high");
    notes.push(
      "The signature is computed over MD5 or SHA-1, which SP 800-131A disallows for signature generation: collisions make it forgeable today.",
    );
    breaks.push(`the signature is computed over ${selection.digest}, and SP 800-131A disallows MD5 and SHA-1 for signature generation`);
    cite(REFS.sp800131a);
  }
  if (rule.roleSensitive) {
    if (selection.role === "security") {
      severity = maxSeverity(severity, "high");
      notes.push(`The surrounding code (${selection.roleSignal ?? "context"}) indicates a security use.`);
    } else {
      notes.push(
        "Nothing around this call shows what the digest protects, so it is rated medium: it is urgent if it guards signatures, passwords or integrity, and low priority if it is only an identifier (ETag, cache key).",
      );
    }
  } else if (selection.role === "non-security" && selection.roleSignal) {
    notes.push(`The surrounding code (${selection.roleSignal}) shows this digest is not a security control.`);
  }
  if (selection.tierCap) confidence = minConfidence(confidence, selection.tierCap);

  return {
    rule,
    title: selection.detail ? `${rule.title} (${selection.detail})` : rule.title,
    severity,
    pq: selection.pq ?? rule.pq,
    confidence,
    algorithm: selection.algorithm,
    ...(breaks.length > 0 ? { classicalBreak: breaks.join("; ") } : {}),
    recommendation: [...notes, rule.recommendation].join(" "),
    references,
  };
}

// ---------------------------------------------------------------------------
// Shared classifiers
// ---------------------------------------------------------------------------

const WEAK_HASH_NAME = /^(?:md5|sha-?1)$/i;
const WEAK_CIPHER_NAME = /des|rc4|rc2/i;

function hashLabel(name: string): string {
  return /md5/i.test(name) ? "MD5" : "SHA-1";
}

function sized(family: string, bits: number | undefined): string {
  return bits === undefined ? family : `${family}-${bits}`;
}

function friendlyCurve(name: string | undefined): string | undefined {
  return name ? (curveFriendlyName(name) ?? name) : undefined;
}

/** Finite-field groups known to node:crypto `getDiffieHellman`, by modulus size. */
const DH_GROUP_BITS: Readonly<Record<string, number>> = {
  modp1: 768,
  modp2: 1024,
  modp5: 1536,
  modp14: 2048,
  modp15: 3072,
  modp16: 4096,
  modp17: 6144,
  modp18: 8192,
};

function groupBits(group: string | undefined): number | undefined {
  if (!group) return undefined;
  const named = DH_GROUP_BITS[group.toLowerCase()];
  if (named !== undefined) return named;
  const ffdhe = /^ffdhe(\d{4})$/i.exec(group)?.[1]; // RFC 7919 groups
  return ffdhe ? Number(ffdhe) : undefined;
}

export const JWT_ALGORITHM = /^(?:none|HS(?:256|384|512)|(?:RS|PS)(?:256|384|512)|ES(?:256K?|384|512)|EdDSA|Ed25519|Ed448|RSA1_5|RSA-OAEP(?:-(?:256|384|512))?|ECDH-ES(?:\+A(?:128|192|256)KW)?)$/;

export function jwtClass(alg: string): JwtClass | null {
  if (!JWT_ALGORITHM.test(alg)) return null;
  if (alg === "none") return "alg-none";
  if (alg.startsWith("HS")) return "hmac";
  if (alg.startsWith("RS") && !alg.startsWith("RSA")) return "rsa";
  if (alg.startsWith("PS")) return "rsa";
  if (alg.startsWith("ES")) return "ecdsa";
  if (alg.startsWith("Ed")) return "eddsa";
  if (alg.startsWith("RSA")) return "rsa-key-transport";
  return "ecdh-key-agreement";
}

/** The rule for `cls` in `library`, or null when the library cannot produce that class. */
function jwtRuleId(library: JwtLibrary, cls: JwtClass): RuleId | null {
  const rule = RULES_BY_ID.get(`jwt/${library}/${cls}`);
  return rule ? rule.id : null;
}

function jwtSelection(library: JwtLibrary, alg: string, detail = alg): RuleSelection | null {
  const cls = jwtClass(alg);
  const rule = cls ? jwtRuleId(library, cls) : null;
  return rule ? { rule, algorithm: `JWT-${alg}`, detail } : null;
}

function jwtUnresolved(library: "jsonwebtoken" | "jose", detail: string): RuleSelection {
  return { rule: `jwt/${library}/algorithm-unresolved`, detail };
}

// ---------------------------------------------------------------------------
// JavaScript / TypeScript: the call table the AST scanner interprets
// ---------------------------------------------------------------------------

export type JsApi = "node:crypto" | "webcrypto" | "jsonwebtoken" | "jose";

/** Where a call carries its algorithm. */
export type JsArgument =
  /** The call itself is the finding (e.g. `publicEncrypt`). */
  | { readonly from: "call" }
  /** A static string or number at `index`; scalar options read from the object at `paramsAt`. */
  | { readonly from: "value"; readonly index: number; readonly paramsAt?: number }
  /** A WebCrypto AlgorithmIdentifier at `index`: a name, or `{ name, ...params }`. */
  | { readonly from: "algorithm"; readonly index: number }
  /** Property `keys` of the options object at `index`, a string or an array of strings. */
  | { readonly from: "options"; readonly index: number; readonly keys: readonly string[] };

/** Static facts the AST extracted from one call, fed to a matcher's classifier. */
export interface CallFacts {
  readonly method: string;
  /** The static algorithm string, or null. */
  readonly token: string | null;
  /** A static number at the algorithm position (a DH prime length), or null. */
  readonly size: number | null;
  /** An algorithm is supplied, but not as a static value. */
  readonly dynamic: boolean;
  /** No algorithm is supplied at all (library default applies). */
  readonly absent: boolean;
  /** Static scalar parameters (`modulusLength`, `namedCurve`, `hash`, ...). */
  readonly params: Readonly<Record<string, string | number>>;
  /** The jose builder class a method was called on. */
  readonly receiver?: string;
  readonly role?: HashRole;
  readonly roleSignal?: string;
}

export interface JsCallMatcher {
  readonly api: JsApi;
  readonly methods: readonly string[];
  /** The method name alone identifies node:crypto, so an unresolved receiver still matches, at `high`. */
  readonly distinctive?: boolean;
  /** Match `new Class()` rather than a call. */
  readonly construct?: boolean;
  /** Match a method of a jose builder instance of one of these classes. */
  readonly receivers?: readonly string[];
  readonly argument: JsArgument;
  /** Ask the AST for the digest's role in the surrounding code. */
  readonly needsRole?: boolean;
  readonly classify: (facts: CallFacts) => RuleSelection | null;
}

function str(value: string | number | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function num(value: string | number | undefined): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function nodeHash(f: CallFacts): RuleSelection | null {
  if (!f.token || !WEAK_HASH_NAME.test(f.token)) return null;
  const base = { algorithm: hashLabel(f.token), detail: f.token, roleSignal: f.roleSignal };
  return f.role === "non-security"
    ? { ...base, rule: "source/node-crypto/weak-hash-non-security", role: f.role }
    : { ...base, rule: "source/node-crypto/weak-hash", role: f.role };
}

function nodeCipher(f: CallFacts): RuleSelection | null {
  if (!f.token || !WEAK_CIPHER_NAME.test(f.token)) return null;
  return { rule: "source/node-crypto/weak-cipher", algorithm: f.token.toUpperCase(), detail: f.token };
}

function nodeLegacyDigest(f: CallFacts): RuleSelection | null {
  if (!f.token || !WEAK_HASH_NAME.test(f.token)) return null;
  const construction = f.method === "createHmac" ? "HMAC" : f.method.startsWith("hkdf") ? "HKDF" : "PBKDF2";
  return {
    rule: "source/node-crypto/legacy-digest",
    algorithm: `${construction}-${hashLabel(f.token)}`,
    detail: `${f.method} ${f.token}`,
  };
}

function keygenDetail(type: string, bits: number | undefined, curve: string | undefined): string {
  if (bits !== undefined) return `${type}, ${bits}-bit`;
  return curve ? `${type}, ${curve}` : type;
}

/** `generateKeyPair(Sync)(type, options)`: the key type decides the rule. */
function nodeKeygen(f: CallFacts): RuleSelection | null {
  const type = f.token?.toLowerCase();
  if (!type) return null;
  switch (type) {
    case "rsa":
    case "rsa-pss": {
      const bits = num(f.params.modulusLength);
      return {
        rule: "source/node-crypto/keygen-rsa",
        algorithm: sized(type === "rsa" ? "RSA" : "RSA-PSS", bits),
        bits,
        digest: str(f.params.hashAlgorithm) ?? str(f.params.hash),
        detail: keygenDetail(type, bits, undefined),
      };
    }
    case "dsa": {
      const bits = num(f.params.modulusLength);
      return { rule: "source/node-crypto/keygen-dsa", algorithm: sized("DSA", bits), bits, detail: keygenDetail(type, bits, undefined) };
    }
    case "ec": {
      const curve = friendlyCurve(str(f.params.namedCurve));
      return {
        rule: "source/node-crypto/keygen-ec",
        algorithm: curve ? `ECDSA-${curve}` : "EC",
        curve,
        detail: keygenDetail(type, undefined, curve),
      };
    }
    case "ed25519":
    case "ed448":
      return { rule: "source/node-crypto/keygen-eddsa", algorithm: type === "ed25519" ? "Ed25519" : "Ed448", detail: type };
    case "x25519":
    case "x448":
      return { rule: "source/node-crypto/keygen-xdh", algorithm: type === "x25519" ? "X25519" : "X448", detail: type };
    case "dh": {
      const bits = num(f.params.primeLength) ?? groupBits(str(f.params.group));
      return { rule: "source/node-crypto/keygen-dh", algorithm: sized("DH", bits), bits, detail: keygenDetail(type, bits, undefined) };
    }
    default:
      return null; // ml-dsa-*, ml-kem-*, slh-dsa-*: post-quantum, nothing to migrate
  }
}

function signatureFamily(token: string | null | undefined): string {
  if (!token) return "RSA/DSA/ECDSA";
  if (/ecdsa/i.test(token)) return "ECDSA";
  if (/dsa/i.test(token)) return "DSA";
  if (/rsa/i.test(token)) return "RSA";
  return "RSA/DSA/ECDSA";
}

/** `createSign(alg)` / `createVerify(alg)`: always a classical signature; the key decides RSA vs ECDSA vs DSA. */
function nodeSignature(f: CallFacts): RuleSelection {
  return {
    rule: "source/node-crypto/signature",
    algorithm: signatureFamily(f.token),
    digest: f.token ?? undefined,
    detail: f.token ? `${f.method} ${f.token}` : f.method,
  };
}

/** One-shot `sign(alg, data, key)`: a digest name means RSA/DSA/ECDSA; `null` means Ed25519/Ed448/ML-DSA, key-determined. */
function nodeOneShotSignature(f: CallFacts): RuleSelection | null {
  return f.token ? nodeSignature(f) : null;
}

function nodeEcdh(f: CallFacts): RuleSelection {
  const curve = friendlyCurve(f.token ?? undefined);
  return { rule: "source/node-crypto/ecdh", algorithm: curve ? `ECDH-${curve}` : "ECDH", curve, detail: curve };
}

function nodeDh(f: CallFacts): RuleSelection {
  const bits = f.size ?? undefined;
  return { rule: "source/node-crypto/dh", algorithm: sized("DH", bits), bits, detail: bits ? `${bits}-bit prime` : undefined };
}

function nodeDhGroup(f: CallFacts): RuleSelection {
  const bits = groupBits(f.token ?? undefined);
  return { rule: "source/node-crypto/dh", algorithm: sized("DH", bits), bits, detail: f.token ?? undefined };
}

type WebCryptoFamily = "rsa-sig" | "rsa-oaep" | "ecdsa" | "ecdh" | "eddsa" | "xdh";

/** WebCrypto algorithm names are matched case-insensitively, per the spec. */
function webCryptoFamily(name: string | null): WebCryptoFamily | null {
  switch (name?.toUpperCase()) {
    case "RSASSA-PKCS1-V1_5":
    case "RSA-PSS":
      return "rsa-sig";
    case "RSA-OAEP":
      return "rsa-oaep";
    case "ECDSA":
      return "ecdsa";
    case "ECDH":
      return "ecdh";
    case "ED25519":
    case "ED448":
      return "eddsa";
    case "X25519":
    case "X448":
      return "xdh";
    default:
      return null;
  }
}

function webCryptoCurveLabel(prefix: string, curve: string | undefined): string {
  return curve ? `${prefix}-${curve}` : prefix;
}

/** `generateKey` / `importKey` / `unwrapKey`: a key of this algorithm now exists. */
function webCryptoKey(f: CallFacts): RuleSelection | null {
  const family = webCryptoFamily(f.token);
  const name = f.token ?? "";
  const detail = `${f.method} ${name}`;
  switch (family) {
    case "rsa-sig":
    case "rsa-oaep": {
      const bits = num(f.params.modulusLength);
      return { rule: "source/webcrypto/keygen-rsa", algorithm: sized("RSA", bits), bits, digest: str(f.params.hash), detail };
    }
    case "ecdsa":
    case "ecdh": {
      const curve = friendlyCurve(str(f.params.namedCurve));
      return {
        rule: "source/webcrypto/keygen-ec",
        algorithm: webCryptoCurveLabel(family === "ecdsa" ? "ECDSA" : "ECDH", curve),
        curve,
        detail,
      };
    }
    case "eddsa":
      return { rule: "source/webcrypto/keygen-eddsa", algorithm: /448/.test(name) ? "Ed448" : "Ed25519", detail };
    case "xdh":
      return { rule: "source/webcrypto/keygen-xdh", algorithm: /448/.test(name) ? "X448" : "X25519", detail };
    default:
      return null;
  }
}

function webCryptoSign(f: CallFacts): RuleSelection | null {
  const detail = `${f.method} ${f.token ?? ""}`;
  switch (webCryptoFamily(f.token)) {
    case "rsa-sig":
      return { rule: "source/webcrypto/rsa-signature", algorithm: "RSA", digest: str(f.params.hash), detail };
    case "ecdsa":
      return { rule: "source/webcrypto/ecdsa", algorithm: "ECDSA", digest: str(f.params.hash), detail };
    case "eddsa":
      return { rule: "source/webcrypto/eddsa", algorithm: /448/.test(f.token ?? "") ? "Ed448" : "Ed25519", detail };
    default:
      return null;
  }
}

function webCryptoDerive(f: CallFacts): RuleSelection | null {
  const family = webCryptoFamily(f.token);
  if (family === "ecdh") return { rule: "source/webcrypto/key-agreement", algorithm: "ECDH", detail: `${f.method} ECDH` };
  if (family === "xdh") {
    const algorithm = /448/.test(f.token ?? "") ? "X448" : "X25519";
    return { rule: "source/webcrypto/key-agreement", algorithm, detail: `${f.method} ${algorithm}` };
  }
  return null;
}

function webCryptoEncrypt(f: CallFacts): RuleSelection | null {
  return webCryptoFamily(f.token) === "rsa-oaep"
    ? { rule: "source/webcrypto/rsa-oaep", algorithm: "RSA-OAEP", detail: `${f.method} RSA-OAEP` }
    : null;
}

/** An algorithm token, an unresolved marker, or nothing, for a JWT call. */
function jwtFromFacts(library: "jsonwebtoken" | "jose", f: CallFacts, whenAbsent: RuleSelection | null): RuleSelection | null {
  if (f.token) return jwtSelection(library, f.token);
  if (f.dynamic) return jwtUnresolved(library, `${f.method}, algorithm set at runtime`);
  return f.absent ? whenAbsent : null;
}

const JOSE_JWS_BUILDERS = ["SignJWT", "CompactSign", "FlattenedSign", "GeneralSign"] as const;
const JOSE_JWE_BUILDERS = ["EncryptJWT", "CompactEncrypt", "FlattenedEncrypt", "GeneralEncrypt"] as const;

export const JS_CALL_MATCHERS: readonly JsCallMatcher[] = [
  // node:crypto: weak primitives
  { api: "node:crypto", methods: ["createHash"], distinctive: true, argument: { from: "value", index: 0 }, needsRole: true, classify: nodeHash },
  { api: "node:crypto", methods: ["hash"], argument: { from: "value", index: 0 }, needsRole: true, classify: nodeHash },
  {
    api: "node:crypto",
    methods: ["createCipheriv", "createDecipheriv", "createCipher", "createDecipher"],
    distinctive: true,
    argument: { from: "value", index: 0 },
    classify: nodeCipher,
  },
  { api: "node:crypto", methods: ["createHmac", "hkdf", "hkdfSync"], argument: { from: "value", index: 0 }, classify: nodeLegacyDigest },
  { api: "node:crypto", methods: ["pbkdf2", "pbkdf2Sync"], argument: { from: "value", index: 4 }, classify: nodeLegacyDigest },
  // node:crypto: asymmetric
  {
    api: "node:crypto",
    methods: ["generateKeyPair", "generateKeyPairSync"],
    distinctive: true,
    argument: { from: "value", index: 0, paramsAt: 1 },
    classify: nodeKeygen,
  },
  { api: "node:crypto", methods: ["createSign", "createVerify"], distinctive: true, argument: { from: "value", index: 0 }, classify: nodeSignature },
  { api: "node:crypto", methods: ["sign", "verify"], argument: { from: "value", index: 0 }, classify: nodeOneShotSignature },
  { api: "node:crypto", methods: ["createECDH"], distinctive: true, argument: { from: "value", index: 0 }, classify: nodeEcdh },
  { api: "node:crypto", methods: ["createDiffieHellman"], distinctive: true, argument: { from: "value", index: 0 }, classify: nodeDh },
  {
    api: "node:crypto",
    methods: ["createDiffieHellmanGroup", "getDiffieHellman"],
    distinctive: true,
    argument: { from: "value", index: 0 },
    classify: nodeDhGroup,
  },
  {
    api: "node:crypto",
    methods: ["diffieHellman"],
    distinctive: true,
    argument: { from: "call" },
    classify: () => ({ rule: "source/node-crypto/key-agreement" }),
  },
  {
    api: "node:crypto",
    methods: ["publicEncrypt", "privateDecrypt"],
    distinctive: true,
    argument: { from: "call" },
    classify: (f) => ({ rule: "source/node-crypto/rsa-encryption", algorithm: "RSA", detail: f.method }),
  },
  {
    api: "node:crypto",
    methods: ["privateEncrypt", "publicDecrypt"],
    distinctive: true,
    argument: { from: "call" },
    classify: (f) => ({ rule: "source/node-crypto/rsa-private-encrypt", algorithm: "RSA", detail: f.method }),
  },
  // WebCrypto
  { api: "webcrypto", methods: ["generateKey"], argument: { from: "algorithm", index: 0 }, classify: webCryptoKey },
  { api: "webcrypto", methods: ["importKey"], argument: { from: "algorithm", index: 2 }, classify: webCryptoKey },
  { api: "webcrypto", methods: ["unwrapKey"], argument: { from: "algorithm", index: 4 }, classify: webCryptoKey },
  { api: "webcrypto", methods: ["sign", "verify"], argument: { from: "algorithm", index: 0 }, classify: webCryptoSign },
  { api: "webcrypto", methods: ["deriveKey", "deriveBits"], argument: { from: "algorithm", index: 0 }, classify: webCryptoDerive },
  { api: "webcrypto", methods: ["encrypt", "decrypt"], argument: { from: "algorithm", index: 0 }, classify: webCryptoEncrypt },
  { api: "webcrypto", methods: ["wrapKey", "unwrapKey"], argument: { from: "algorithm", index: 3 }, classify: webCryptoEncrypt },
  // jsonwebtoken: sign() defaults to HS256; verify() without an allow-list accepts whatever the key permits.
  {
    api: "jsonwebtoken",
    methods: ["sign"],
    argument: { from: "options", index: 2, keys: ["algorithm"] },
    classify: (f) =>
      jwtFromFacts("jsonwebtoken", f, {
        rule: "jwt/jsonwebtoken/hmac",
        algorithm: "JWT-HS256",
        detail: "HS256, the library default",
        tierCap: "high",
      }),
  },
  {
    api: "jsonwebtoken",
    methods: ["verify"],
    argument: { from: "options", index: 2, keys: ["algorithms"] },
    classify: (f) => jwtFromFacts("jsonwebtoken", f, jwtUnresolved("jsonwebtoken", "verify without an algorithms allow-list")),
  },
  // jose
  {
    api: "jose",
    methods: ["jwtVerify", "compactVerify", "flattenedVerify", "generalVerify"],
    argument: { from: "options", index: 2, keys: ["algorithms"] },
    classify: (f) => jwtFromFacts("jose", f, null),
  },
  {
    api: "jose",
    methods: ["jwtDecrypt", "compactDecrypt", "flattenedDecrypt", "generalDecrypt"],
    argument: { from: "options", index: 2, keys: ["keyManagementAlgorithms"] },
    classify: (f) => jwtFromFacts("jose", f, null),
  },
  {
    api: "jose",
    methods: ["importPKCS8", "importSPKI", "importX509", "importJWK"],
    argument: { from: "value", index: 1 },
    classify: (f) => jwtFromFacts("jose", f, null),
  },
  {
    api: "jose",
    methods: ["generateKeyPair", "generateSecret"],
    argument: { from: "value", index: 0 },
    classify: (f) => jwtFromFacts("jose", f, null),
  },
  {
    api: "jose",
    methods: ["setProtectedHeader"],
    receivers: [...JOSE_JWS_BUILDERS, ...JOSE_JWE_BUILDERS],
    argument: { from: "options", index: 0, keys: ["alg"] },
    classify: (f) => jwtFromFacts("jose", f, null),
  },
  {
    api: "jose",
    methods: ["UnsecuredJWT"],
    construct: true,
    argument: { from: "call" },
    classify: () => ({ rule: "jwt/jose/alg-none", algorithm: "JWT-none", detail: "UnsecuredJWT" }),
  },
];

/** jose classes whose instances are fluent builders (every method returns the builder). */
export const JOSE_BUILDERS: ReadonlySet<string> = new Set<string>([...JOSE_JWS_BUILDERS, ...JOSE_JWE_BUILDERS]);

// ---------------------------------------------------------------------------
// Regex matchers: Python, Go, JVM, and the JavaScript fallback
// ---------------------------------------------------------------------------

export type RegexLanguage = "javascript" | "python" | "go" | "java";

export interface RegexMatcher {
  readonly language: RegexLanguage;
  /** Global; linear time (bounded quantifiers only). */
  readonly pattern: RegExp;
  /** File-level prerequisite (usually the import), tested once per file. Not global. */
  readonly gate?: RegExp;
  /** Captures, plus a bounded window of text after the match, to zero or more selections. */
  readonly classify: (match: RegExpExecArray, after: string) => readonly RuleSelection[];
  /** Source this matcher must fire on (drives the catalogue and ReDoS tests). */
  readonly sample: string;
}

/** Characters of trailing context a regex classifier may inspect. */
export const REGEX_WINDOW_CHARS = 256;

function one(selection: RuleSelection | null): readonly RuleSelection[] {
  return selection ? [selection] : [];
}

/** Read `name: value` / `name = value` scalars out of the trailing window. */
function windowNumber(after: string, pattern: RegExp): number | undefined {
  const match = pattern.exec(after);
  return match?.[1] ? Number(match[1]) : undefined;
}

function windowString(after: string, pattern: RegExp): string | undefined {
  return pattern.exec(after)?.[1];
}

function factsFor(method: string, token: string | null, params: Record<string, string | number> = {}): CallFacts {
  return { method, token, size: null, dynamic: token === null, absent: false, params };
}

const JS_MODULUS = /\bmodulusLength\s{0,8}:\s{0,8}(\d{3,5})/;
const JS_CURVE = /\bnamedCurve\s{0,8}:\s{0,8}["'`]([\w-]{1,32})["'`]/;
const JS_PRIME = /\bprimeLength\s{0,8}:\s{0,8}(\d{3,5})/;
const JS_HASH = /\bhash\s{0,8}:\s{0,8}(?:\{\s{0,8}name\s{0,8}:\s{0,8})?["'`]([\w-]{1,16})["'`]/;
const WEBCRYPTO_NAME = /["'`](RSASSA-PKCS1-v1_5|RSA-PSS|RSA-OAEP|ECDSA|ECDH|Ed25519|Ed448|X25519|X448)["'`]/i;
const JWT_USAGE = /jsonwebtoken|\bjwt\s{0,8}\.\s{0,8}(?:sign|verify|decode)/i;

function jsParams(after: string): Record<string, string | number> {
  const params: Record<string, string | number> = {};
  const modulus = windowNumber(after, JS_MODULUS);
  const curve = windowString(after, JS_CURVE);
  const prime = windowNumber(after, JS_PRIME);
  const hash = windowString(after, JS_HASH);
  if (modulus !== undefined) params.modulusLength = modulus;
  if (curve) params.namedCurve = curve;
  if (prime !== undefined) params.primeLength = prime;
  if (hash) params.hash = hash;
  return params;
}

function webCryptoRegex(method: string, after: string): RuleSelection | null {
  const name = WEBCRYPTO_NAME.exec(after)?.[1] ?? null;
  const facts = factsFor(method, name, jsParams(after));
  switch (method) {
    case "generateKey":
    case "importKey":
      return webCryptoKey(facts);
    case "sign":
    case "verify":
      return webCryptoSign(facts);
    case "deriveKey":
    case "deriveBits":
      return webCryptoDerive(facts);
    case "unwrapKey":
      return webCryptoEncrypt(facts) ?? webCryptoKey(facts);
    default:
      return webCryptoEncrypt(facts);
  }
}

const JS_REGEX: readonly RegexMatcher[] = [
  {
    language: "javascript",
    pattern: /\b(?:createHash|crypto\s{0,8}\.\s{0,8}hash)\s{0,16}\(\s{0,16}["'`]([\w-]{1,32})["'`]/g,
    classify: (m) => one(nodeHash(factsFor("createHash", m[1] ?? null))),
    sample: 'crypto.createHash("md5")',
  },
  {
    language: "javascript",
    pattern: /\bcreate(?:Cipher|Decipher)(?:iv)?\s{0,16}\(\s{0,16}["'`]([\w-]{1,64})["'`]/g,
    classify: (m) => one(nodeCipher(factsFor("createCipheriv", m[1] ?? null))),
    sample: 'crypto.createCipheriv("des-ede3-cbc", key, iv)',
  },
  {
    language: "javascript",
    pattern: /\bgenerateKeyPair(?:Sync)?\s{0,16}\(\s{0,16}["'`]([\w-]{1,24})["'`]/g,
    classify: (m, after) => one(nodeKeygen(factsFor("generateKeyPairSync", m[1] ?? null, jsParams(after)))),
    sample: 'generateKeyPairSync("rsa", { modulusLength: 2048 })',
  },
  {
    language: "javascript",
    pattern: /\b(createSign|createVerify)\s{0,16}\(\s{0,16}(?:["'`]([\w-]{1,48})["'`])?/g,
    classify: (m) => one(nodeSignature(factsFor(m[1] ?? "createSign", m[2] ?? null))),
    sample: 'crypto.createSign("RSA-SHA256")',
  },
  {
    language: "javascript",
    pattern: /\bcreateECDH\s{0,16}\(\s{0,16}(?:["'`]([\w-]{1,32})["'`])?/g,
    classify: (m) => one(nodeEcdh(factsFor("createECDH", m[1] ?? null))),
    sample: 'crypto.createECDH("prime256v1")',
  },
  {
    language: "javascript",
    pattern: /\bcreateDiffieHellman\s{0,16}\(\s{0,16}(\d{1,5})?/g,
    classify: (m) => [nodeDh({ ...factsFor("createDiffieHellman", null), size: m[1] ? Number(m[1]) : null })],
    sample: "crypto.createDiffieHellman(2048)",
  },
  {
    language: "javascript",
    pattern: /\b(?:createDiffieHellmanGroup|getDiffieHellman)\s{0,16}\(\s{0,16}(?:["'`]([\w-]{1,16})["'`])?/g,
    classify: (m) => one(nodeDhGroup(factsFor("getDiffieHellman", m[1] ?? null))),
    sample: 'crypto.getDiffieHellman("modp14")',
  },
  {
    language: "javascript",
    pattern: /\bdiffieHellman\s{0,16}\(\s{0,16}\{/g,
    classify: () => [{ rule: "source/node-crypto/key-agreement" }],
    sample: "crypto.diffieHellman({ privateKey, publicKey })",
  },
  {
    language: "javascript",
    pattern: /\b(publicEncrypt|privateDecrypt|privateEncrypt|publicDecrypt)\s{0,16}\(/g,
    classify: (m) => {
      const method = m[1] ?? "publicEncrypt";
      const rule = method === "publicEncrypt" || method === "privateDecrypt" ? "source/node-crypto/rsa-encryption" : "source/node-crypto/rsa-private-encrypt";
      return [{ rule, algorithm: "RSA", detail: method }];
    },
    sample: "crypto.publicEncrypt(publicKey, buffer)",
  },
  {
    language: "javascript",
    pattern: /\bsubtle\s{0,16}\.\s{0,16}(generateKey|importKey|sign|verify|deriveKey|deriveBits|encrypt|decrypt|wrapKey|unwrapKey)\s{0,16}\(/g,
    classify: (m, after) => one(webCryptoRegex(m[1] ?? "generateKey", after)),
    sample: 'crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"])',
  },
  {
    language: "javascript",
    gate: JWT_USAGE,
    pattern: /["'`](HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA)["'`]/g,
    classify: (m) => one(jwtSelection("jsonwebtoken", m[1] ?? "")),
    sample: 'jwt.sign(payload, key, { algorithm: "RS256" })',
  },
  {
    // "none" is an ordinary string (`display = "none"`), so unlike the
    // algorithm names above it only counts as an assignment to an `alg`,
    // `algorithm` or `algorithms` key, within the same statement. A comparison
    // (`alg === "none"`, how libraries reject it) does not match.
    language: "javascript",
    gate: JWT_USAGE,
    pattern: /\b(?:alg|algorithms?)["'`]?\s{0,8}[:=][^\]\r\n;:=]{0,64}?["'`]none["'`]/g,
    classify: () => one(jwtSelection("jsonwebtoken", "none")),
    sample: 'jwt.verify(token, key, { algorithms: ["none"] })',
  },
];

// ----- Python -----

const PYCA_GATE = /\bcryptography\b/;
const PYCRYPTODOME_GATE = /\b(?:Crypto|Cryptodome)\s{0,4}\./;
const PYJWT_GATE = /\bjwt\s{0,8}\.\s{0,8}(?:encode|decode)\s{0,8}\(|\bimport\s{1,8}jwt\b|\bfrom\s{1,8}(?:jwt|jose)\b/;
const PY_KEY_SIZE = /\bkey_size\s{0,8}=\s{0,8}(\d{3,5})/;
const PY_CURVE = /\b(SECP\d{3}[RK]1|BrainpoolP\d{3}R1|SECT\d{3}[KR]1)\b/i;
const PY_WEAK_DIGEST = /\bhashes\s{0,8}\.\s{0,8}(SHA1|MD5)\b/;
const PY_NON_SECURITY = /^[^\r\n]{0,240}?\busedforsecurity\s{0,4}=\s{0,4}False\b/;

function pyCurve(after: string): string | undefined {
  return friendlyCurve(windowString(after, PY_CURVE)?.toLowerCase());
}

function hashlibSelection(name: string, after: string): RuleSelection | null {
  if (!WEAK_HASH_NAME.test(name)) return null;
  const nonSecurity = PY_NON_SECURITY.test(after);
  return nonSecurity
    ? {
        rule: "source/python-hashlib/weak-hash-non-security",
        algorithm: hashLabel(name),
        detail: name.toLowerCase(),
        role: "non-security",
        roleSignal: "usedforsecurity=False",
      }
    : { rule: "source/python-hashlib/weak-hash", algorithm: hashLabel(name), detail: name.toLowerCase() };
}

function pyJwtList(list: string): readonly RuleSelection[] {
  const out: RuleSelection[] = [];
  for (const token of list.split(",")) {
    const alg = token.trim().replace(/^["']|["']$/g, "");
    const selection = jwtSelection("pyjwt", alg);
    if (selection) out.push(selection);
  }
  return out;
}

const PYTHON_REGEX: readonly RegexMatcher[] = [
  {
    language: "python",
    gate: PYCA_GATE,
    pattern: /\brsa\s{0,8}\.\s{0,8}generate_private_key\s{0,8}\(/g,
    classify: (_m, after) => {
      const bits = windowNumber(after, PY_KEY_SIZE);
      return [{ rule: "source/python-cryptography/keygen-rsa", algorithm: sized("RSA", bits), bits, detail: bits ? `${bits}-bit` : undefined }];
    },
    sample: "from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)",
  },
  {
    language: "python",
    gate: PYCA_GATE,
    pattern: /\bec\s{0,8}\.\s{0,8}generate_private_key\s{0,8}\(/g,
    classify: (_m, after) => {
      const curve = pyCurve(after);
      return [{ rule: "source/python-cryptography/keygen-ec", algorithm: curve ? `ECDSA-${curve}` : "EC", curve, detail: curve }];
    },
    sample: "from cryptography.hazmat.primitives.asymmetric import ec\nec.generate_private_key(ec.SECP256R1())",
  },
  {
    language: "python",
    gate: PYCA_GATE,
    pattern: /\bdsa\s{0,8}\.\s{0,8}generate_(?:private_key|parameters)\s{0,8}\(/g,
    classify: (_m, after) => {
      const bits = windowNumber(after, PY_KEY_SIZE);
      return [{ rule: "source/python-cryptography/keygen-dsa", algorithm: sized("DSA", bits), bits }];
    },
    sample: "from cryptography.hazmat.primitives.asymmetric import dsa\ndsa.generate_private_key(key_size=2048)",
  },
  {
    language: "python",
    gate: PYCA_GATE,
    pattern: /\bdh\s{0,8}\.\s{0,8}generate_parameters\s{0,8}\(/g,
    classify: (_m, after) => {
      const bits = windowNumber(after, PY_KEY_SIZE);
      return [{ rule: "source/python-cryptography/dh", algorithm: sized("DH", bits), bits }];
    },
    sample: "from cryptography.hazmat.primitives.asymmetric import dh\ndh.generate_parameters(generator=2, key_size=2048)",
  },
  {
    language: "python",
    gate: PYCA_GATE,
    pattern: /\b(X25519|X448)PrivateKey\s{0,8}\.\s{0,8}(?:generate|from_private_bytes)\s{0,8}\(/g,
    classify: (m) => [{ rule: "source/python-cryptography/xdh", algorithm: m[1] ?? "X25519", detail: m[1] }],
    sample: "from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey\nX25519PrivateKey.generate()",
  },
  {
    language: "python",
    gate: PYCA_GATE,
    pattern: /\b(Ed25519|Ed448)PrivateKey\s{0,8}\.\s{0,8}(?:generate|from_private_bytes)\s{0,8}\(/g,
    classify: (m) => [{ rule: "source/python-cryptography/keygen-eddsa", algorithm: m[1] ?? "Ed25519", detail: m[1] }],
    sample: "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\nEd25519PrivateKey.generate()",
  },
  {
    language: "python",
    gate: PYCA_GATE,
    pattern: /\bec\s{0,8}\.\s{0,8}ECDH\s{0,8}\(/g,
    classify: () => [{ rule: "source/python-cryptography/ecdh", algorithm: "ECDH" }],
    sample: "from cryptography.hazmat.primitives.asymmetric import ec\nshared = key.exchange(ec.ECDH(), peer)",
  },
  {
    language: "python",
    gate: PYCA_GATE,
    pattern: /\bec\s{0,8}\.\s{0,8}ECDSA\s{0,8}\(/g,
    classify: (_m, after) => [
      { rule: "source/python-cryptography/ecdsa", algorithm: "ECDSA", digest: windowString(after, PY_WEAK_DIGEST) },
    ],
    sample: "from cryptography.hazmat.primitives.asymmetric import ec\nkey.sign(data, ec.ECDSA(hashes.SHA256()))",
  },
  {
    language: "python",
    gate: PYCA_GATE,
    pattern: /\bpadding\s{0,8}\.\s{0,8}(PSS|PKCS1v15)\s{0,8}\(/g,
    classify: (m) => [{ rule: "source/python-cryptography/rsa-signature", algorithm: "RSA", detail: m[1] }],
    sample: "from cryptography.hazmat.primitives.asymmetric import padding\nkey.sign(data, padding.PKCS1v15(), hashes.SHA256())",
  },
  {
    language: "python",
    gate: PYCA_GATE,
    pattern: /\bpadding\s{0,8}\.\s{0,8}OAEP\s{0,8}\(/g,
    classify: () => [{ rule: "source/python-cryptography/rsa-oaep", algorithm: "RSA-OAEP" }],
    sample: "from cryptography.hazmat.primitives.asymmetric import padding\npub.encrypt(msg, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))",
  },
  {
    language: "python",
    pattern: /\bhashlib\s{0,8}\.\s{0,8}(md5|sha1)\s{0,8}\(/g,
    classify: (m, after) => one(hashlibSelection(m[1] ?? "", after)),
    sample: "import hashlib\nhashlib.md5(data)",
  },
  {
    language: "python",
    pattern: /\bhashlib\s{0,8}\.\s{0,8}new\s{0,8}\(\s{0,8}["']([\w-]{1,16})["']/g,
    classify: (m, after) => one(hashlibSelection(m[1] ?? "", after)),
    sample: 'import hashlib\nhashlib.new("sha1", data)',
  },
  {
    language: "python",
    gate: PYCRYPTODOME_GATE,
    pattern: /\bRSA\s{0,8}\.\s{0,8}generate\s{0,8}\(\s{0,8}(\d{3,5})?/g,
    classify: (m) => {
      const bits = m[1] ? Number(m[1]) : undefined;
      return [{ rule: "source/pycryptodome/keygen-rsa", algorithm: sized("RSA", bits), bits, detail: bits ? `${bits}-bit` : undefined }];
    },
    sample: "from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)",
  },
  {
    language: "python",
    gate: PYCRYPTODOME_GATE,
    pattern: /\bECC\s{0,8}\.\s{0,8}generate\s{0,8}\(/g,
    classify: (_m, after) => {
      const curve = friendlyCurve(windowString(after, /\bcurve\s{0,8}=\s{0,8}["']([\w-]{1,24})["']/));
      return [{ rule: "source/pycryptodome/keygen-ec", algorithm: curve ? `ECDSA-${curve}` : "EC", curve, detail: curve }];
    },
    sample: "from Crypto.PublicKey import ECC\nkey = ECC.generate(curve='P-256')",
  },
  {
    language: "python",
    gate: PYCRYPTODOME_GATE,
    pattern: /\bDSA\s{0,8}\.\s{0,8}generate\s{0,8}\(\s{0,8}(\d{3,5})?/g,
    classify: (m) => {
      const bits = m[1] ? Number(m[1]) : undefined;
      return [{ rule: "source/pycryptodome/keygen-dsa", algorithm: sized("DSA", bits), bits }];
    },
    sample: "from Crypto.PublicKey import DSA\nkey = DSA.generate(2048)",
  },
  {
    language: "python",
    gate: PYCRYPTODOME_GATE,
    pattern: /\bPKCS1_OAEP\s{0,8}\.\s{0,8}new\s{0,8}\(/g,
    classify: () => [{ rule: "source/pycryptodome/rsa-oaep", algorithm: "RSA-OAEP" }],
    sample: "from Crypto.Cipher import PKCS1_OAEP\ncipher = PKCS1_OAEP.new(key)",
  },
  {
    language: "python",
    gate: PYCRYPTODOME_GATE,
    pattern: /\b(pkcs1_15|pss|PKCS1_PSS|PKCS1_v1_5)\s{0,8}\.\s{0,8}new\s{0,8}\(/g,
    classify: (m) => [{ rule: "source/pycryptodome/rsa-signature", algorithm: "RSA", detail: m[1] }],
    sample: "from Crypto.Signature import pkcs1_15\nsigner = pkcs1_15.new(key)",
  },
  {
    language: "python",
    gate: PYCRYPTODOME_GATE,
    pattern: /\bDSS\s{0,8}\.\s{0,8}new\s{0,8}\(/g,
    classify: () => [{ rule: "source/pycryptodome/dss", algorithm: "ECDSA/DSA" }],
    sample: "from Crypto.Signature import DSS\nsigner = DSS.new(key, 'fips-186-3')",
  },
  {
    language: "python",
    gate: PYCRYPTODOME_GATE,
    pattern: /\b(MD5|SHA1|SHA)\s{0,8}\.\s{0,8}new\s{0,8}\(/g,
    classify: (m) => [{ rule: "source/pycryptodome/weak-hash", algorithm: m[1] === "MD5" ? "MD5" : "SHA-1", detail: m[1] }],
    sample: "from Crypto.Hash import MD5\nh = MD5.new(data)",
  },
  {
    language: "python",
    gate: PYCRYPTODOME_GATE,
    pattern: /\b(DES3|DES|ARC4|ARC2)\s{0,8}\.\s{0,8}new\s{0,8}\(/g,
    classify: (m) => [{ rule: "source/pycryptodome/weak-cipher", algorithm: m[1], detail: m[1] }],
    sample: "from Crypto.Cipher import DES3\ncipher = DES3.new(key, DES3.MODE_CBC)",
  },
  {
    language: "python",
    gate: PYJWT_GATE,
    pattern: /\balgorithm\s{0,8}=\s{0,8}["']([\w+-]{2,24})["']/g,
    classify: (m) => one(jwtSelection("pyjwt", m[1] ?? "")),
    sample: 'import jwt\njwt.encode(payload, key, algorithm="RS256")',
  },
  {
    language: "python",
    gate: PYJWT_GATE,
    pattern: /\balgorithms\s{0,8}=\s{0,8}\[([^\]\r\n]{1,256})\]/g,
    classify: (m) => pyJwtList(m[1] ?? ""),
    sample: 'import jwt\njwt.decode(token, key, algorithms=["ES256", "HS256"])',
  },
];

// ----- Go -----

const GO_BITS = /^[^)\r\n]{0,120}?,\s{0,8}(\d{3,5})\s{0,8}\)/;
const GO_CURVE = /\belliptic\s{0,4}\.\s{0,4}(P224|P256|P384|P521)\s{0,4}\(/;
const GO_WEAK_DIGEST = /\bcrypto\s{0,4}\.\s{0,4}(SHA1|MD5)\b/;

function goCurve(after: string): string | undefined {
  const name = windowString(after, GO_CURVE);
  return name ? `P-${name.slice(1)}` : undefined;
}

const GO_REGEX: readonly RegexMatcher[] = [
  {
    language: "go",
    gate: /"crypto\/rsa"/,
    pattern: /\brsa\s{0,4}\.\s{0,4}(GenerateKey|GenerateMultiPrimeKey)\s{0,4}\(/g,
    classify: (_m, after) => {
      const bits = windowNumber(after, GO_BITS);
      return [{ rule: "source/go/keygen-rsa", algorithm: sized("RSA", bits), bits, detail: bits ? `${bits}-bit` : undefined }];
    },
    sample: 'import "crypto/rsa"\nkey, err := rsa.GenerateKey(rand.Reader, 2048)',
  },
  {
    language: "go",
    gate: /"crypto\/rsa"/,
    pattern: /\brsa\s{0,4}\.\s{0,4}(SignPKCS1v15|SignPSS|VerifyPKCS1v15|VerifyPSS)\s{0,4}\(/g,
    classify: (m, after) => [
      { rule: "source/go/rsa-signature", algorithm: "RSA", digest: windowString(after, GO_WEAK_DIGEST), detail: m[1] },
    ],
    sample: 'import "crypto/rsa"\nsig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest)',
  },
  {
    language: "go",
    gate: /"crypto\/rsa"/,
    pattern: /\brsa\s{0,4}\.\s{0,4}(EncryptOAEP|DecryptOAEP|EncryptPKCS1v15|DecryptPKCS1v15|DecryptPKCS1v15SessionKey)\s{0,4}\(/g,
    classify: (m) => [{ rule: "source/go/rsa-encryption", algorithm: "RSA", detail: m[1] }],
    sample: 'import "crypto/rsa"\nct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)',
  },
  {
    language: "go",
    gate: /"crypto\/ecdsa"/,
    pattern: /\becdsa\s{0,4}\.\s{0,4}GenerateKey\s{0,4}\(/g,
    classify: (_m, after) => {
      const curve = goCurve(after);
      return [{ rule: "source/go/keygen-ec", algorithm: curve ? `ECDSA-${curve}` : "ECDSA", curve, detail: curve }];
    },
    sample: 'import "crypto/ecdsa"\nkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)',
  },
  {
    language: "go",
    gate: /"crypto\/ecdsa"/,
    pattern: /\becdsa\s{0,4}\.\s{0,4}(Sign|SignASN1|Verify|VerifyASN1)\s{0,4}\(/g,
    classify: (m) => [{ rule: "source/go/ecdsa", algorithm: "ECDSA", detail: m[1] }],
    sample: 'import "crypto/ecdsa"\nsig, err := ecdsa.SignASN1(rand.Reader, key, digest)',
  },
  {
    language: "go",
    gate: /"crypto\/ecdh"/,
    pattern: /\becdh\s{0,4}\.\s{0,4}(P256|P384|P521|X25519)\s{0,4}\(\s{0,4}\)/g,
    classify: (m) => {
      const curve = m[1] ?? "X25519";
      return [{ rule: "source/go/ecdh", algorithm: curve === "X25519" ? "X25519" : `ECDH-P-${curve.slice(1)}`, detail: curve }];
    },
    sample: 'import "crypto/ecdh"\nkey, err := ecdh.X25519().GenerateKey(rand.Reader)',
  },
  {
    language: "go",
    gate: /"crypto\/elliptic"/,
    pattern: /\belliptic\s{0,4}\.\s{0,4}(GenerateKey|Marshal|MarshalCompressed|Unmarshal|UnmarshalCompressed)\s{0,4}\(/g,
    classify: (m) => [{ rule: "source/go/elliptic", algorithm: "EC", detail: m[1] }],
    sample: 'import "crypto/elliptic"\npriv, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)',
  },
  {
    language: "go",
    gate: /"crypto\/dsa"/,
    pattern: /\bdsa\s{0,4}\.\s{0,4}(GenerateKey|GenerateParameters|Sign|Verify)\s{0,4}\(/g,
    classify: (m) => [{ rule: "source/go/dsa", algorithm: "DSA", detail: m[1] }],
    sample: 'import "crypto/dsa"\nerr := dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256)',
  },
  {
    language: "go",
    gate: /"crypto\/ed25519"/,
    pattern: /\bed25519\s{0,4}\.\s{0,4}(GenerateKey|NewKeyFromSeed|Sign|Verify|VerifyWithOptions)\s{0,4}\(/g,
    classify: (m) => [{ rule: "source/go/ed25519", algorithm: "Ed25519", detail: m[1] }],
    sample: 'import "crypto/ed25519"\npub, priv, err := ed25519.GenerateKey(rand.Reader)',
  },
  {
    language: "go",
    gate: /curve25519"/,
    pattern: /\bcurve25519\s{0,4}\.\s{0,4}(X25519|ScalarMult|ScalarBaseMult)\s{0,4}\(/g,
    classify: (m) => [{ rule: "source/go/curve25519", algorithm: "X25519", detail: m[1] }],
    sample: 'import "golang.org/x/crypto/curve25519"\nshared, err := curve25519.X25519(priv, peer)',
  },
  {
    language: "go",
    gate: /"crypto\/md5"/,
    pattern: /\bmd5\s{0,4}\.\s{0,4}(New|Sum)\s{0,4}\(/g,
    classify: () => [{ rule: "source/go/weak-hash", algorithm: "MD5", detail: "md5" }],
    sample: 'import "crypto/md5"\nsum := md5.Sum(data)',
  },
  {
    language: "go",
    gate: /"crypto\/sha1"/,
    pattern: /\bsha1\s{0,4}\.\s{0,4}(New|Sum)\s{0,4}\(/g,
    classify: () => [{ rule: "source/go/weak-hash", algorithm: "SHA-1", detail: "sha1" }],
    sample: 'import "crypto/sha1"\nh := sha1.New()',
  },
  {
    language: "go",
    gate: /"crypto\/des"/,
    pattern: /\bdes\s{0,4}\.\s{0,4}(NewCipher|NewTripleDESCipher)\s{0,4}\(/g,
    classify: (m) => [{ rule: "source/go/weak-cipher", algorithm: m[1] === "NewCipher" ? "DES" : "3DES", detail: m[1] }],
    sample: 'import "crypto/des"\nblock, err := des.NewTripleDESCipher(key)',
  },
  {
    language: "go",
    gate: /"crypto\/rc4"/,
    pattern: /\brc4\s{0,4}\.\s{0,4}NewCipher\s{0,4}\(/g,
    classify: () => [{ rule: "source/go/weak-cipher", algorithm: "RC4", detail: "rc4" }],
    sample: 'import "crypto/rc4"\nc, err := rc4.NewCipher(key)',
  },
];

// ----- JVM (JCA factory calls; Kotlin and Scala share the API) -----

const JAVA_BITS = /\binitialize\s{0,8}\(\s{0,8}(\d{3,5})/;

function javaGetInstance(factory: string): RegExp {
  return new RegExp(`\\b${factory}\\s{0,32}\\.\\s{0,32}getInstance\\s{0,32}\\(\\s{0,32}"([^"\\\\\\r\\n]{1,64})"`, "g");
}

function javaKeygen(token: string, after: string): RuleSelection | null {
  const bits = windowNumber(after, JAVA_BITS);
  const t = token.toUpperCase();
  if (t === "RSA" || t === "RSASSA-PSS") return { rule: "source/java/keygen-rsa", algorithm: sized("RSA", bits), bits, detail: token };
  if (t === "EC" || t === "ECDSA") return { rule: "source/java/keygen-ec", algorithm: "EC", detail: token };
  if (t === "DSA") return { rule: "source/java/keygen-dsa", algorithm: sized("DSA", bits), bits, detail: token };
  if (t === "DH" || t === "DIFFIEHELLMAN") return { rule: "source/java/keygen-dh", algorithm: sized("DH", bits), bits, detail: token };
  if (t === "ED25519" || t === "ED448" || t === "EDDSA") return { rule: "source/java/keygen-eddsa", algorithm: t === "ED448" ? "Ed448" : "Ed25519", detail: token };
  if (t === "X25519" || t === "X448" || t === "XDH") return { rule: "source/java/keygen-xdh", algorithm: t === "X448" ? "X448" : "X25519", detail: token };
  return null;
}

function javaSignature(token: string): RuleSelection | null {
  if (/ecdsa/i.test(token)) return { rule: "source/java/ecdsa", algorithm: "ECDSA", digest: token, detail: token };
  if (/ed25519|ed448|eddsa/i.test(token)) return { rule: "source/java/eddsa", algorithm: /448/.test(token) ? "Ed448" : "Ed25519", detail: token };
  if (/rsa|pss/i.test(token)) return { rule: "source/java/rsa-signature", algorithm: "RSA", digest: token, detail: token };
  if (/dsa/i.test(token)) return { rule: "source/java/dsa-signature", algorithm: "DSA", digest: token, detail: token };
  return null;
}

function javaKeyAgreement(token: string): RuleSelection | null {
  const t = token.toUpperCase();
  if (t === "ECDH" || t === "ECMQV") return { rule: "source/java/key-agreement", algorithm: "ECDH", detail: token };
  if (t === "DH" || t === "DIFFIEHELLMAN") return { rule: "source/java/key-agreement", algorithm: "DH", detail: token };
  if (t === "X25519" || t === "X448" || t === "XDH") return { rule: "source/java/key-agreement", algorithm: t === "X448" ? "X448" : "X25519", detail: token };
  return null;
}

function javaCipher(token: string): RuleSelection | null {
  if (/^RSA(?:\/|$)/i.test(token)) return { rule: "source/java/rsa-encryption", algorithm: "RSA", detail: token };
  const weak = /^(DESede|TripleDES|DES|RC2|RC4|ARCFOUR)(?:\/|$)/i.exec(token);
  return weak?.[1] ? { rule: "source/java/weak-cipher", algorithm: weak[1].toUpperCase(), detail: token } : null;
}

function javaDigest(token: string): RuleSelection | null {
  if (/^MD[25]$/i.test(token)) return { rule: "source/java/weak-hash", algorithm: "MD5", detail: token };
  return /^SHA(?:-?1)?$/i.test(token) ? { rule: "source/java/weak-hash", algorithm: "SHA-1", detail: token } : null;
}

const JAVA_REGEX: readonly RegexMatcher[] = [
  {
    language: "java",
    pattern: javaGetInstance("KeyPairGenerator"),
    classify: (m, after) => one(javaKeygen(m[1] ?? "", after)),
    sample: 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\nkpg.initialize(2048);',
  },
  {
    language: "java",
    pattern: javaGetInstance("Signature"),
    classify: (m) => one(javaSignature(m[1] ?? "")),
    sample: 'Signature s = Signature.getInstance("SHA256withECDSA");',
  },
  {
    language: "java",
    pattern: javaGetInstance("KeyAgreement"),
    classify: (m) => one(javaKeyAgreement(m[1] ?? "")),
    sample: 'KeyAgreement ka = KeyAgreement.getInstance("ECDH");',
  },
  {
    language: "java",
    pattern: javaGetInstance("Cipher"),
    classify: (m) => one(javaCipher(m[1] ?? "")),
    sample: 'Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");',
  },
  {
    language: "java",
    pattern: javaGetInstance("MessageDigest"),
    classify: (m) => one(javaDigest(m[1] ?? "")),
    sample: 'MessageDigest md = MessageDigest.getInstance("MD5");',
  },
];

export const REGEX_MATCHERS: readonly RegexMatcher[] = [...JS_REGEX, ...PYTHON_REGEX, ...GO_REGEX, ...JAVA_REGEX];
