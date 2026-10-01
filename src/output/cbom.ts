/**
 * CycloneDX 1.6 Cryptography Bill of Materials (CBOM) emitter.
 *
 * A CBOM is the standardized, machine-readable inventory of the cryptographic
 * assets a system uses. Emitting one is what lets cryptosweep's output flow into
 * the SBOM / compliance / risk toolchains organizations already run, rather than
 * being one more bespoke report.
 *
 * What goes in, and only from structured finding fields (never from titles):
 *   - one `algorithm` asset per distinct algorithm, typed with the CycloneDX
 *     primitive vocabulary, its OID (the certificate's own signature OID when
 *     the scanner read one), and its NIST quantum security category;
 *   - one `certificate` asset per parsed certificate, linked to its signature
 *     algorithm and to its subject public key;
 *   - key material (`related-crypto-material`) for committed private keys and
 *     embedded public keys, one per occurrence;
 *   - the negotiated `protocol`, when a live session was observed;
 *   - flagged dependencies as `library` components that `provide` the
 *     algorithms the registry lists for them.
 * Status findings ("hybrid key exchange not offered", "expires in 30 days") are
 * not assets and stay in the report and SARIF.
 *
 * Spec: https://cyclonedx.org/docs/1.6/json/ (cryptoProperties)
 */
import { createHash } from "node:crypto";
import { describeAlgorithm } from "../algorithms";
import type { AlgorithmDescriptor } from "../algorithms";
import { resolveUsage } from "../model/risk";
import { confidenceOf, sanitizeText } from "../report";
import type { CertificateDetails, CryptoUsage, Finding, PqStatus, Report, Severity } from "../report";
import { entryForRuleId } from "../scanners/deps/registry";
import { VERSION } from "../version";
import { REPOSITORY_URL } from "./sarif";

export { describeAlgorithm } from "../algorithms";
export type { AlgorithmDescriptor } from "../algorithms";

/** CycloneDX 1.6 `cryptoProperties.assetType` values we emit. */
type AssetType = "algorithm" | "certificate" | "related-crypto-material" | "protocol";

interface Occurrence {
  location: string;
  line?: number;
}

interface Property {
  name: string;
  value: string;
}

interface CryptoProperties {
  assetType: AssetType;
  algorithmProperties?: Omit<AlgorithmDescriptor, "oid">;
  certificateProperties?: {
    subjectName?: string;
    issuerName?: string;
    notValidBefore?: string;
    notValidAfter?: string;
    signatureAlgorithmRef?: string;
    subjectPublicKeyRef?: string;
    certificateFormat: string;
  };
  relatedCryptoMaterialProperties?: {
    type: "private-key" | "public-key";
    state?: "compromised";
    algorithmRef?: string;
    size?: number;
  };
  protocolProperties?: {
    type: "tls" | "ssh" | "ipsec" | "ike" | "sstp" | "wpa" | "other" | "unknown";
    version?: string;
    cipherSuites?: { name: string }[];
    cryptoRefArray?: string[];
  };
  oid?: string;
}

interface CryptoComponent {
  type: "cryptographic-asset";
  "bom-ref": string;
  name: string;
  cryptoProperties: CryptoProperties;
  evidence?: { occurrences: Occurrence[] };
  properties: Property[];
}

interface LibraryComponent {
  type: "library";
  "bom-ref": string;
  name: string;
  version?: string;
  purl: string;
  evidence?: { occurrences: Occurrence[] };
  properties: Property[];
}

interface Dependency {
  ref: string;
  dependsOn?: string[];
  provides?: string[];
}

const PQ_RANK: Record<PqStatus, number> = { vulnerable: 0, transitional: 1, unknown: 2, safe: 3 };
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * Accumulates the BOM. Every asset is keyed by its bom-ref, so a second
 * finding about the same asset adds an occurrence and a finding id instead of a
 * duplicate component.
 */
class BomBuilder {
  private readonly crypto = new Map<string, { component: CryptoComponent; findings: Finding[] }>();
  private readonly libraries = new Map<string, { component: LibraryComponent; provides: Set<string>; findings: Finding[] }>();
  /** Algorithm assets whose OID a scanner read, which a catalogue OID must never replace. */
  private readonly scannerOids = new Set<string>();

  /**
   * Add (or extend) an algorithm asset and return its bom-ref. An OID the
   * scanner read from the artifact (`oid`) wins over the catalogue's.
   */
  algorithm(label: string, usage: readonly CryptoUsage[], oid: string | undefined, finding?: Finding): string {
    const ref = `crypto/algorithm/${slug(label)}`;
    const existing = this.crypto.get(ref);
    if (existing) {
      if (finding) existing.findings.push(finding);
      if (oid && !this.scannerOids.has(ref)) {
        existing.component.cryptoProperties.oid = oid;
        this.scannerOids.add(ref);
      }
      return ref;
    }
    const { oid: catalogOid, ...algorithmProperties } = describeAlgorithm(label, usage);
    const resolvedOid = oid ?? catalogOid;
    if (oid) this.scannerOids.add(ref);
    this.crypto.set(ref, {
      component: {
        type: "cryptographic-asset",
        "bom-ref": ref,
        name: sanitizeText(label),
        cryptoProperties: { assetType: "algorithm", algorithmProperties, ...(resolvedOid ? { oid: resolvedOid } : {}) },
        properties: [],
      },
      findings: finding ? [finding] : [],
    });
    return ref;
  }

  /**
   * Add (or extend) a non-algorithm asset under a caller-chosen bom-ref. The
   * display name is built from file paths and certificate subjects, so it is
   * sanitized like every other display string.
   */
  asset(ref: string, name: string, cryptoProperties: CryptoProperties, finding: Finding): string {
    const existing = this.crypto.get(ref);
    if (existing) {
      existing.findings.push(finding);
      return ref;
    }
    this.crypto.set(ref, {
      component: { type: "cryptographic-asset", "bom-ref": ref, name: sanitizeText(name), cryptoProperties, properties: [] },
      findings: [finding],
    });
    return ref;
  }

  library(component: Omit<LibraryComponent, "evidence">, finding: Finding, provides: readonly string[]): void {
    const existing = this.libraries.get(component["bom-ref"]);
    if (existing) {
      existing.findings.push(finding);
      for (const ref of provides) existing.provides.add(ref);
      for (const property of component.properties) {
        const duplicate = existing.component.properties.some((p) => p.name === property.name && p.value === property.value);
        if (!duplicate) existing.component.properties.push(property);
      }
      return;
    }
    this.libraries.set(component["bom-ref"], {
      component: { ...component, properties: [...component.properties] },
      provides: new Set(provides),
      findings: [finding],
    });
  }

  components(): Array<CryptoComponent | LibraryComponent> {
    const cryptoAssets = [...this.crypto.values()].map(({ component, findings }) => withProvenance(component, findings));
    const libraries = [...this.libraries.values()].map(({ component, findings }) => withProvenance(component, findings));
    return [...libraries, ...cryptoAssets];
  }

  dependencies(rootRef: string): Dependency[] {
    const libraryRefs = [...this.libraries.keys()];
    const out: Dependency[] = [];
    if (libraryRefs.length > 0) out.push({ ref: rootRef, dependsOn: libraryRefs });
    for (const [ref, { provides }] of this.libraries) {
      if (provides.size > 0) out.push({ ref, provides: [...provides] });
    }
    return out;
  }
}

/** Attach occurrences and the cryptosweep properties (worst posture, finding ids) derived from the findings. */
function withProvenance<T extends CryptoComponent | LibraryComponent>(component: T, findings: readonly Finding[]): T {
  if (findings.length === 0) return component;
  const worstPq = findings.reduce((a, f) => (PQ_RANK[f.pq_status] < PQ_RANK[a] ? f.pq_status : a), "safe" as PqStatus);
  const worstSeverity = findings.reduce((a, f) => (SEVERITY_RANK[f.severity] < SEVERITY_RANK[a] ? f.severity : a), "info" as Severity);
  const properties: Property[] = [
    ...component.properties,
    { name: "cryptosweep:pq_status", value: worstPq },
    { name: "cryptosweep:severity", value: worstSeverity },
    ...unique(findings.map(confidenceOf)).map((value) => ({ name: "cryptosweep:confidence", value })),
    ...unique(findings.map((f) => f.id)).map((value) => ({ name: "cryptosweep:finding", value })),
  ];
  const occurrences = uniqueBy(findings.map(occurrenceOf).filter((o): o is Occurrence => o !== null), (o) => `${o.location}#${o.line ?? ""}`);
  return { ...component, properties, ...(occurrences.length > 0 ? { evidence: { occurrences } } : {}) };
}

function occurrenceOf(finding: Finding): Occurrence | null {
  const { path, line, host, port } = finding.location ?? {};
  if (path) return line ? { location: path, line } : { location: path };
  if (host) return { location: endpointOf(host, port) };
  return null;
}

function endpointOf(host: string, port: number | undefined): string {
  const authority = host.includes(":") ? `[${host}]` : host;
  return `tls://${port ? `${authority}:${port}` : authority}`;
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function uniqueBy<T>(values: readonly T[], key: (value: T) => string): T[] {
  const seen = new Map<string, T>();
  for (const value of values) if (!seen.has(key(value))) seen.set(key(value), value);
  return [...seen.values()];
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "asset";
}

/** A stable short digest, for bom-refs of assets that have no natural short name. */
function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

/** True for an RFC 3339 date-time, the only form CycloneDX accepts in certificate validity fields. */
function isDateTime(value: string): boolean {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) && !Number.isNaN(Date.parse(value));
}

/** One certificate asset, linked to its signature algorithm and to a public-key asset for its subject key. */
function addCertificate(bom: BomBuilder, cert: CertificateDetails, finding: Finding): void {
  const identity = `${cert.subject}|${cert.issuer}|${cert.notValidAfter}|${cert.publicKey}`;
  const signatureRef = bom.algorithm(cert.signatureAlgorithm, ["signature"], cert.signatureOid, finding);
  const keyAlgorithmRef = bom.algorithm(cert.publicKey, ["signature"], undefined, finding);
  const keyRef = bom.asset(
    `crypto/key/public/${digest(identity)}`,
    `${cert.subject} public key`,
    {
      assetType: "related-crypto-material",
      relatedCryptoMaterialProperties: {
        type: "public-key",
        algorithmRef: keyAlgorithmRef,
        ...(cert.publicKeyBits ? { size: cert.publicKeyBits } : {}),
      },
    },
    finding,
  );
  bom.asset(
    `crypto/certificate/${digest(identity)}`,
    cert.subject,
    {
      assetType: "certificate",
      certificateProperties: {
        subjectName: cert.subject,
        issuerName: cert.issuer,
        ...(isDateTime(cert.notValidBefore) ? { notValidBefore: cert.notValidBefore } : {}),
        ...(isDateTime(cert.notValidAfter) ? { notValidAfter: cert.notValidAfter } : {}),
        signatureAlgorithmRef: signatureRef,
        subjectPublicKeyRef: keyRef,
        certificateFormat: "X.509",
      },
    },
    finding,
  );
}

/**
 * Without parsed certificate details, the leaf's signature algorithm and key
 * still come from structured fields (`ruleId` + `algorithm` + endpoint), so the
 * leaf is inventoried with the links it can honestly carry and nothing more.
 */
function addLeafFromFindings(bom: BomBuilder, findings: readonly Finding[]): void {
  const parsed = new Set(
    findings.flatMap((f) => (f.certificates?.length && f.location?.host ? [endpointOf(f.location.host, f.location.port)] : [])),
  );
  const byEndpoint = new Map<string, { signature?: Finding; key?: Finding }>();
  for (const f of findings) {
    if (!f.algorithm || !f.location?.host) continue;
    if (f.ruleId !== "tls/leaf-signature" && f.ruleId !== "tls/leaf-public-key") continue;
    const endpoint = endpointOf(f.location.host, f.location.port);
    if (parsed.has(endpoint)) continue; // the parsed certificate already carries these links
    const entry = byEndpoint.get(endpoint) ?? {};
    if (f.ruleId === "tls/leaf-signature") entry.signature = f;
    else entry.key = f;
    byEndpoint.set(endpoint, entry);
  }
  for (const [endpoint, { signature, key }] of byEndpoint) {
    const anchor = signature ?? key;
    if (!anchor) continue;
    const signatureRef = signature?.algorithm ? bom.algorithm(signature.algorithm, ["signature"], signature.oid) : undefined;
    const keyRef =
      key?.algorithm
        ? bom.asset(
            `crypto/key/public/${digest(`leaf|${endpoint}`)}`,
            `Leaf public key (${endpoint})`,
            {
              assetType: "related-crypto-material",
              relatedCryptoMaterialProperties: {
                type: "public-key",
                algorithmRef: bom.algorithm(key.algorithm, ["signature"], key.oid),
              },
            },
            key,
          )
        : undefined;
    bom.asset(
      `crypto/certificate/${digest(`leaf|${endpoint}`)}`,
      `Leaf certificate (${endpoint})`,
      {
        assetType: "certificate",
        certificateProperties: {
          ...(signatureRef ? { signatureAlgorithmRef: signatureRef } : {}),
          ...(keyRef ? { subjectPublicKeyRef: keyRef } : {}),
          certificateFormat: "X.509",
        },
      },
      anchor,
    );
  }
}

const PROTOCOL_TYPES = new Set(["tls", "ssh", "ipsec", "ike", "sstp", "wpa"]);

function addProtocol(bom: BomBuilder, finding: Finding): void {
  const details = finding.protocol;
  const type = details?.type.toLowerCase() ?? "tls";
  const protocolType = (PROTOCOL_TYPES.has(type) ? type : "other") as NonNullable<CryptoProperties["protocolProperties"]>["type"];
  const endpoint = finding.location?.host ? endpointOf(finding.location.host, finding.location.port) : finding.evidence;
  const groupRef = details?.group ? bom.algorithm(details.group, ["key-establishment"], undefined, finding) : undefined;
  const name = details?.version ? `${protocolType.toUpperCase()} ${details.version}` : protocolType.toUpperCase();
  bom.asset(
    `crypto/protocol/${slug(`${protocolType}-${details?.version ?? "unknown"}`)}-${digest(endpoint)}`,
    `${name} (${endpoint})`,
    {
      assetType: "protocol",
      protocolProperties: {
        type: protocolType,
        ...(details?.version ? { version: details.version } : {}),
        ...(details?.cipherSuite ? { cipherSuites: [{ name: details.cipherSuite }] } : {}),
        ...(groupRef ? { cryptoRefArray: [groupRef] } : {}),
      },
    },
    finding,
  );
}

/** Key material from a `keys` finding, one asset per occurrence (each is a distinct key). */
function addKeyMaterial(bom: BomBuilder, finding: Finding, usage: readonly CryptoUsage[]): void {
  const isPrivate = usage.includes("secret-material");
  const where = occurrenceOf(finding);
  const place = where ? `${where.location}${where.line ? `:${where.line}` : ""}` : finding.id;
  const algorithmRef = finding.algorithm ? bom.algorithm(finding.algorithm, usage, finding.oid, finding) : undefined;
  bom.asset(
    `crypto/key/${isPrivate ? "private" : "public"}/${digest(`${finding.ruleId ?? ""}|${place}`)}`,
    `${isPrivate ? "Private" : "Public"} key material (${place})`,
    {
      assetType: "related-crypto-material",
      relatedCryptoMaterialProperties: {
        type: isPrivate ? "private-key" : "public-key",
        // Key material disclosed in a repository is compromised by definition (SP 800-57 Part 1).
        ...(isPrivate ? { state: "compromised" as const } : {}),
        ...(algorithmRef ? { algorithmRef } : {}),
      },
    },
    finding,
  );
}

/** The purl type for each ecosystem the registry covers (purl-spec). */
const PURL_TYPE: Readonly<Record<string, string>> = { npm: "npm", python: "pypi", cargo: "cargo" };

/** A concrete version (not a range), which is all CycloneDX `version` and a purl may carry. */
function pinnedVersion(version: string | undefined): string | undefined {
  const v = (version ?? "").trim().replace(/^==?/, "");
  return /^\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.-]+)?$/.test(v) ? v : undefined;
}

function purlOf(ecosystem: string, name: string, version: string | undefined): string {
  const type = PURL_TYPE[ecosystem] ?? ecosystem;
  // PyPI names are case-insensitive with `_` equivalent to `-` (purl-spec, PEP 503).
  const normalized = type === "pypi" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name;
  const path = normalized
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
  return `pkg:${type}/${path}${version ? `@${encodeURIComponent(version)}` : ""}`;
}

function addLibrary(bom: BomBuilder, finding: Finding): void {
  const entry = entryForRuleId(finding.ruleId);
  const ecosystem = finding.dependency?.ecosystem ?? entry?.ecosystem;
  const name = finding.dependency?.name ?? entry?.name;
  if (!ecosystem || !name) return;
  const declared = finding.dependency?.version;
  const version = pinnedVersion(declared);
  const purl = purlOf(ecosystem, name, version);
  const provides = (entry?.algorithms ?? []).map((label) => bom.algorithm(label, entry?.usage ?? [], undefined));
  // A range is not a version: keep what the manifest said without pretending it is one.
  const properties = declared && !version ? [{ name: "cryptosweep:declared-version", value: declared }] : [];
  bom.library({ type: "library", "bom-ref": purl, name, ...(version ? { version } : {}), purl, properties }, finding, provides);
}

/** Route each finding to the asset(s) it evidences. */
function buildBom(findings: readonly Finding[]): BomBuilder {
  const bom = new BomBuilder();
  for (const finding of findings) {
    const usage = resolveUsage(finding);
    if (finding.category === "deps") {
      addLibrary(bom, finding);
      continue;
    }
    if (finding.certificates?.length) {
      for (const cert of finding.certificates) addCertificate(bom, cert, finding);
      continue;
    }
    if (finding.category === "keys") {
      addKeyMaterial(bom, finding, usage);
      continue;
    }
    if (finding.protocol || finding.ruleId === "tls/negotiated-protocol") {
      addProtocol(bom, finding);
      if (!finding.algorithm) continue;
    }
    if (finding.algorithm) bom.algorithm(finding.algorithm, usage, finding.oid, finding);
  }
  addLeafFromFindings(bom, findings);
  return bom;
}

/** Deterministic BOM serial number derived from the report, so output is reproducible. */
function serialNumber(report: Report): string {
  const hex = createHash("sha256").update(`${report.target}|${report.scanned_at}`).digest("hex");
  const uuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
  return `urn:uuid:${uuid}`;
}

/** Render a report as a CycloneDX 1.6 CBOM document (pretty JSON). */
export function toCbom(report: Report): string {
  const bom = buildBom(report.findings);
  const rootRef = "target";
  const dependencies = bom.dependencies(rootRef);
  const document = {
    $schema: "http://cyclonedx.org/schema/bom-1.6.schema.json",
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: serialNumber(report),
    version: 1,
    metadata: {
      timestamp: report.scanned_at,
      tools: {
        components: [
          {
            type: "application",
            name: "cryptosweep",
            version: VERSION,
            "bom-ref": "tool/cryptosweep",
            externalReferences: [{ type: "vcs", url: REPOSITORY_URL }],
          },
        ],
      },
      component: {
        type: "application",
        "bom-ref": rootRef,
        name: report.target,
      },
    },
    components: bom.components(),
    ...(dependencies.length > 0 ? { dependencies } : {}),
  };
  return JSON.stringify(document, null, 2);
}
