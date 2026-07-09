/** Public library surface for cryptosweep. */
export { VERSION } from "./version";
export type {
  Category,
  Confidence,
  Finding,
  Location,
  PqStatus,
  Reference,
  Report,
  ReportSummary,
  Severity,
} from "./report";
export { buildReport, failsThreshold, normalizeFinding, toJson, toMarkdown } from "./report";
export { toCbom, describeAlgorithm } from "./output/cbom";
export { toSarif } from "./output/sarif";
export { toHtml } from "./output/viewer";
export type { KeyType } from "./crypto";
export {
  REFS,
  curveFriendlyName,
  isQuantumVulnerableKey,
  keyAlgorithmLabel,
  keyPosture,
} from "./crypto";
export { certificateSignatureOid, signatureAlgorithmName } from "./asn1";
export type { CertInfo, TlsProbe, TlsScanOptions, TlsScanResult } from "./scanners/tls";
export { analyzeTls, parseCertificate, scanTls } from "./scanners/tls";
export type { ClonedRepo, SourceScanOptions } from "./scanners/source";
export { cloneRepo, scanContent, scanSource } from "./scanners/source";
export type { DepsScanOptions, ParsedDep } from "./scanners/deps";
export { matchDeps, scanDeps } from "./scanners/deps";
export type { Ecosystem, RegistryEntry } from "./scanners/deps/registry";
export { REGISTRY, lookupEntry } from "./scanners/deps/registry";
