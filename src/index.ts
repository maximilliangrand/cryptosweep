/** Public library surface for cryptosweep. */
export { VERSION } from "./version";
export type {
  Category,
  Finding,
  PqStatus,
  Report,
  ReportSummary,
  Severity,
} from "./report";
export { buildReport, toJson, toMarkdown } from "./report";
export type {
  CertInfo,
  KeyType,
  RawCertificate,
  TlsProbe,
  TlsScanOptions,
  TlsScanResult,
} from "./scanners/tls";
export { analyzeTls, normalizeCert, scanTls, signatureAlgorithmFromDer } from "./scanners/tls";
export type { ClonedRepo, SourceScanOptions } from "./scanners/source";
export { cloneRepo, scanContent, scanSource } from "./scanners/source";
export type { DepsScanOptions, ParsedDep } from "./scanners/deps";
export { matchDeps, scanDeps } from "./scanners/deps";
export type { Ecosystem, RegistryEntry } from "./scanners/deps/registry";
export { REGISTRY, lookupEntry } from "./scanners/deps/registry";
