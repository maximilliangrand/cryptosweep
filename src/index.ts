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
export type { DataClass, EstateProfile, Obligation, ObligationScope, QuantumAssumption } from "./model/estate";
export { DATA_CLASSES, defaultProfile, isDataClassId } from "./model/estate";
export type {
  CryptoAsset,
  CryptoGraph,
  HarvestLedger,
  MoscaStatus,
  MoscaVerdict,
  RiskModel,
  ThreatModel,
} from "./model/risk";
export { assessRisk, classifyThreat } from "./model/risk";
export type { KeyType } from "./crypto";
export {
  REFS,
  curveFriendlyName,
  isClassicallyWeakKey,
  isQuantumVulnerableKey,
  keyAlgorithmLabel,
  keyPosture,
} from "./crypto";
export { certificateSignatureOid, signatureAlgorithmName } from "./asn1";
export { assertTargetAllowed, isBlockedAddress } from "./net-guard";
export type { CertInfo, TlsProbe, TlsScanOptions, TlsScanResult } from "./scanners/tls";
export { analyzeTls, parseCertificate, scanTls } from "./scanners/tls";
export type { ClonedRepo, SourceScanOptions } from "./scanners/source";
export { cloneRepo, scanContent, scanSource } from "./scanners/source";
export type { DepsScanOptions, ParsedDep } from "./scanners/deps";
export { matchDeps, scanDeps } from "./scanners/deps";
export type { Ecosystem, RegistryEntry } from "./scanners/deps/registry";
export { REGISTRY, lookupEntry } from "./scanners/deps/registry";
export { reconcile } from "./reconcile";
