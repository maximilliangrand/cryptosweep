/** Public library surface for cryptosweep. */
export { VERSION } from "./version";
export type {
  Category,
  CertificateDetails,
  Confidence,
  CoverageEntry,
  CryptoUsage,
  Finding,
  Location,
  NonProductionContext,
  PackageCoordinates,
  PqStatus,
  ProtocolDetails,
  Reference,
  Report,
  ReportSummary,
  Severity,
} from "./report";
export { buildReport, failsThreshold, normalizeFinding, sanitizeText, toJson, toMarkdown } from "./report";
export { toCbom, describeAlgorithm } from "./output/cbom";
export { toSarif } from "./output/sarif";
export { toHtml } from "./output/viewer";
export type {
  DataClass,
  EstateProfile,
  MigrationAssumption,
  Obligation,
  ObligationScope,
  ProfileOptions,
  QuantumAssumption,
} from "./model/estate";
export { DATA_CLASSES, DEFAULT_MIGRATION_YEARS, defaultProfile, isDataClassId } from "./model/estate";
export type {
  CryptoAsset,
  CryptoGraph,
  HarvestLedger,
  MoscaStatus,
  MoscaVerdict,
  RiskModel,
  ThreatAssessment,
  ThreatModel,
} from "./model/risk";
export { assessRisk, assessThreat, classifyThreat, resolveUsage } from "./model/risk";
export type { KeyType } from "./crypto";
export {
  REFS,
  curveFriendlyName,
  isClassicallyWeakKey,
  isPostQuantumKey,
  isQuantumVulnerableKey,
  keyAlgorithmLabel,
  keyPosture,
} from "./crypto";
export { certificateSignatureOid, signatureAlgorithmName } from "./asn1";
export type { ResolvedAddress } from "./net-guard";
export { assertTargetAllowed, isBlockedAddress, resolveAllowedAddress } from "./net-guard";
export type { ClassifyOptions, ScanTargetOptions, Target } from "./orchestrate";
export { classifyTarget, scanClonedRepo, scanLocalDir, scanTarget } from "./orchestrate";
export type { ClonedRepo, CloneOptions, GitHubRepo } from "./clone";
export { cloneRepository, parseGitHubRepo } from "./clone";
export type {
  CertInfo,
  GroupOutcome,
  GroupProbeResult,
  HybridSupport,
  TlsProbe,
  TlsScanOptions,
  TlsScanResult,
} from "./scanners/tls";
export { analyzeTls, parseCertificate, scanTls } from "./scanners/tls";
export type { SourceScanOptions } from "./scanners/source";
export { scanContent, scanSource } from "./scanners/source";
export type { RuleId, RuleLanguage, RuleUsage, SourceRule } from "./scanners/source-rules";
export { SOURCE_RULES, sourceRule } from "./scanners/source-rules";
export type { DepsScanOptions, ParsedDep } from "./scanners/deps";
export { matchDeps, scanDeps } from "./scanners/deps";
export type { Ecosystem, RegistryEntry } from "./scanners/deps/registry";
export { REGISTRY, depsRuleId, entryForRuleId, lookupEntry } from "./scanners/deps/registry";
export { reconcile } from "./reconcile";
