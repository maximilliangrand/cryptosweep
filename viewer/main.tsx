/**
 * Blueprint report viewer (Palantir's open-source design system, Apache-2.0).
 *
 * This React app is bundled by scripts/build-viewer.mjs into a single, offline,
 * self-contained HTML shell with React, Blueprint, and the stylesheet all
 * inlined. At scan time the CLI injects the report JSON into that shell. React
 * escapes every value it renders, so a scanned repository's content can never
 * become markup.
 */
import { createRoot } from "react-dom/client";
import { useMemo, useState } from "react";
import {
  Callout,
  Card,
  Classes,
  Collapse,
  Elevation,
  H4,
  InputGroup,
  Intent,
  Navbar,
  NonIdealState,
  Tag,
} from "@blueprintjs/core";
import "@blueprintjs/core/lib/css/blueprint.css";
import "./styles.css";

type Severity = "critical" | "high" | "medium" | "low" | "info";

interface Reference {
  label: string;
  url?: string;
}
interface Finding {
  id: string;
  ruleId?: string;
  severity: Severity;
  category: string;
  title: string;
  evidence: string;
  location?: { path?: string; line?: number; host?: string; port?: number };
  pq_status: string;
  confidence?: string;
  algorithm?: string;
  recommendation: string;
  references?: Reference[];
}
interface Report {
  target: string;
  scanned_at: string;
  summary: Record<Severity | "findings", number>;
  findings: Finding[];
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const PQ_STATUSES = ["vulnerable", "transitional", "safe", "unknown"];

function sevTag(sev: Severity): { className: string; intent?: Intent } {
  if (sev === "critical") return { className: "", intent: Intent.DANGER };
  if (sev === "high") return { className: "csw-high" };
  if (sev === "medium") return { className: "", intent: Intent.WARNING };
  if (sev === "low") return { className: "", intent: Intent.PRIMARY };
  return { className: "csw-info" };
}

function pqIntent(status: string): Intent {
  if (status === "vulnerable") return Intent.DANGER;
  if (status === "safe") return Intent.SUCCESS;
  if (status === "transitional") return Intent.PRIMARY;
  return Intent.NONE;
}

function readReport(): Report {
  const el = document.getElementById("data");
  return JSON.parse(el?.textContent ?? "{}") as Report;
}

function Tile({ n, label, kind }: { n: number; label: string; kind: string }): JSX.Element {
  return (
    <Card className={`csw-tile csw-tile-${kind}`} elevation={Elevation.ONE}>
      <div className="csw-tile-n">{n ?? 0}</div>
      <div className="csw-tile-l">{label}</div>
    </Card>
  );
}

function FindingCard({ f }: { f: Finding }): JSX.Element {
  const [open, setOpen] = useState(false);
  const s = sevTag(f.severity);
  return (
    <Card className={`csw-finding csw-border-${f.severity}`} elevation={Elevation.ZERO}>
      <div className="csw-finding-row" onClick={() => setOpen((v) => !v)}>
        <Tag className={s.className} intent={s.intent} large minimal={false}>
          {f.severity}
        </Tag>
        <span className="csw-finding-title">{f.title}</span>
        {f.confidence ? (
          <Tag minimal round>
            {f.confidence}
          </Tag>
        ) : null}
        <Tag intent={pqIntent(f.pq_status)} minimal>
          {f.pq_status}
        </Tag>
      </div>
      <Collapse isOpen={open}>
        <div className="csw-detail">
          <dl>
            <dt>Evidence</dt>
            <dd className={Classes.MONOSPACE_TEXT}>{f.evidence}</dd>
            {f.algorithm ? (
              <>
                <dt>Algorithm</dt>
                <dd className={Classes.MONOSPACE_TEXT}>{f.algorithm}</dd>
              </>
            ) : null}
            <dt>Recommendation</dt>
            <dd>{f.recommendation}</dd>
            {f.references && f.references.length ? (
              <>
                <dt>References</dt>
                <dd>
                  {f.references.map((r, i) => (
                    <span key={i}>
                      {i ? " · " : ""}
                      {r.url ? (
                        <a href={r.url} target="_blank" rel="noopener noreferrer">
                          {r.label}
                        </a>
                      ) : (
                        r.label
                      )}
                    </span>
                  ))}
                </dd>
              </>
            ) : null}
            <dt>Rule</dt>
            <dd className={Classes.MONOSPACE_TEXT}>
              {(f.ruleId ?? f.id) + "  ·  " + f.id}
            </dd>
          </dl>
        </div>
      </Collapse>
    </Card>
  );
}

function App(): JSX.Element {
  const report = useMemo(readReport, []);
  const [query, setQuery] = useState("");
  const [sev, setSev] = useState<Set<Severity>>(new Set());
  const [pq, setPq] = useState<Set<string>>(new Set());

  const findings = report.findings ?? [];
  const pqVuln = findings.filter((f) => f.pq_status === "vulnerable").length;

  const assets = useMemo(() => {
    const seen = new Map<string, Finding>();
    for (const f of findings) if (f.algorithm && !seen.has(f.algorithm)) seen.set(f.algorithm, f);
    return [...seen.entries()];
  }, [findings]);

  const shown = findings.filter((f) => {
    if (sev.size && !sev.has(f.severity)) return false;
    if (pq.size && !pq.has(f.pq_status)) return false;
    if (query) {
      const hay = `${f.title} ${f.evidence} ${f.algorithm ?? ""} ${f.recommendation}`.toLowerCase();
      if (!hay.includes(query.toLowerCase())) return false;
    }
    return true;
  });

  const toggle = <T,>(set: Set<T>, setter: (s: Set<T>) => void, v: T): void => {
    const next = new Set(set);
    if (next.has(v)) next.delete(v);
    else next.add(v);
    setter(next);
  };

  return (
    <div className="csw-app">
      <Navbar className="csw-navbar">
        <Navbar.Group>
          <Navbar.Heading className="csw-brand">cryptosweep</Navbar.Heading>
          <Navbar.Divider />
          <span className="csw-target">{report.target}</span>
        </Navbar.Group>
        <Navbar.Group align="right">
          <span className={Classes.TEXT_MUTED}>scanned {report.scanned_at}</span>
        </Navbar.Group>
      </Navbar>

      <div className="csw-tiles">
        <Tile n={report.summary?.critical} label="Critical" kind="critical" />
        <Tile n={report.summary?.high} label="High" kind="high" />
        <Tile n={report.summary?.medium} label="Medium" kind="medium" />
        <Tile n={report.summary?.low} label="Low" kind="low" />
        <Tile n={report.summary?.info} label="Info" kind="info" />
        <Tile n={pqVuln} label="PQ-vulnerable" kind="critical" />
      </div>

      <div className="csw-controls">
        <InputGroup
          className="csw-search"
          placeholder="Search findings, evidence, algorithms…"
          value={query}
          onChange={(e) => setQuery(e.currentTarget.value)}
        />
        <div className="csw-chips">
          {SEVERITIES.map((s) => (
            <Tag
              key={s}
              interactive
              minimal={!sev.has(s)}
              intent={sev.has(s) ? Intent.PRIMARY : Intent.NONE}
              onClick={() => toggle(sev, setSev, s)}
            >
              {s}
            </Tag>
          ))}
          {PQ_STATUSES.map((p) => (
            <Tag
              key={p}
              interactive
              minimal={!pq.has(p)}
              intent={pq.has(p) ? Intent.PRIMARY : Intent.NONE}
              onClick={() => toggle(pq, setPq, p)}
            >
              {p}
            </Tag>
          ))}
        </div>
      </div>

      <div className="csw-main">
        <div className="csw-col">
          <H4 className={Classes.HEADING}>
            Findings <span className={Classes.TEXT_MUTED}>({shown.length} of {findings.length})</span>
          </H4>
          {shown.length ? (
            shown.map((f) => <FindingCard key={f.id} f={f} />)
          ) : (
            <Callout intent={Intent.NONE} title="No findings match the current filters" />
          )}
        </div>
        <div className="csw-aside">
          <H4 className={Classes.HEADING}>Cryptographic assets</H4>
          {assets.length ? (
            assets.map(([name, f]) => (
              <Card key={name} className="csw-asset" elevation={Elevation.ZERO}>
                <span className={Classes.MONOSPACE_TEXT}>{name}</span>
                <Tag intent={pqIntent(f.pq_status)} minimal>
                  {f.pq_status}
                </Tag>
              </Card>
            ))
          ) : (
            <NonIdealState title="No algorithms inventoried" />
          )}
        </div>
      </div>

      <footer className="csw-footer">
        <span className={Classes.TEXT_MUTED}>
          Generated by cryptosweep. UI built with Blueprint (Apache-2.0). Confidence reflects how the
          evidence was derived: confirmed is parsed structure, low is a context heuristic. Not a
          substitute for a credentialed cryptographer's review.
        </span>
      </footer>
    </div>
  );
}

const root = document.getElementById("root");
if (root) createRoot(root).render(<App />);
