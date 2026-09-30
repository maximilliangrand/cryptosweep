/**
 * Hardened repository cloning.
 *
 * A clone is a network fetch from a caller-supplied remote (on the MCP path, a
 * model-supplied one), so it sits behind the same trust boundary as a TLS scan.
 * By default only `https://github.com/<owner>/<repo>` is accepted, which is the
 * documented behaviour. The host is vetted by the SSRF guard and then pinned for
 * git's own connection (`http.curloptResolve`), so DNS cannot swing it to an
 * internal address between the check and the fetch. Other https hosts and ssh
 * remotes are refused unless the caller opts in (the CLI's
 * `--allow-any-git-host`; the MCP server never does).
 *
 * git runs without a shell, with an allowlisted environment and with config
 * that switches off what a hostile remote or the operator's ambient config
 * could turn against the operator: redirects, other transports, credential
 * helpers and prompts, hooks, LFS smudging, symlinks in the checkout, and the
 * system and global config files. A deadline and size ceilings bound the fetch
 * and the checkout, and the temp directory is removed on every failure path.
 */
import { spawn } from "node:child_process";
import { mkdtemp, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isIP } from "node:net";
import { join } from "node:path";
import { resolveAllowedAddress } from "./net-guard";
import type { ResolvedAddress } from "./net-guard";

export interface ClonedRepo {
  dir: string;
  cleanup: () => Promise<void>;
}

export interface CloneOptions {
  /** Permit https remotes on other hosts and ssh remotes. Operator opt-in only. */
  allowAnyHost?: boolean;
  /** Skip the SSRF check on the remote host (and with it, address pinning). */
  allowPrivate?: boolean;
  /** Deadline for the whole clone, fetch and checkout together. */
  timeoutMs?: number;
  /** Ceiling on the packfile git downloads. */
  maxPackBytes?: number;
  /** Ceiling on the total size of the files the checkout would write. */
  maxCheckoutBytes?: number;
  /** Ceiling on the number of files the checkout would write. */
  maxCheckoutFiles?: number;
  /** Aborting kills git and removes the partial clone. */
  signal?: AbortSignal;
}

export interface GitHubRepo {
  owner: string;
  repo: string;
  /** The canonical clone URL, `https://github.com/<owner>/<repo>.git`. */
  url: string;
}

/** A remote that passed validation, in the only forms git is ever handed. */
export type CloneRemote =
  | { transport: "https"; url: string; host: string; port: number }
  | { transport: "ssh"; url: string; host: string };

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_PACK_BYTES = 512 * 1024 * 1024;
const DEFAULT_MAX_CHECKOUT_BYTES = 1024 * 1024 * 1024;
const DEFAULT_MAX_CHECKOUT_FILES = 250_000;
const WATCH_INTERVAL_MS = 250;
/** How long git gets to clean up after SIGTERM before it is killed outright. */
const KILL_GRACE_MS = 2_000;
const MAX_STDERR_BYTES = 16 * 1024;

/** GitHub account and organization names: alphanumerics and inner hyphens, at most 39 characters. */
const GITHUB_OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
/** GitHub repository names: letters, digits, `.`, `_` and `-`, at most 100 characters. */
const GITHUB_REPO = /^[A-Za-z0-9._-]{1,100}$/;
const GITHUB_URL = /^https:\/\/(?:www\.)?github\.com\/([^/?#]+)\/([^/?#]+?)(?:\.git)?\/?$/i;
const GITHUB_HOST_PREFIX = /^(?:www\.)?github\.com\//i;
const GITHUB_SHORTHAND = /^([^/]+)\/([^/]+?)(?:\.git)?$/;

const HOSTNAME =
  /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const REMOTE_PATH = /^[A-Za-z0-9._~][A-Za-z0-9._~/-]*$/;
const HTTPS_REMOTE = /^https:\/\/([^/:?#@[\]]+|\[[0-9A-Fa-f:.]+\])(?::(\d{1,5}))?\/([^?#]+)$/;
const SCP_REMOTE = /^([A-Za-z0-9._-]+)@([^:/@]+):([^?#]+)$/;
const SSH_REMOTE = /^ssh:\/\/(?:([A-Za-z0-9._-]+)@)?([^/:?#@]+)(?::(\d{1,5}))?\/([^?#]+)$/i;

/** Environment variables git may inherit: the executable search path and the operator's proxy and CA settings. */
const INHERITED_ENV = [
  "PATH",
  "SystemRoot",
  "HTTPS_PROXY",
  "https_proxy",
  "ALL_PROXY",
  "all_proxy",
  "NO_PROXY",
  "no_proxy",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
];

function isGitHubRepoName(name: string): boolean {
  return GITHUB_REPO.test(name) && name !== "." && name !== ".." && name.toLowerCase() !== ".git";
}

/**
 * Parse `owner/repo`, `github.com/owner/repo` or
 * `https://github.com/owner/repo(.git)`, validating owner and repository names
 * strictly. Returns null for anything else.
 */
export function parseGitHubRepo(input: string): GitHubRepo | null {
  const match =
    GITHUB_URL.exec(input) ?? GITHUB_SHORTHAND.exec(input.replace(GITHUB_HOST_PREFIX, ""));
  const owner = match?.[1];
  const repo = match?.[2];
  if (!owner || !repo || !GITHUB_OWNER.test(owner) || !isGitHubRepoName(repo)) return null;
  return { owner, repo, url: `https://github.com/${owner}/${repo}.git` };
}

/** Render caller input for an error message: printable ASCII only, bounded length. */
function printable(text: string, max = 200): string {
  const flat = text.replace(/[^\x20-\x7e]/g, "?");
  return flat.length > max ? `${flat.slice(0, max)}...` : flat;
}

function parsePortText(text: string | undefined, fallback: number): number | null {
  if (text === undefined) return fallback;
  const port = Number(text);
  return Number.isInteger(port) && port >= 1 && port <= 65_535 ? port : null;
}

function isValidRemoteHost(host: string): boolean {
  return HOSTNAME.test(host) || /^\[[0-9A-Fa-f:.]+\]$/.test(host);
}

function isValidRemotePath(path: string): boolean {
  return REMOTE_PATH.test(path) && !path.split("/").some((segment) => segment === "..");
}

function parseOtherRemote(url: string): CloneRemote | null {
  const https = HTTPS_REMOTE.exec(url);
  if (https) {
    const [, host = "", portText, path = ""] = https;
    const port = parsePortText(portText, 443);
    if (!isValidRemoteHost(host) || port === null || !isValidRemotePath(path)) return null;
    return { transport: "https", url, host: host.toLowerCase(), port };
  }
  const ssh = SSH_REMOTE.exec(url);
  if (ssh) {
    const [, , host = "", portText, path = ""] = ssh;
    if (!HOSTNAME.test(host) || parsePortText(portText, 22) === null || !isValidRemotePath(path))
      return null;
    return { transport: "ssh", url, host: host.toLowerCase() };
  }
  const scp = SCP_REMOTE.exec(url);
  if (scp) {
    const [, , host = "", path = ""] = scp;
    if (!HOSTNAME.test(host) || !isValidRemotePath(path)) return null;
    return { transport: "ssh", url, host: host.toLowerCase() };
  }
  return null;
}

/**
 * Validate a clone URL. GitHub repositories are always accepted (normalized to
 * the canonical https URL); any other remote only with `allowAnyHost`.
 */
export function parseCloneRemote(url: string, allowAnyHost = false): CloneRemote {
  const github = parseGitHubRepo(url);
  if (github) return { transport: "https", url: github.url, host: "github.com", port: 443 };
  if (!allowAnyHost) {
    throw new Error(
      `Refusing to clone ${printable(url)}: only public GitHub repositories (https://github.com/<owner>/<repo>) can be cloned. ` +
        "The CLI accepts other https and ssh remotes with --allow-any-git-host.",
    );
  }
  const remote = parseOtherRemote(url);
  if (!remote) {
    throw new Error(
      `Refusing to clone ${printable(url)}: not a supported repository URL (https://host/path or git@host:path).`,
    );
  }
  return remote;
}

function curlAddress(address: ResolvedAddress): string {
  return address.family === 6 ? `[${address.address}]` : address.address;
}

/** The `-c` settings every git invocation runs with. Exported for tests. */
export function hardenedConfig(
  remote: CloneRemote,
  pinned: readonly ResolvedAddress[] = [],
): string[] {
  const settings = [
    "protocol.allow=never",
    `protocol.${remote.transport}.allow=always`,
    "http.followRedirects=false",
    "http.sslVerify=true",
    "http.lowSpeedLimit=1024",
    "http.lowSpeedTime=30",
    "credential.helper=",
    "core.askPass=",
    "core.hooksPath=/dev/null",
    "core.symlinks=false",
    "core.fsmonitor=false",
    "submodule.recurse=false",
  ];
  // An IP-literal host has nothing to resolve, so only names are pinned.
  const host = remote.host.replace(/^\[(.*)\]$/, "$1");
  if (remote.transport === "https" && pinned.length > 0 && isIP(host) === 0) {
    settings.push(
      `http.curloptResolve=${host}:${remote.port}:${pinned.map(curlAddress).join(",")}`,
    );
  }
  return settings.flatMap((setting) => ["-c", setting]);
}

/** A scrubbed environment: nothing from the caller's git, ssh or credential setup leaks in. */
export function gitEnvironment(
  remote: CloneRemote,
  home: string,
  pinned: readonly ResolvedAddress[] = [],
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    HOME: home,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_TERMINAL_PROMPT: "0",
    GIT_ASKPASS: "",
    GIT_LFS_SKIP_SMUDGE: "1",
    LC_ALL: "C",
  };
  for (const name of INHERITED_ENV) {
    const value = process.env[name];
    if (value !== undefined) env[name] = value;
  }
  if (remote.transport === "ssh") {
    // Explicit operator opt-in: the agent socket is theirs to offer. BatchMode
    // makes ssh fail instead of prompting, and a vetted address is pinned the
    // same way the https path pins it.
    const first = pinned[0];
    const pin = first ? ` -o HostName=${first.address} -o HostKeyAlias=${remote.host}` : "";
    env.GIT_SSH_COMMAND = `ssh -o BatchMode=yes -o ConnectTimeout=20${pin}`;
    const agent = process.env.SSH_AUTH_SOCK;
    if (agent !== undefined) env.SSH_AUTH_SOCK = agent;
  }
  return env;
}

interface GitRun {
  env: NodeJS.ProcessEnv;
  deadline: number;
  timeoutMs: number;
  what: string;
  signal?: AbortSignal;
  onStdout?: (chunk: Buffer) => void;
  /** Polled while git runs; a returned string aborts the run with that message. */
  watch?: () => Promise<string | null>;
}

/** Last meaningful stderr line, printable ASCII only, so a remote cannot inject terminal escapes. */
function stderrExcerpt(stderr: string): string {
  const lines = stderr
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const notFound = lines.some((line) =>
    /terminal prompts disabled|could not read Username|Repository not found/i.test(line),
  );
  const last = printable(lines.at(-1) ?? "no error output", 300);
  return notFound ? `repository not found or not public (${last})` : last;
}

async function runGit(args: readonly string[], run: GitRun): Promise<void> {
  const limit =
    run.timeoutMs >= 1000 ? `${Math.round(run.timeoutMs / 1000)}s` : `${run.timeoutMs}ms`;
  const timedOut = (): Error => new Error(`${run.what} timed out after ${limit}`);
  const remaining = run.deadline - Date.now();
  if (remaining <= 0) throw timedOut();
  run.signal?.throwIfAborted();

  await new Promise<void>((resolve, reject) => {
    const child = spawn("git", args, {
      env: run.env,
      stdio: ["ignore", run.onStdout ? "pipe" : "ignore", "pipe"],
      windowsHide: true,
    });
    let stderr = "";
    let stopReason: Error | null = null;
    let forceKill: NodeJS.Timeout | undefined;
    let settled = false;

    // SIGTERM lets git remove its partial clone and take its helpers down with
    // it; SIGKILL follows if it does not exit.
    const stop = (reason: Error): void => {
      if (stopReason) return;
      stopReason = reason;
      child.kill("SIGTERM");
      forceKill = setTimeout(() => child.kill("SIGKILL"), KILL_GRACE_MS);
    };
    const onAbort = (): void => stop(new Error(`${run.what} was cancelled`));
    const timer = setTimeout(() => stop(timedOut()), remaining);
    let checking = false;
    const poll = run.watch
      ? setInterval(() => {
          if (checking || !run.watch) return;
          checking = true;
          void run
            .watch()
            .then((reason) => {
              if (reason) stop(new Error(reason));
            })
            .finally(() => {
              checking = false;
            });
        }, WATCH_INTERVAL_MS)
      : undefined;
    run.signal?.addEventListener("abort", onAbort, { once: true });

    const finish = (error: Error | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(forceKill);
      if (poll) clearInterval(poll);
      run.signal?.removeEventListener("abort", onAbort);
      if (error) reject(error);
      else resolve();
    };

    child.stdout?.on("data", (chunk: Buffer) => {
      try {
        run.onStdout?.(chunk);
      } catch (err) {
        stop(err instanceof Error ? err : new Error(String(err)));
      }
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      if (stderr.length < MAX_STDERR_BYTES)
        stderr += chunk.toString("utf8").slice(0, MAX_STDERR_BYTES - stderr.length);
    });
    child.on("error", (err) =>
      finish(new Error(`${run.what} could not start git: ${err.message}`)),
    );
    child.on("close", (code) => {
      if (stopReason) finish(stopReason);
      else if (code === 0) finish(null);
      else finish(new Error(`${run.what} failed: ${stderrExcerpt(stderr)}`));
    });
  });
}

/** Bytes git has written into the pack directory so far, including the in-flight tmp_pack file. */
async function packBytes(dir: string): Promise<number> {
  const packDir = join(dir, ".git", "objects", "pack");
  let names: string[];
  try {
    names = await readdir(packDir);
  } catch {
    return 0;
  }
  let total = 0;
  for (const name of names) {
    try {
      total += (await stat(join(packDir, name))).size;
    } catch {
      /* renamed or removed between readdir and stat */
    }
  }
  return total;
}

function formatBytes(bytes: number): string {
  return bytes >= 1024 * 1024 ? `${Math.round(bytes / (1024 * 1024))} MiB` : `${bytes} bytes`;
}

/** Count what the checkout would write, from the tree listing, before writing any of it. */
function checkoutCounter(
  maxBytes: number,
  maxFiles: number,
  what: string,
): (chunk: Buffer) => void {
  let carry = "";
  let bytes = 0;
  let files = 0;
  return (chunk) => {
    const records = (carry + chunk.toString("latin1")).split("\0");
    carry = records.pop() ?? "";
    for (const record of records) {
      const size = /^\d+ \w+ [0-9a-f]+ +(\d+|-)\t/.exec(record)?.[1];
      files += 1;
      if (size && size !== "-") bytes += Number(size);
      if (files > maxFiles)
        throw new Error(`${what}: the checkout would exceed the ${maxFiles}-file ceiling`);
      if (bytes > maxBytes)
        throw new Error(`${what}: the checkout would exceed the ${formatBytes(maxBytes)} ceiling`);
    }
  };
}

/**
 * Shallow-clone a repository into a fresh temp directory. The caller must
 * invoke `cleanup()`; on any failure the directory is already gone.
 */
export async function cloneRepository(
  url: string,
  options: CloneOptions = {},
): Promise<ClonedRepo> {
  const remote = parseCloneRemote(url, options.allowAnyHost === true);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const deadline = Date.now() + timeoutMs;
  const maxPackBytes = options.maxPackBytes ?? DEFAULT_MAX_PACK_BYTES;
  const what = `git clone of ${remote.url}`;

  // Vet the host before anything touches the disk or the network; the vetted
  // addresses are then pinned so git cannot resolve the name differently.
  const pinned = options.allowPrivate ? [] : await resolveAllowedAddress(remote.host, false);
  options.signal?.throwIfAborted();

  const work = await mkdtemp(join(tmpdir(), "cryptosweep-"));
  const dir = join(work, "repo");
  const cleanup = (): Promise<void> => rm(work, { recursive: true, force: true, maxRetries: 3 });
  const config = hardenedConfig(remote, pinned);
  const run = {
    env: gitEnvironment(remote, work, pinned),
    deadline,
    timeoutMs,
    signal: options.signal,
  };

  try {
    await runGit(
      [
        ...config,
        "clone",
        "--quiet",
        "--depth",
        "1",
        "--no-tags",
        "--no-checkout",
        "--template=",
        "--",
        remote.url,
        dir,
      ],
      {
        ...run,
        what,
        watch: async () =>
          (await packBytes(dir)) > maxPackBytes
            ? `${what}: the download exceeded the ${formatBytes(maxPackBytes)} ceiling`
            : null,
      },
    );
    await runGit([...config, "-C", dir, "ls-tree", "-r", "-l", "-z", "HEAD"], {
      ...run,
      what,
      onStdout: checkoutCounter(
        options.maxCheckoutBytes ?? DEFAULT_MAX_CHECKOUT_BYTES,
        options.maxCheckoutFiles ?? DEFAULT_MAX_CHECKOUT_FILES,
        what,
      ),
    });
    await runGit([...config, "-C", dir, "checkout", "--quiet", "--force", "HEAD"], {
      ...run,
      what,
    });
  } catch (err) {
    await cleanup();
    throw err instanceof Error ? err : new Error(String(err));
  }
  return { dir, cleanup };
}
