import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cloneRepository,
  gitEnvironment,
  hardenedConfig,
  parseCloneRemote,
  parseGitHubRepo,
} from "../src/clone";

// DNS is stubbed: the clone path must vet and pin the host, but tests stay offline.
const guard = vi.hoisted(() => ({ resolveAllowedAddress: vi.fn() }));
vi.mock("../src/net-guard", () => ({ resolveAllowedAddress: guard.resolveAllowedAddress }));

const posix = process.platform !== "win32";

/**
 * A stand-in `git` found first on PATH. It records every invocation (args and
 * environment) and behaves according to the repository name in the URL, so
 * each test can drive one failure mode through the real spawn path.
 */
const FAKE_GIT = String.raw`#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const args = process.argv.slice(2);
fs.appendFileSync(path.join(__dirname, "calls.jsonl"), JSON.stringify({ args, env: process.env }) + "\n");
const rest = [];
for (let i = 0; i < args.length; i += 1) {
  if (args[i] === "-c") { i += 1; continue; }
  rest.push(args[i]);
}
let cwd = process.cwd();
if (rest[0] === "-C") { cwd = rest[1]; rest.splice(0, 2); }
const sub = rest[0];
if (sub === "clone") {
  const dir = rest[rest.length - 1];
  const mode = rest[rest.length - 2].replace(/\.git$/, "").split(/[/:]/).pop();
  const pack = path.join(dir, ".git", "objects", "pack");
  fs.mkdirSync(pack, { recursive: true });
  fs.writeFileSync(path.join(dir, ".git", "mode"), mode);
  if (mode === "fail") {
    process.stderr.write("fatal: unable to access the remote\nremote: \x1b]0;pwned\x07\x1b[31mred\n");
    process.exit(128);
  }
  if (mode === "hang") { setInterval(() => {}, 1000); return; }
  if (mode === "stubborn") { process.on("SIGTERM", () => {}); setInterval(() => {}, 1000); return; }
  if (mode === "huge-pack") {
    setInterval(() => fs.appendFileSync(path.join(pack, "tmp_pack_x"), Buffer.alloc(256 * 1024)), 10);
    return;
  }
  fs.writeFileSync(path.join(pack, "pack-1.pack"), "PACK");
  process.exit(0);
}
if (sub === "ls-tree") {
  const mode = fs.readFileSync(path.join(cwd, ".git", "mode"), "utf8");
  const size = mode === "big-tree" ? 4 * 1024 * 1024 : 60;
  const count = mode === "many-files" ? 50 : 2;
  for (let n = 0; n < count; n += 1) {
    process.stdout.write("100644 blob " + "a".repeat(40) + " " + String(size).padStart(7) + "\tfile" + n + ".js\0");
  }
  process.exit(0);
}
if (sub === "checkout") {
  fs.writeFileSync(path.join(cwd, "index.js"), "require('crypto').createHash('md5');\n");
  process.exit(0);
}
process.exit(1);
`;

interface GitCall {
  args: string[];
  env: Record<string, string>;
}

describe("parseGitHubRepo", () => {
  it("accepts the documented GitHub forms and normalizes them to one https URL", () => {
    for (const input of [
      "octocat/Hello-World",
      "octocat/Hello-World.git",
      "github.com/octocat/Hello-World",
      "https://github.com/octocat/Hello-World",
      "https://github.com/octocat/Hello-World.git",
      "https://github.com/octocat/Hello-World/",
      "https://www.github.com/octocat/Hello-World",
    ]) {
      expect(parseGitHubRepo(input), input).toEqual({
        owner: "octocat",
        repo: "Hello-World",
        url: "https://github.com/octocat/Hello-World.git",
      });
    }
    expect(parseGitHubRepo("my-org/.github")?.repo).toBe(".github");
  });

  it("rejects anything that is not a strictly valid owner/repo on github.com", () => {
    for (const input of [
      "-owner/repo", // leading hyphen
      "owner-/repo", // trailing hyphen
      "own_er/repo", // underscore in an owner
      "cloudflare.com/cdn-cgi", // a dot in an owner means a hostname, not GitHub
      `${"a".repeat(40)}/repo`, // owner longer than 39 characters
      `owner/${"r".repeat(101)}`,
      "owner/..",
      "owner/.",
      "owner/.git",
      "owner/re po",
      "owner/repo/tree/main",
      "http://github.com/owner/repo", // https only
      "https://github.com:443/owner/repo",
      "https://user:secret@github.com/owner/repo",
      "https://github.com@evil.example/owner/repo",
      "https://github.com/owner/repo?ref=x",
      "https://github.com/owner/repo#readme",
      "https://gitlab.com/owner/repo",
      "git@github.com:owner/repo.git",
      "ssh://git@github.com/owner/repo.git",
    ]) {
      expect(parseGitHubRepo(input), input).toBeNull();
    }
  });
});

describe("parseCloneRemote", () => {
  it("refuses every non-GitHub remote unless explicitly allowed", () => {
    for (const url of [
      "https://127.0.0.1/internal/secret.git",
      "https://localhost/team/secret.git",
      "https://internal.corp.local/team/repo.git",
      "git@127.0.0.1:internal/secret.git",
      "git@github.com:owner/repo.git",
      "ssh://git@github.com/owner/repo.git",
      "file:///etc",
      "ext::sh -c touch% /tmp/pwned",
      "--upload-pack=touch /tmp/pwned",
    ]) {
      expect(() => parseCloneRemote(url), url).toThrow(/only public GitHub repositories/);
    }
  });

  it("accepts validated https and ssh remotes with the opt-in", () => {
    expect(parseCloneRemote("https://git.example.com:8443/team/repo.git", true)).toEqual({
      transport: "https",
      url: "https://git.example.com:8443/team/repo.git",
      host: "git.example.com",
      port: 8443,
    });
    expect(parseCloneRemote("git@git.example.com:team/repo.git", true)).toMatchObject({
      transport: "ssh",
      host: "git.example.com",
    });
    expect(parseCloneRemote("ssh://git@git.example.com:2222/team/repo.git", true)).toMatchObject({
      transport: "ssh",
      host: "git.example.com",
    });
  });

  it("still rejects malformed remotes with the opt-in", () => {
    for (const url of [
      "http://git.example.com/team/repo.git",
      "git://git.example.com/team/repo.git",
      "file:///etc/repo.git",
      "ext::sh -c touch% /tmp/pwned",
      "https://user:pw@git.example.com/team/repo.git",
      "https://git.example.com/team/repo.git?x=1",
      "https://git.example.com:0/team/repo.git",
      "https://-oProxyCommand=x/team/repo.git",
      "git@-oProxyCommand=x:team/repo.git",
      "git@git.example.com:-u/repo.git",
      "git@git.example.com:../../etc",
      "https://git.example.com/team/re po.git",
    ]) {
      expect(() => parseCloneRemote(url, true), url).toThrow(/not a supported repository URL/);
    }
  });
});

describe("hardenedConfig", () => {
  const pin = [{ address: "203.0.114.9", family: 4 as const }];
  const v6 = [{ address: "2001:4860:4860::8888", family: 6 as const }];

  it("pins a host name to its vetted addresses, bracketing IPv6", () => {
    const remote = parseCloneRemote("https://git.example.com:8443/team/repo.git", true);
    expect(hardenedConfig(remote, [...pin, ...v6])).toContain(
      "http.curloptResolve=git.example.com:8443:203.0.114.9,[2001:4860:4860::8888]",
    );
  });

  it("does not pin an IP-literal host, which has nothing to resolve", () => {
    const remote = parseCloneRemote("https://[2001:4860:4860::8888]/team/repo.git", true);
    expect(
      hardenedConfig(remote, v6).some((setting) => setting.startsWith("http.curloptResolve")),
    ).toBe(false);
  });
});

describe("hardened git invocation (real git)", () => {
  const hasGit = spawnSync("git", ["--version"]).status === 0;

  it.skipIf(!hasGit)(
    "refuses every transport but the allowed one, even for local file:// URLs",
    async () => {
      const scratch = await mkdtemp(join(tmpdir(), "csw-clone-real-"));
      try {
        const source = join(scratch, "source");
        await mkdir(source);
        const run = (args: string[], cwd = scratch) =>
          spawnSync("git", args, { cwd, encoding: "utf8" });
        expect(run(["init", "-q"], source).status).toBe(0);
        const remote = parseCloneRemote("octocat/Hello-World");
        const result = spawnSync(
          "git",
          [
            ...hardenedConfig(remote),
            "clone",
            "--quiet",
            "--template=",
            "--",
            `file://${source}`,
            join(scratch, "out"),
          ],
          { cwd: scratch, env: gitEnvironment(remote, scratch), encoding: "utf8" },
        );
        expect(result.status).not.toBe(0);
        expect(result.stderr).toMatch(/transport 'file' not allowed/);
      } finally {
        await rm(scratch, { recursive: true, force: true });
      }
    },
  );

  it.skipIf(!hasGit)("removes the temp directory when a real clone fails", async () => {
    const scratchTmp = await mkdtemp(join(tmpdir(), "csw-clone-tmp-"));
    const previousTmp = process.env.TMPDIR;
    process.env.TMPDIR = scratchTmp;
    // A loopback port with nothing listening: git fails fast and offline.
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 1;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try {
      await expect(
        cloneRepository(`https://127.0.0.1:${port}/team/repo.git`, {
          allowAnyHost: true,
          allowPrivate: true,
        }),
      ).rejects.toThrow(/git clone of https:\/\/127\.0\.0\.1:\d+\/team\/repo\.git failed/);
      expect(await readdir(scratchTmp)).toEqual([]);
    } finally {
      if (previousTmp === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = previousTmp;
      await rm(scratchTmp, { recursive: true, force: true });
    }
  });
});

describe.skipIf(!posix)("cloneRepository", () => {
  let bin: string;
  let previousPath: string | undefined;

  const calls = (): GitCall[] => {
    const log = join(bin, "calls.jsonl");
    if (!existsSync(log)) return [];
    return readFileSync(log, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as GitCall);
  };
  const cloneCall = (): GitCall | undefined => calls().find((call) => call.args.includes("clone"));
  const cloneDir = (): string => cloneCall()?.args.at(-1) ?? "";

  beforeAll(async () => {
    bin = await mkdtemp(join(tmpdir(), "csw-fake-git-"));
    await writeFile(join(bin, "git"), FAKE_GIT, "utf8");
    await chmod(join(bin, "git"), 0o755);
  });
  afterAll(async () => {
    await rm(bin, { recursive: true, force: true });
  });
  beforeEach(async () => {
    await rm(join(bin, "calls.jsonl"), { force: true });
    previousPath = process.env.PATH;
    process.env.PATH = `${bin}${delimiter}${previousPath ?? ""}`;
    guard.resolveAllowedAddress.mockReset();
    guard.resolveAllowedAddress.mockResolvedValue([{ address: "140.82.121.4", family: 4 }]);
  });
  afterEach(() => {
    process.env.PATH = previousPath;
  });

  it("clones a GitHub repository with the hardened configuration and a pinned address", async () => {
    process.env.CSW_TEST_SECRET = "must-not-leak";
    process.env.GIT_DIR = "/tmp/elsewhere";
    try {
      const repo = await cloneRepository("octocat/ok");
      expect(existsSync(join(repo.dir, "index.js"))).toBe(true);
      await repo.cleanup();
      expect(existsSync(dirname(repo.dir))).toBe(false);
    } finally {
      delete process.env.CSW_TEST_SECRET;
      delete process.env.GIT_DIR;
    }

    expect(guard.resolveAllowedAddress).toHaveBeenCalledWith("github.com", false);
    const call = cloneCall();
    expect(call).toBeDefined();
    const settings = (call?.args ?? []).filter((_, i, all) => all[i - 1] === "-c");
    expect(settings).toEqual(
      expect.arrayContaining([
        "protocol.allow=never",
        "protocol.https.allow=always",
        "http.followRedirects=false",
        "credential.helper=",
        "core.hooksPath=/dev/null",
        "core.symlinks=false",
        "http.curloptResolve=github.com:443:140.82.121.4",
      ]),
    );
    expect(call?.args.slice(-10)).toEqual([
      "clone",
      "--quiet",
      "--depth",
      "1",
      "--no-tags",
      "--no-checkout",
      "--template=",
      "--",
      "https://github.com/octocat/ok.git",
      cloneDir(),
    ]);

    const env = call?.env ?? {};
    expect(env).toMatchObject({
      GIT_TERMINAL_PROMPT: "0",
      GIT_LFS_SKIP_SMUDGE: "1",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_ASKPASS: "",
    });
    expect(env.CSW_TEST_SECRET).toBeUndefined();
    expect(env.GIT_DIR).toBeUndefined();
    expect(env.SSH_AUTH_SOCK).toBeUndefined();
    expect(env.GIT_SSH_COMMAND).toBeUndefined();
    // Every git step runs hardened, not just the clone.
    expect(
      calls().map((c) => c.args.find((a) => ["clone", "ls-tree", "checkout"].includes(a))),
    ).toEqual(["clone", "ls-tree", "checkout"]);
    for (const c of calls()) expect(c.args).toContain("protocol.allow=never");
  });

  it("vets the host before spawning git, and spawns nothing when the guard refuses", async () => {
    guard.resolveAllowedAddress.mockRejectedValue(
      new Error("Refusing to scan internal.corp: resolves to non-public address 10.0.0.5"),
    );
    await expect(
      cloneRepository("https://internal.corp/team/repo.git", { allowAnyHost: true }),
    ).rejects.toThrow(/non-public address 10\.0\.0\.5/);
    expect(calls()).toEqual([]);
  });

  it("refuses git@ and other hosts without spawning git or resolving anything", async () => {
    for (const url of ["git@github.com:octocat/ok.git", "https://127.0.0.1/internal/secret.git"]) {
      await expect(cloneRepository(url), url).rejects.toThrow(/only public GitHub repositories/);
    }
    expect(guard.resolveAllowedAddress).not.toHaveBeenCalled();
    expect(calls()).toEqual([]);
  });

  it("runs ssh remotes in batch mode, pinned to the vetted address, only with the opt-in", async () => {
    guard.resolveAllowedAddress.mockResolvedValue([{ address: "203.0.114.9", family: 4 }]);
    const repo = await cloneRepository("git@git.example.com:team/ok.git", { allowAnyHost: true });
    await repo.cleanup();
    const call = cloneCall();
    expect(call?.args).toContain("protocol.ssh.allow=always");
    expect(call?.args).not.toContain("protocol.https.allow=always");
    expect(call?.env.GIT_SSH_COMMAND).toBe(
      "ssh -o BatchMode=yes -o ConnectTimeout=20 -o HostName=203.0.114.9 -o HostKeyAlias=git.example.com",
    );
  });

  it("removes the temp directory and strips terminal escapes from git's error output", async () => {
    const error = await cloneRepository("octocat/fail").then(
      () => null,
      (err: unknown) => err,
    );
    expect(error).toBeInstanceOf(Error);
    const message = error instanceof Error ? error.message : "";
    expect(message).toMatch(
      /git clone of https:\/\/github\.com\/octocat\/fail\.git failed: remote: \?\]0;pwned/,
    );
    expect([...message].filter((char) => char < " " || char === "\u007f")).toEqual([]);
    expect(existsSync(dirname(cloneDir()))).toBe(false);
  });

  it("kills git at the deadline and cleans up", async () => {
    await expect(cloneRepository("octocat/hang", { timeoutMs: 300 })).rejects.toThrow(
      /timed out after 300ms/,
    );
    expect(existsSync(dirname(cloneDir()))).toBe(false);
  });

  it("escalates to SIGKILL when git ignores SIGTERM", async () => {
    await expect(cloneRepository("octocat/stubborn", { timeoutMs: 200 })).rejects.toThrow(
      /timed out/,
    );
    expect(existsSync(dirname(cloneDir()))).toBe(false);
  });

  it("aborts on cancellation and cleans up", async () => {
    const controller = new AbortController();
    const pending = cloneRepository("octocat/hang", { signal: controller.signal });
    await vi.waitFor(() => expect(cloneCall()).toBeDefined());
    controller.abort();
    await expect(pending).rejects.toThrow(/cancelled/);
    expect(existsSync(dirname(cloneDir()))).toBe(false);
  });

  it("stops a download that exceeds the pack ceiling", async () => {
    await expect(
      cloneRepository("octocat/huge-pack", { maxPackBytes: 1024 * 1024 }),
    ).rejects.toThrow(/download exceeded the 1 MiB ceiling/);
    expect(existsSync(dirname(cloneDir()))).toBe(false);
  });

  it("refuses a checkout that would exceed the size or file ceiling, before writing it", async () => {
    await expect(
      cloneRepository("octocat/big-tree", { maxCheckoutBytes: 1024 * 1024 }),
    ).rejects.toThrow(/checkout would exceed the 1 MiB ceiling/);
    expect(calls().some((c) => c.args.includes("checkout"))).toBe(false);
    expect(existsSync(dirname(cloneDir()))).toBe(false);

    await rm(join(bin, "calls.jsonl"), { force: true });
    await expect(cloneRepository("octocat/many-files", { maxCheckoutFiles: 10 })).rejects.toThrow(
      /checkout would exceed the 10-file ceiling/,
    );
    expect(existsSync(dirname(cloneDir()))).toBe(false);
  });
});
