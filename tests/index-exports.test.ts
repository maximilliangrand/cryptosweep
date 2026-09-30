import { describe, expect, it } from "vitest";
import * as lib from "../src/index";

/**
 * The library surface after the audit fixes: the only clone path is the
 * hardened one behind the SSRF guard, and the orchestrator, guard and rule
 * catalogue are reachable without deep imports.
 */
describe("library exports", () => {
  it("exposes the hardened clone path and not the old unguarded helper", () => {
    expect("cloneRepo" in lib).toBe(false);
    expect(typeof lib.cloneRepository).toBe("function");
    expect(typeof lib.parseGitHubRepo).toBe("function");
  });

  it("exposes the orchestrator, the shared guard and the rule catalogue", () => {
    for (const fn of [lib.classifyTarget, lib.scanTarget, lib.scanLocalDir, lib.resolveAllowedAddress, lib.assessThreat]) {
      expect(typeof fn).toBe("function");
    }
    expect(lib.SOURCE_RULES.length).toBeGreaterThan(0);
    expect(lib.entryForRuleId(lib.depsRuleId({ ecosystem: "npm", name: "jsonwebtoken" }))?.name).toBe("jsonwebtoken");
  });
});
