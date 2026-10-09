import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import type {
  CodexWorkerRequest,
  CodexWorkerResult,
} from "../src/deep-scan/types.js";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import {
  DeepScanCoordinator,
  FakeStore,
  fixtureRun,
  promptContext,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";
import { readJson, writeJson } from "./support/json.ts";

const execFileAsync = promisify(execFile);

const root = await temporaryDirectories.create("functional-bug-scan-e2e-");
try {
  const fixture = await fixtureRun({
    workers: 2,
    subagents: 1,
    stopAfterNoNew: 1,
    maxDiscoveryRuns: 2,
    maxTimeHours: 1,
  });
  fixture.run.targetPath = path.join(root, "invoice-fixture");
  fixture.run.scanDir = path.join(root, "saved-scan");
  const sourcePath = path.join(fixture.run.targetPath, "src", "proration.mjs");
  await mkdir(path.dirname(sourcePath), { recursive: true });
  const source = await readFile(
    new URL("./fixtures/functional-bug/proration.mjs", import.meta.url),
    "utf8",
  );
  await writeFile(sourcePath, source, "utf8");
  const sourceModule = await import(
    `${pathToFileURL(sourcePath).href}?fixture=${Date.now()}`
  );
  assert.equal(sourceModule.prorateCents(500, 2, 5), 0);
  assert.equal(sourceModule.prorateCentsSafe(500, 2, 5), 200);

  const store = new FakeStore(fixture.run);
  const workerSubagents: number[] = [];
  let reviewDraft: ScanDraftInput | undefined;
  const executor = {
    async run(request: CodexWorkerRequest): Promise<CodexWorkerResult> {
      request.signal.throwIfAborted();
      const context = await promptContext(request.promptPath);
      const artifactRoot = request.artifactContext?.root;
      assert.ok(artifactRoot);
      const destination = path.join(artifactRoot, "result.json");
      if (request.kind === "discovery") {
        workerSubagents.push(request.subagents);
        assert.equal(request.subagents, 1);
        const currentSource = await readFile(sourcePath, "utf8");
        const defectLine = currentSource
          .split(/\r?\n/u)
          .findIndex((line) =>
            line.includes("Math.floor(numerator / denominator) * amountCents"),
          ) + 1;
        const actual = sourceModule.prorateCents(500, 2, 5);
        const expected = 200;
        const findings =
          defectLine > 0 && actual !== expected
          ? [
                {
                  ruleId: "invoice.proration.integer-order",
                  identity: { anchor: "invoice-proration-integer-order" },
                  title: "Proration truncates the ratio before applying the amount",
                  summary:
                    "The implementation divides the integer numerator by the denominator before multiplying by the invoice amount.",
                  priority: "P1",
                  category: "algorithm",
                  confidence: {
                    level: "high",
                    rationale:
                      "A direct reproduction returns zero while the documented proration result is 200 cents.",
                  },
                  locations: [
                    {
                      path: "src/proration.mjs",
                      startLine: defectLine,
                      endLine: defectLine,
                    },
                  ],
                  expected: "prorateCents(500, 2, 5) returns 200 cents.",
                  actual: `prorateCents(500, 2, 5) returns ${actual} cents.`,
                  impact:
                    "Invoices with a fractional ratio can be undercharged.",
                  validation: {
                    status: "validated",
                    method: "Executed the fixture function with a deterministic input.",
                    evidence: [
                      "The buggy function returned 0; the expected value is 200.",
                    ],
                    reproduction: ["Call prorateCents(500, 2, 5)."],
                    counterEvidence: [
                      "The safe sibling function returned 200 for the same input.",
                    ],
                  },
                  suggestedCorrection:
                    "Multiply the amount by the numerator before dividing, using the documented rounding rule.",
                  tests: [
                    "Add a regression test for a fractional ratio and a nonzero amount.",
                  ],
                  provenance: {
                    source: "local_plugin",
                    candidateId: "invoice-proration-integer-order",
                    workerLabel: context.workerLabel,
                  },
                },
              ]
            : [];
        await writeJson(destination, {
          scanId: context.scanId,
          reviewType: "functional_bug",
          findings,
          coverage: {
            completeness: "complete",
            surfaces: [
              {
                label: "Integer proration",
                disposition: findings.length ? "reported" : "no_issue_found",
                notes: findings.length
                  ? "The incorrect fractional calculation was reproduced."
                  : "No incorrect result was reproduced.",
              },
              {
                label: "Safe proration implementation",
                disposition:
                  sourceModule.prorateCentsSafe(500, 2, 5) === expected
                    ? "no_issue_found"
                    : "needs_follow_up",
                notes: "The safe implementation returned 200 cents.",
              },
            ],
            explicitExclusions: [],
            deferred: [],
          },
        });
        return { threadId: `discovery-thread-${context.workerLabel}` };
      }

      if (request.kind !== "dedup") {
        throw new Error(`Unexpected worker kind: ${request.kind}`);
      }
      const reducer = request.artifactContext?.deepReducer;
      assert.ok(reducer);
      const sourceFindings: Array<{
        id: string;
        finding: Record<string, any>;
      }> = [];
      for (const worker of reducer.claimedWorkers) {
        const workerResult = await readJson(worker.resultPath);
        for (const [index, finding] of workerResult.findings.entries()) {
          sourceFindings.push({
            id: `${worker.id}:${index}`,
            finding,
          });
        }
      }
      const merged = new Map<string, Record<string, any>>();
      for (const sourceFinding of sourceFindings) {
        const key = `${sourceFinding.finding.ruleId}:${sourceFinding.finding.identity.anchor}`;
        const existing = merged.get(key);
        merged.set(key, {
          ...(existing ?? sourceFinding.finding),
          provenance: {
            ...sourceFinding.finding.provenance,
            ...(existing?.provenance ?? {}),
            source: "local_plugin",
            sourceFindingIds: [
              ...new Set([
                ...(existing?.provenance?.sourceFindingIds ?? []),
                sourceFinding.id,
              ]),
            ],
          },
        });
      }
      await writeJson(destination, {
        scanId: fixture.run.scanId,
        reviewType: "functional_bug",
        findings: [...merged.values()],
      });
      return { threadId: `reducer-thread-${context.reducerLabel}` };
    },
  };

  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [],
    clock: {
      now: () => 1_700_000_000_000,
      sleep: async (_delay: number, signal: AbortSignal) => signal.throwIfAborted(),
    },
    threadId: "fixture-owner",
    onComplete: async (draft: ScanDraftInput) => {
      reviewDraft = draft;
    },
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 30_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal?.terminalReason, "capped");
  assert.deepEqual(workerSubagents, [1, 1]);
  assert.equal(store.dedupClaims.length, 1);
  assert.ok(reviewDraft);
  const reviewCoverage = reviewDraft.coverage as {
    completeness: string;
    deferred: Record<string, unknown>[];
    surfaces: Array<Record<string, unknown>>;
    explicitExclusions: Record<string, unknown>[];
  };
  assert.equal(reviewDraft.reviewType, "functional_bug");
  assert.equal(reviewDraft.findings.length, 1);
  assert.equal(reviewDraft.findings[0].priority, "P1");
  assert.equal(
    (reviewDraft.findings[0].confidence as { level: string }).level,
    "high",
  );
  const sourceRefs = reviewDraft.findings[0].provenance as {
    sourceFindingIds?: string[];
  };
  assert.equal(sourceRefs.sourceFindingIds?.length, 2);
  assert.equal(reviewCoverage.deferred.length, 0);
  assert.equal(
    reviewCoverage.surfaces.some(
      (surface) =>
        surface.label === "Safe proration implementation" &&
        surface.disposition === "no_issue_found",
    ),
    true,
  );

  await writeJson(path.join(fixture.run.scanDir, "scan-manifest.json"), {
    scan: {
      id: fixture.run.scanId,
      producer: { name: "functional-bug-scan-plugin", version: "0.1.160" },
      status: "completed",
      startedAt: "2026-10-09T00:00:00Z",
      completedAt: "2026-10-09T00:05:00Z",
      reviewType: "functional_bug",
      target: {
        kind: "directory_snapshot",
        targetId: "functional-bug-fixture",
        displayName: "invoice-fixture",
        snapshotDigest: `codex-security-snapshot/v1:sha256:${"1".repeat(64)}`,
      },
      scope: { includePaths: ["."], excludePaths: [] },
    },
  });
  const deferred = reviewCoverage.deferred;
  await writeJson(path.join(fixture.run.scanDir, "findings.json"), {
    documentType: "functional-bug-scan.findings",
    schemaVersion: "1.0",
    scanId: fixture.run.scanId,
    findings: reviewDraft!.findings,
    hypotheses: deferred.filter(
      (item) => "candidate" in item || "finding" in item || "hypothesis" in item,
    ),
  });
  await writeJson(path.join(fixture.run.scanDir, "coverage.json"), {
    documentType: "functional-bug-scan.coverage",
    schemaVersion: "1.0",
    scanId: fixture.run.scanId,
    mode: "deep_repository",
    completeness: reviewCoverage.completeness,
    inventoryStrategy: "repository",
    includePaths: ["."],
    excludePaths: [],
    reviewedAreas: reviewCoverage.surfaces.map(
      (surface) => ({
        label: surface.label,
        disposition:
          surface.disposition === "not_applicable" ? "excluded" :
          surface.disposition === "needs_follow_up" ? "follow_up" : "reviewed",
        notes: surface.notes,
        ...(surface.sourceWorkerIds === undefined
          ? {}
          : { sourceWorkerIds: surface.sourceWorkerIds }),
      }),
    ),
    explicitExclusions: reviewCoverage.explicitExclusions,
    deferred,
  });

  const finalizer = fileURLToPath(
    new URL("../../scripts/finalize_scan_contract.py", import.meta.url),
  );
  await execFileAsync(
    process.platform === "win32" ? "python" : "python3",
    [finalizer, "--scan-dir", fixture.run.scanDir],
    { cwd: path.dirname(finalizer), windowsHide: true },
  );
  const savedManifest = await readJson(path.join(fixture.run.scanDir, "scan-manifest.json"));
  const savedFindings = await readJson(path.join(fixture.run.scanDir, "findings.json"));
  const savedCoverage = await readJson(path.join(fixture.run.scanDir, "coverage.json"));
  const report = await readFile(path.join(fixture.run.scanDir, "report.md"), "utf8");
  assert.equal(savedManifest.documentType, "functional-bug-scan.scan-manifest");
  assert.equal(savedFindings.documentType, "functional-bug-scan.findings");
  assert.equal(savedFindings.findings.length, 1);
  assert.equal(savedFindings.findings[0].priority, "P1");
  assert.equal(savedFindings.findings[0].validation.status, "validated");
  assert.equal(savedFindings.findings[0].provenance.sourceFindingIds.length, 2);
  assert.equal(savedCoverage.reviewedAreas.length >= 4, true);
  assert.match(report, /Functional Bug Report/);
  assert.match(report, /P1/);
  assert.match(report, /Safe proration implementation/);
  assert.doesNotMatch(report, /## Unvalidated hypotheses/);
  assert.doesNotMatch(report, /CWE|taxonomy|attack path|security severity/iu);
  assert.equal(
    Object.keys(savedFindings.findings[0]).some((field) =>
      ["severity", "taxonomy", "attackPath"].includes(field),
    ),
    false,
  );
} finally {
  await temporaryDirectories.cleanup();
}
