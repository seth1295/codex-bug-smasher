import { writeJsonLine as writeResult } from "./support/json.ts";
import { finding, scanId, workerDraft } from "./scan-draft-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import assert from "node:assert/strict";
import { mkdir, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";

const { validateDiscoveryArtifacts, validateReducerArtifacts } =
  await importSource(
    fileURLToPath(
      new URL("../src/deep-scan/artifact-validation.ts", import.meta.url),
    ),
  );

const root = await temporaryDirectory("functional-bug-artifact-validation-", true);
const otherScanId = "12c17317-9594-49e0-b06a-d72fd7e14bba";
try {
  const bug = finding("proration-order", "src/proration.mjs");
  const coverage = {
    completeness: "partial",
    surfaces: [
      {
        label: "Integer proration",
        disposition: "reported",
        notes: "A fractional input reproduced the incorrect result.",
      },
      {
        label: "Safe proration implementation",
        disposition: "no_issue_found",
        notes: "The sibling implementation returned the expected value.",
      },
    ],
    explicitExclusions: [],
    deferred: [
      {
        candidate: { title: "Potential large-value overflow" },
        reason: "The supported maximum amount was not established.",
      },
    ],
  };
  const draft = workerDraft([bug], { coverage });
  const artifacts = {
    scanDir: root,
    workersRoot: path.join(root, "artifacts", "deep_discovery", "workers"),
    dedupRoot: path.join(root, "artifacts", "deep_discovery", "dedup"),
  };
  const workerDir = path.join(artifacts.workersRoot, "discovery-0001", "output");
  await mkdir(workerDir, { recursive: true });
  const workerResultPath = path.join(workerDir, "result.json");
  await writeResult(workerResultPath, draft);

  assert.deepEqual(
    await validateDiscoveryArtifacts(artifacts, workerResultPath, scanId),
    draft,
  );

  await writeResult(workerResultPath, { ...draft, complete: false });
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, workerResultPath, scanId),
    /checkpoint|not complete/,
  );

  await writeResult(workerResultPath, {
    ...draft,
    findings: [
      {
        ...bug,
        validation: {
          status: "hypothesis",
          method: "The source path was not fully traced.",
          evidence: ["The suspected call path may be unreachable."],
        },
      },
    ],
  });
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, workerResultPath, scanId),
    /validated/,
  );

  await writeResult(workerResultPath, {
    ...draft,
    findings: [{ ...bug, attackPath: { steps: ["not a correctness field"] } }],
  });
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, workerResultPath, scanId),
  );

  await writeResult(workerResultPath, { ...draft, scanId: otherScanId });
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, workerResultPath, scanId),
    /different scan/,
  );

  await writeResult(workerResultPath, draft);
  const reducerDir = path.join(artifacts.dedupRoot, "dedup-0001", "output");
  await mkdir(reducerDir, { recursive: true });
  const reducerResultPath = path.join(reducerDir, "result.json");
  const sourceFinding = {
    ...bug,
    provenance: {
      ...bug.provenance,
      sourceFindingIds: ["worker-001:0"],
    },
  };
  const sourceCoverage = {
    ...coverage,
    surfaces: coverage.surfaces.map((surface) => ({
      ...surface,
      sourceWorkerIds: ["worker-001"],
    })),
    deferred: coverage.deferred.map((item) => ({
      ...item,
      sourceWorkerIds: ["worker-001"],
    })),
  };
  const sources = {
    discoveries: [
      {
        workerId: "worker-001",
        result: {
          ...draft,
          findings: [sourceFinding],
          scanCoverage: sourceCoverage,
        },
      },
    ],
    previous: null,
  };
  await writeResult(reducerResultPath, {
    scanId,
    reviewType: "functional_bug",
    findings: [sourceFinding],
  });
  const accepted = await validateReducerArtifacts(
    {
      artifacts,
      artifactDir: reducerDir,
      resultPath: reducerResultPath,
      reducerId: "dedup-0001",
      sources,
    },
    scanId,
  );
  assert.equal(accepted.newFindings, 1);
  assert.deepEqual(accepted.result.scanCoverage, {
    completeness: "partial",
    surfaces: sourceCoverage.surfaces,
    explicitExclusions: [],
    deferred: sourceCoverage.deferred,
    openQuestions: [],
  });
  assert.deepEqual(
    accepted.result.findings[0]?.provenance.sourceFindingIds,
    ["worker-001:0"],
  );
  assert.deepEqual(
    await validateDiscoveryArtifacts(artifacts, workerResultPath, scanId),
    draft,
  );
  const savedReducer = await readFile(reducerResultPath, "utf8");
  assert.equal(savedReducer.includes('"severity"'), false);
  assert.equal(savedReducer.includes('"taxonomy"'), false);
  assert.equal(savedReducer.includes('"attackPath"'), false);
} finally {
  await rm(root, { recursive: true, force: true });
}

console.log("functional bug discovery and reducer artifacts validated");
