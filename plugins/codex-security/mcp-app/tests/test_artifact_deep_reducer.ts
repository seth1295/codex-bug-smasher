import { readJson, writeJson } from "./support/json.ts";
import { sourceReferences } from "./support/source-references.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { finding, scanId, workerDraft } from "./scan-draft-fixture.ts";
import assert from "node:assert/strict";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";

type Finding = ReturnType<typeof finding>;

const {
  deepReducerInputsInputSchema,
  deepReductionInputSchema,
  getCodexSecurityDeepReducerInputs,
  recordCodexSecurityDeepReduction,
} = await importSource(
  fileURLToPath(new URL("../src/artifact-deep-reducer.ts", import.meta.url)),
);

const validReduction = reduction([]);

assert.equal(
  deepReducerInputsInputSchema.safeParse({ maxBytes: 4096 }).success,
  true,
);
assert.equal(deepReducerInputsInputSchema.safeParse({}).success, false);
assert.equal(
  deepReducerInputsInputSchema.safeParse({ path: "/tmp" }).success,
  false,
);
assert.equal(deepReductionInputSchema.safeParse(validReduction).success, true);
assert.equal(
  deepReductionInputSchema.safeParse(workerDraft([])).success,
  false,
  "Deep reducer submissions no longer accept coverage",
);
assert.equal(
  deepReductionInputSchema.safeParse({ ...validReduction, resultPath: "/tmp" })
    .success,
  false,
);
assert.equal(
  deepReductionInputSchema.safeParse({
    ...validReduction,
    consumedWorkerIds: ["spoofed"],
  }).success,
  false,
);
assert.equal(
  deepReductionInputSchema.safeParse({ candidates: [], merges: [] }).success,
  false,
);

const root = await temporaryDirectory("functional-bug-deep-reducer-", true);
try {
  const scanRoot = path.join(root, "scan");
  const workersRoot = path.join(
    scanRoot,
    "artifacts",
    "deep_discovery",
    "workers",
  );
  const dedupRoot = path.join(scanRoot, "artifacts", "deep_discovery", "dedup");

  const shared = finding("shared", "src/shared.ts");
  const independent = finding("independent", "src/independent.ts");
  const rejectedCoverage = {
    completeness: "partial",
    surfaces: [
      {
        label: "Payment calculation",
        disposition: "rejected",
        notes: "The cents rounding rule matches the documented result.",
        receiptRefs: ["artifacts/missing-worker-receipt.md"],
      },
      {
        label: "Batch import",
        disposition: "needs_follow_up",
        notes: "The alternate parser still needs review.",
      },
    ],
    explicitExclusions: [
      { pattern: "vendor", reason: "Outside the requested source scope." },
    ],
    deferred: [
      {
        candidateId: "candidate-import",
        reason: "Check whether the alternate parser truncates early.",
        paths: ["src/import.ts"],
      },
    ],
    openQuestions: ["Does the alternate parser apply the same rounding rule?"],
  };
  const first = await createWorker({
    workersRoot,
    label: "discovery-0001",
    id: "worker-001",
    result: workerDraft([shared], {
      coverage: rejectedCoverage,
    }),
  });
  const second = await createWorker({
    workersRoot,
    label: "discovery-0002",
    id: "worker-002",
    result: workerDraft([shared, independent], {
      scope: { summary: "Shared and independent request handling." },
      coverage: { ...workerDraft([]).coverage, completeness: "unknown" },
    }),
  });
  const originalWorkerArtifacts = await Promise.all(
    [first, second].map((worker) => readFile(worker.resultPath, "utf8")),
  );
  const outputRoot = path.join(dedupRoot, "dedup-0001", "output");
  await mkdir(outputRoot, { recursive: true });
  const context = {
    root: outputRoot,
    repoRoot: root,
    scanId,
    layout: "reducer",
    deepReducer: {
      scanRoot,
      claimedWorkers: [first, second],
    },
  };

  const inputs = await getCodexSecurityDeepReducerInputs(context);
  await assert.rejects(
    recordCodexSecurityDeepReduction(
      context,
      reduction([], { complete: false }),
    ),
    /only a checkpoint/,
    "a reducer submission must contain a complete result",
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(context, reduction([shared])),
    /unaccounted|discarded.*finding/,
    "a successful reduction must account for every fresh finding, not just one",
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(
      context,
      reduction([
        shared,
        independent,
        finding("invented", "src/unreviewed.ts"),
      ]),
    ),
    /no assigned source finding/,
    "a reducer cannot introduce an unvalidated finding outside its assigned sources",
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(
      context,
      reduction(
        [
          {
            ...shared,
            validation: {
              status: "hypothesis",
              method: "The source path was not verified.",
              evidence: ["The suspected call path is incomplete."],
            },
          },
          independent,
        ],
        { complete: true },
      ),
    ),
    /validated/,
    "the reducer cannot promote an unresolved hypothesis into a confirmed bug",
  );
  assert.deepEqual(inputs, {
    discoveries: [
      { workerId: first.id, result: withSourceRefs(first) },
      { workerId: second.id, result: withSourceRefs(second) },
    ],
    previous: null,
  });
  assert.equal(JSON.stringify(inputs).includes(root), false);
  assert.equal(JSON.stringify(inputs).includes("result.json"), false);

  await assert.rejects(readFile(path.join(outputRoot, "result.json"), "utf8"), {
    code: "ENOENT",
  });
  await assert.rejects(
    readdir(path.join(outputRoot, "checkpoints")),
    { code: "ENOENT" },
    "invalid reducer submissions do not save a checkpoint",
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(context, reduction([])),
    /discarded every accepted bug finding/,
  );

  const merged = reduction([shared, independent], {
    scope: { summary: "Shared and independent request handling." },
  });
  const outcome = await recordCodexSecurityDeepReduction(context, merged);
  const mergedWithSources = {
    ...merged,
    scanCoverage: {
      completeness: "partial",
      surfaces: [
        {
          label: "Payment calculation",
          disposition: "rejected",
          notes: "The cents rounding rule matches the documented result.",
          receiptRefs: ["artifacts/missing-worker-receipt.md"],
          sourceWorkerIds: [first.id],
        },
        {
          label: "Batch import",
          disposition: "needs_follow_up",
          notes: "The alternate parser still needs review.",
          sourceWorkerIds: [first.id],
        },
      ],
      explicitExclusions: [
        { pattern: "vendor", reason: "Outside the requested source scope." },
      ],
      deferred: [
        {
          candidateId: "candidate-import",
          reason: "Check whether the alternate parser truncates early.",
          paths: ["src/import.ts"],
          sourceWorkerIds: [first.id],
        },
      ],
      openQuestions: ["Does the alternate parser apply the same rounding rule?"],
    },
    findings: [
      retainedFinding(shared, [
        { id: "worker-001:0", finding: shared },
        { id: "worker-002:0", finding: shared },
      ]),
      retainedFinding(independent, [
        { id: "worker-002:1", finding: independent },
      ]),
    ],
  };
  assert.deepEqual(outcome, {
    findingCount: 2,
    consumedWorkerIds: [first.id, second.id],
  });
  assert.deepEqual(
    await readJson(outputRoot, "result.json"),
    mergedWithSources,
  );
  const checkpointNames = await readdir(path.join(outputRoot, "checkpoints"));
  assert.equal(checkpointNames.length, 1);
  assert.deepEqual(
    await readJson(outputRoot, "checkpoints", checkpointNames[0]),
    mergedWithSources,
    "reducer checkpoints retain accepted findings, scope, and source coverage",
  );

  assert.deepEqual(
    await Promise.all(
      [first, second].map((worker) => readFile(worker.resultPath, "utf8")),
    ),
    originalWorkerArtifacts,
    "reduction must not rewrite raw discovery worker coverage evidence",
  );

  const collision = {
    ...independent,
    ruleId: shared.ruleId,
    identity: shared.identity,
  };
  const collisionWorker = await createWorker({
    workersRoot,
    label: "discovery-collision",
    id: "worker-collision",
    result: workerDraft([shared, collision]),
  });
  const collisionRoot = path.join(dedupRoot, "dedup-collision", "output");
  await mkdir(collisionRoot, { recursive: true });
  const collisionContext = {
    ...context,
    root: collisionRoot,
    deepReducer: { scanRoot, claimedWorkers: [collisionWorker] },
  };
  await assert.rejects(
    recordCodexSecurityDeepReduction(collisionContext, reduction([shared])),
    /ambiguous|unaccounted/,
  );
  const collisionInputs =
    await getCodexSecurityDeepReducerInputs(collisionContext);
  const sourceFindingIds =
    collisionInputs.discoveries[0].result.findings.flatMap(
      (finding: { provenance: { sourceFindingIds: string[] } }) =>
        finding.provenance.sourceFindingIds,
    );
  assert.deepEqual(sourceFindingIds, [
    "worker-collision:0",
    "worker-collision:1",
  ]);
  await recordCodexSecurityDeepReduction(
    collisionContext,
    reduction([
      {
        ...shared,
        provenance: { ...shared.provenance, sourceFindingIds },
      },
    ]),
  );
  const collisionOutput = await readJson(collisionRoot, "result.json");
  assert.deepEqual(collisionOutput.findings[0].provenance.sourceFindings, [
    { id: "worker-collision:0", finding: shared },
    { id: "worker-collision:1", finding: collision },
  ]);
  await assert.rejects(
    recordCodexSecurityDeepReduction(
      collisionContext,
      reduction([
        {
          ...shared,
          provenance: {
            ...shared.provenance,
            sourceFindingIds: ["unassigned:0"],
          },
        },
      ]),
    ),
    /unknown source finding/,
  );
  await assert.rejects(
    readFile(
      path.join(
        scanRoot,
        "artifacts",
        "02_discovery",
        "candidate_ledger.jsonl",
      ),
    ),
    { code: "ENOENT" },
  );

  const third = await createWorker({
    workersRoot,
    label: "discovery-0003",
    id: "worker-003",
    result: workerDraft([shared]),
  });
  const nextOutputRoot = path.join(dedupRoot, "dedup-0002", "output");
  await mkdir(nextOutputRoot, { recursive: true });
  const nextContext = {
    root: nextOutputRoot,
    repoRoot: root,
    scanId,
    layout: "reducer",
    deepReducer: {
      scanRoot,
      claimedWorkers: [third],
      previousReducerResultPath: path.join(outputRoot, "result.json"),
    },
  };
  const nextInputs = await getCodexSecurityDeepReducerInputs(nextContext);
  assert.deepEqual(nextInputs, {
    discoveries: [{ workerId: third.id, result: withSourceRefs(third) }],
    previous: mergedWithSources,
  });
  await assert.rejects(
    recordCodexSecurityDeepReduction(nextContext, reduction([shared])),
    (error: NodeJS.ErrnoException) =>
      error.code === "merge_traceability_unstable_candidate_id",
  );
  assert.deepEqual(
    await recordCodexSecurityDeepReduction(nextContext, merged),
    { findingCount: 2, consumedWorkerIds: [third.id] },
  );
  assert.deepEqual(await readJson(nextOutputRoot, "result.json"), {
    ...mergedWithSources,
    findings: [
      retainedFinding(shared, [
        { id: "worker-003:0", finding: shared },
        { id: "worker-001:0", finding: shared },
        { id: "worker-002:0", finding: shared },
      ]),
      mergedWithSources.findings[1],
    ],
  });

  const enrichedPrevious = structuredClone(mergedWithSources);
  enrichedPrevious.findings[0].summary =
    "The earlier reduction established another input path to the incorrect result.";
  enrichedPrevious.findings[0].validation = {
    status: "validated",
    method: "A focused reproduction exercised both input paths.",
    evidence: ["Both paths returned the same incorrect result."],
    reproduction: ["Call the input that reaches either path."],
    counterEvidence: ["The safe implementation returned the expected value."],
  };
  for (const legacyCoverage of [
    rejectedCoverage,
    {
      completeness: "outdated",
      surfaces: [null],
      explicitExclusions: false,
      deferred: 42,
    },
    "legacy coverage is no longer structured",
  ]) {
    const previousArtifact = JSON.stringify({
      ...enrichedPrevious,
      coverage: legacyCoverage,
    });
    await writeFile(path.join(outputRoot, "result.json"), previousArtifact);
    assert.deepEqual(
      (await getCodexSecurityDeepReducerInputs(nextContext)).previous,
      enrichedPrevious,
      "previous reducer coverage is ignored even when malformed; findings and scope remain intact",
    );
    assert.equal(
      await readFile(path.join(outputRoot, "result.json"), "utf8"),
      previousArtifact,
      "reading a previous reduction does not rewrite its legacy coverage",
    );
  }
  const previousArtifact = await readFile(
    path.join(outputRoot, "result.json"),
    "utf8",
  );
  await recordCodexSecurityDeepReduction(nextContext, merged);
  const preservedEnrichment = await readJson(nextOutputRoot, "result.json");
  assert.equal(
    Object.hasOwn(preservedEnrichment, "coverage"),
    false,
    "a subsequent accepted reduction omits the previous reducer's legacy coverage",
  );
  assert.equal(
    await readFile(path.join(outputRoot, "result.json"), "utf8"),
    previousArtifact,
    "the original previous reduction remains available without rewriting its coverage",
  );
  assert.equal(
    preservedEnrichment.findings[0].provenance.previousFindings[0].summary,
    enrichedPrevious.findings[0].summary,
    "previous synthesized evidence must survive even when source references are unchanged",
  );

  await assert.rejects(
    getCodexSecurityDeepReducerInputs({ root, repoRoot: root, layout: "scan" }),
    /No active Deep reducer is bound/,
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(context, {
      ...merged,
      scanId: "12c17317-9594-49e0-b06a-d72fd7e14bba",
    }),
    /scanId does not match/,
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(context, {
      ...merged,
      findings: [
        {
          ...shared,
          locations: [{ path: "src/shared.ts", startLine: 3, endLine: 2 }],
        },
      ],
    }),
    /endLine/,
  );
  await assert.rejects(
    getCodexSecurityDeepReducerInputs({
      ...context,
      deepReducer: { ...context.deepReducer, claimedWorkers: [first, first] },
    }),
    /repeats assigned discovery worker/,
  );

  await writeJson(first.resultPath, { ...first.result, complete: false });
  await assert.rejects(
    getCodexSecurityDeepReducerInputs(context),
    /only a checkpoint/,
    "unfinished discovery worker results are not reducer inputs",
  );

  for (const invalidCoverage of [
    undefined,
    { ...workerDraft([]).coverage, completeness: "outdated" },
  ]) {
    await writeJson(first.resultPath, {
      ...first.result,
      coverage: invalidCoverage,
    });
    await assert.rejects(
      getCodexSecurityDeepReducerInputs(context),
      /coverage|completeness/,
      "discovery worker coverage remains required and validated before projection",
    );
  }

  await writeFile(first.resultPath, "{invalid functional bug scan\n");
  await assert.rejects(
    getCodexSecurityDeepReducerInputs(context),
    (error: Error) =>
      error.name !== "DeepScanNonRetryableError" &&
      /Invalid Deep Scan JSON artifact/.test(error.message) &&
      !error.message.includes(root),
  );

  await writeJson(first.resultPath, {
    ...first.result,
    scanId: "12c17317-9594-49e0-b06a-d72fd7e14bba",
  });
  await assert.rejects(
    getCodexSecurityDeepReducerInputs(context),
    (error: Error) =>
      error.name !== "DeepScanNonRetryableError" &&
      /different scan/.test(error.message) &&
      !error.message.includes(root),
  );
} finally {
  await rm(root, { recursive: true, force: true });
}

console.log("artifact deep reducer tests passed");

async function createWorker({
  workersRoot,
  label,
  id,
  result,
}: {
  workersRoot: string;
  label: string;
  id: string;
  result: ReturnType<typeof workerDraft<Finding>>;
}) {
  const workerRoot = path.join(workersRoot, label, "output");
  await mkdir(workerRoot, { recursive: true });
  const resultPath = path.join(workerRoot, "result.json");
  await writeFile(resultPath, JSON.stringify(result) + "\n");
  return { id, resultPath, result };
}

function reduction(findings: Record<string, unknown>[], extra = {}) {
  return { scanId, reviewType: "functional_bug", findings, ...extra };
}

function withSourceRefs(worker: Awaited<ReturnType<typeof createWorker>>) {
  const { coverage, ...result } = worker.result;
  const scanCoverage = structuredClone(coverage) as {
    completeness: string;
    surfaces: Record<string, unknown>[];
    explicitExclusions: Record<string, unknown>[];
    deferred: Record<string, unknown>[];
    openQuestions?: unknown[];
  };
  scanCoverage.surfaces = scanCoverage.surfaces.map((surface) => ({
    ...surface,
    sourceWorkerIds: [worker.id],
  }));
  scanCoverage.deferred = scanCoverage.deferred.map((candidate) => ({
    ...candidate,
    sourceWorkerIds: [worker.id],
  }));
  return {
    ...result,
    scanCoverage,
    findings: worker.result.findings.map(sourceReferences(worker)),
  };
}

function retainedFinding(
  finding: Finding & { validation?: unknown },
  sourceFindings: { id: string; finding: unknown }[],
) {
  return {
    ...finding,
    provenance: {
      ...finding.provenance,
      sourceFindingIds: sourceFindings.map((source) => source.id),
      sourceFindings,
    },
  };
}
