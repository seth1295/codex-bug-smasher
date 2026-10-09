import { readJson, writeJson } from "../json.ts";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, realpath } from "node:fs/promises";
import path from "node:path";
import { sourceReferences } from "../source-references.ts";

// This is the existing code-mode transport ceiling, used only to size the eval.
const IPC_FRAME_LIMIT_BYTES = 64 * 1024 * 1024;
const SCAN_ID = "7fc17317-9594-49e0-b06a-d72fd7e14bba";

/** Generate one reducer assignment; no repository scan or external service runs. */
export async function createReducerPagingFixture(root: string) {
  const fixtureRoot = await realpath(root);
  const scanRoot = path.join(fixtureRoot, "scan");
  const deepRoot = path.join(scanRoot, "artifacts", "deep_discovery");
  const workerRoot = path.join(deepRoot, "workers", "discovery-0001", "output");
  const previousRoot = path.join(deepRoot, "dedup", "dedup-0001", "output");
  const outputRoot = path.join(deepRoot, "dedup", "dedup-0002", "output");
  await Promise.all(
    [workerRoot, previousRoot, outputRoot].map((directory) =>
      mkdir(directory, { recursive: true }),
    ),
  );

  const freshProration = finding("fractional-proration", {
    title: "Proration truncates the ratio before multiplying the amount",
    summary: paddedSummary(IPC_FRAME_LIMIT_BYTES / 2),
    expected: "Prorating 500 cents at two fifths returns 200 cents.",
    actual: "Integer division returns 0 cents before the amount is applied.",
    impact: "Invoice adjustments can undercharge a customer.",
  });
  const freshSorting = finding("batch-sort-order", {
    title: "The import comparator reorders equal-value rows inconsistently",
    summary:
      "An independently reachable batch import treats equal-value rows as unequal because the comparator ignores the stable secondary key.",
    expected: "Rows with equal values retain their input order.",
    actual: "Equal-value rows can swap order between runs.",
    impact: "Imported records can be associated with the wrong adjacent item.",
  });
  const previousOriginal = finding("pagination-total", {
    title: "Pagination reports the page size instead of the total result count",
    summary:
      "The count field is calculated from the current page after slicing rather than from the full filtered result set.",
    expected: "The response count matches the full filtered result set.",
    actual: "The response count is limited to the current page.",
    impact: "Callers stop pagination before they receive all matching records.",
  });
  const synthesizedHistory = {
    ...previousOriginal,
    summary:
      "Earlier synthesis also established that the export endpoint reuses the same count helper. One correction fixes both response paths.",
  };
  const previousSourceId = "previous-worker:0";
  const previousCanonical = {
    ...previousOriginal,
    summary:
      "The page response and export response share a count helper that uses the sliced result. One correction fixes both paths.",
    provenance: {
      ...previousOriginal.provenance,
      sourceFindingIds: [previousSourceId],
      sourceFindings: [{ id: previousSourceId, finding: previousOriginal }],
      previousFindings: [synthesizedHistory],
    },
  };
  const workerId = "current-worker";
  const currentFindings = [freshProration, freshSorting];
  const expectedSources = new Map<string, ReturnType<typeof finding>>([
    ...currentFindings.map(
      (value, index) => [`${workerId}:${index}`, value] as const,
    ),
    [previousSourceId, previousOriginal],
  ]);
  const sourceSha256ById = Object.fromEntries(
    [...expectedSources].map(([id, value]) => [id, canonicalSha256(value)]),
  );
  const result = {
    scanId: SCAN_ID,
    findings: currentFindings,
    scope: {
      summary: "Three independent synthetic functional behavior issues.",
    },
  };
  const previous = {
    scanId: SCAN_ID,
    reviewType: "functional_bug",
    findings: [previousCanonical],
  };
  const workerPath = path.join(workerRoot, "result.json");
  const previousPath = path.join(previousRoot, "result.json");
  await writeJson(workerPath, {
    ...result,
    reviewType: "functional_bug",
    coverage: {
      completeness: "complete",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
  });
  await writeJson(previousPath, previous);

  const logicalInputs = {
    discoveries: [
      {
        workerId,
        result: {
          ...result,
          findings: currentFindings.map(sourceReferences({ id: workerId })),
        },
      },
    ],
    previous,
  };
  const { bytes, stringEscapes } = jsonMetrics(logicalInputs);
  // The old response included JSON.stringify(inputs) as text and inputs again
  // as structuredContent. Count its exact bytes without allocating both copies.
  const envelopeBytes =
    Buffer.byteLength(
      JSON.stringify({
        content: [{ type: "text", text: "" }],
        structuredContent: null,
      }),
    ) - Buffer.byteLength("null");
  const legacyResponseBytes = envelopeBytes + bytes * 2 + stringEscapes;
  assert.ok(legacyResponseBytes > IPC_FRAME_LIMIT_BYTES);
  return {
    context: {
      root: outputRoot,
      repoRoot: fixtureRoot,
      scanId: SCAN_ID,
      layout: "reducer" as const,
      deepReducer: {
        scanRoot,
        claimedWorkers: [{ id: workerId, resultPath: workerPath }],
        previousReducerResultPath: previousPath,
      },
    },
    resultPath: path.join(outputRoot, "result.json"),
    expected: {
      sourceSha256ById,
      sourceIdentityById: Object.fromEntries(
        [...expectedSources].map(([id, value]) => [id, value.identity]),
      ),
      previousSourceId,
      historySha256: canonicalSha256(synthesizedHistory),
    },
    measurements: {
      ipcFrameLimitBytes: IPC_FRAME_LIMIT_BYTES,
      largeSemanticFieldBytes: Buffer.byteLength(freshProration.summary),
      logicalInputBytes: bytes,
      legacyResponseBytes,
    },
  };
}

/** Fail on lost, duplicated, substituted, or de-identified reducer evidence. */
export async function gradeReducerPagingResult(
  fixture: Awaited<ReturnType<typeof createReducerPagingFixture>>,
) {
  const result = await readJson(fixture.resultPath);
  assert.equal(result.scanId, fixture.context.scanId);
  assert.notEqual(result.complete, false);
  assert.ok(Array.isArray(result.findings));
  const expectedIds = Object.keys(fixture.expected.sourceSha256ById).sort();
  assert.equal(
    result.findings.length,
    expectedIds.length,
    "the three independent issues must remain separate output findings",
  );
  const refs = [];
  for (const finding of result.findings) {
    const provenance = finding.provenance;
    assert.ok(Array.isArray(provenance?.sourceFindingIds));
    assert.equal(
      provenance.sourceFindingIds.length,
      1,
      "each independent output finding must reference only its own source",
    );
    const [sourceId] = provenance.sourceFindingIds;
    assert.deepEqual(
      finding.identity,
      fixture.expected.sourceIdentityById[sourceId],
      `output identity must match its source ${sourceId}`,
    );
    assert.ok(Array.isArray(provenance?.sourceFindings));
    refs.push(...provenance.sourceFindingIds);
    assert.deepEqual(
      provenance.sourceFindings
        .map((source: { id: string }) => source.id)
        .sort(),
      [...provenance.sourceFindingIds].sort(),
      "each output finding must retain exactly its attributed originals",
    );
    const [source] = provenance.sourceFindings;
    assert.equal(
      canonicalSha256(source.finding),
      fixture.expected.sourceSha256ById[source.id],
      `original evidence changed for ${source.id}`,
    );
  }
  assert.deepEqual(
    refs.sort(),
    expectedIds,
    "each assigned reference must occur exactly once",
  );
  const previous = result.findings.find(
    (finding: { provenance: { sourceFindingIds: string[] } }) =>
      finding.provenance.sourceFindingIds.includes(
        fixture.expected.previousSourceId,
      ),
  );
  assert.ok(
    previous.provenance.previousFindings?.some(
      (history: unknown) =>
        canonicalSha256(history) === fixture.expected.historySha256,
    ),
    "the prior synthesized history must survive losslessly",
  );
  return {
    findingCount: result.findings.length,
    accountedSourceCount: refs.length,
    preservedOriginalCount: refs.length,
    previousIdentityPreserved: true,
    synthesizedHistoryPreserved: true,
  };
}

function finding(
  id: "fractional-proration" | "batch-sort-order" | "pagination-total",
  extra: Record<"title" | "summary" | "expected" | "actual" | "impact", string>,
) {
  return {
    ruleId: "synthetic." + id,
    identity: { anchor: id },
    title: extra.title,
    summary: extra.summary,
    priority: "P2",
    category: "algorithm",
    confidence: { level: "high", rationale: "Synthetic validated fixture." },
    locations: [{ path: `src/${id}.mjs`, startLine: 1, endLine: 2 }],
    expected: extra.expected,
    actual: extra.actual,
    impact: extra.impact,
    validation: {
      status: "validated",
      method: "Focused deterministic fixture reproduction.",
      evidence: ["The synthetic input produced the incorrect result."],
      counterEvidence: ["A corrected sibling implementation returns the contract value."],
    },
    suggestedCorrection: "Correct the calculation while preserving the documented contract.",
    tests: ["Add a regression test for the reproduced input."],
    provenance: { source: "local_plugin" },
  };
}

function paddedSummary(bytes: number) {
  const beginning =
    "BEGIN BUG: Integer division truncates a fractional ratio before applying it to the amount. The following repeated text is synthetic padding to exercise byte-aware paging, not additional evidence.\n";
  const ending =
    "\nEND BUG: Multiply before dividing and define the rounding rule. Sorting stability and pagination totals are distinct issues requiring independent corrections.";
  const available =
    bytes - Buffer.byteLength(beginning) - Buffer.byteLength(ending);
  const unit = '"\\\n😀';
  const repeats = Math.floor(available / Buffer.byteLength(unit));
  return (
    beginning +
    unit.repeat(repeats) +
    "x".repeat(available % Buffer.byteLength(unit)) +
    ending
  );
}

function canonicalSha256(value: unknown) {
  const hash = createHash("sha256");
  visitJson(value, (chunk) => hash.update(chunk), true);
  return hash.digest("hex");
}

function jsonMetrics(value: unknown) {
  let bytes = 0;
  let stringEscapes = 0;
  visitJson(value, (chunk) => {
    bytes += Buffer.byteLength(chunk);
    for (let index = 0; index < chunk.length; index += 1) {
      if (chunk[index] === '"' || chunk[index] === "\\") stringEscapes += 1;
    }
  });
  return { bytes, stringEscapes };
}

// Hash and measure one scalar at a time instead of retaining another complete
// copy of the oversized document. Fixture values contain only JSON types.
function visitJson(
  value: unknown,
  emit: (chunk: string) => void,
  sorted = false,
) {
  if (Array.isArray(value)) {
    emit("[");
    value.forEach((item, index) => {
      if (index > 0) emit(",");
      visitJson(item, emit, sorted);
    });
    emit("]");
  } else if (value !== null && typeof value === "object") {
    emit("{");
    const keys = Object.keys(value);
    if (sorted) keys.sort();
    keys.forEach((key, index) => {
      if (index > 0) emit(",");
      emit(JSON.stringify(key));
      emit(":");
      visitJson((value as Record<string, unknown>)[key], emit, sorted);
    });
    emit("}");
  } else {
    emit(JSON.stringify(value)!);
  }
}
