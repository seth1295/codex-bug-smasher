import { isDeepStrictEqual } from "node:util";
import {
  parsePersistedScanDraft,
  parseScanDraft,
  preserveFindingDetails,
  saveScanDraftCheckpoint,
  scanFindingIdentity,
  type ScanDraftInput,
} from "../artifact-scan-draft.js";
import {
  readJsonObject,
  requireRegularFile,
  writeJsonAtomic,
} from "./artifacts.js";
import type { DeepScanArtifacts } from "./artifacts.js";

export type DeepReductionInput = Omit<ScanDraftInput, "coverage"> & {
  scanCoverage?: Record<string, unknown>;
};

export interface DeepReductionSources {
  discoveries: { workerId: string; result: DeepReductionInput }[];
  previous: DeepReductionInput | null;
}

export interface ReducerArtifactValidation {
  newFindings: number;
  result: DeepReductionInput;
}

/**
 * Check reducer findings with the functional bug scan validator.
 * It requires coverage, so add an empty value and remove it after validation.
 */
export function parseDeepReduction(
  input: Record<string, unknown>,
  persisted = false,
): DeepReductionInput {
  if (input.reviewType !== "functional_bug") {
    throw new Error(
      "Deep reduction must identify its functional bug review type.",
    );
  }
  const { scanCoverage, ...semanticInput } = input;
  if (
    scanCoverage !== undefined &&
    (typeof scanCoverage !== "object" ||
      scanCoverage === null ||
      Array.isArray(scanCoverage))
  ) {
    throw new Error("Deep reduction scanCoverage must be an object.");
  }
  const standard = {
    ...semanticInput,
    coverage: {
      completeness: "complete",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
  };
  const { coverage: _coverage, ...parsed } = persisted
    ? parsePersistedScanDraft(standard)
    : parseScanDraft(standard as unknown as ScanDraftInput);
  return {
    ...parsed,
    ...(scanCoverage === undefined
      ? {}
      : { scanCoverage: scanCoverage as Record<string, unknown> }),
  };
}

/** Admit exactly one complete functional bug discovery result. */
export async function validateDiscoveryArtifacts(
  artifacts: DeepScanArtifacts,
  resultPath: string,
  expectedScanId: string,
): Promise<ScanDraftInput> {
  await requireRegularFile(resultPath, artifacts.workersRoot);
  const result = parseStoredScanDraft(
    await readJsonObject(resultPath),
    "Deep Bug Scan worker",
    expectedScanId,
    parsePersistedScanDraft,
  );
  if (result.complete === false)
    throw new Error(
      "Deep Bug Scan worker wrote only a checkpoint; its review is not complete.",
    );
  if (result.reviewType !== "functional_bug")
    throw new Error(
      "Deep Scan worker did not return a functional bug review result.",
    );
  return result;
}

/** Validate the complete aggregate and derive convergence from stable finding identities. */
export async function validateReducerArtifacts(
  input: {
    artifacts: DeepScanArtifacts;
    artifactDir: string;
    resultPath: string;
    reducerId: string;
    previousReducerResultPath?: string;
    sources?: DeepReductionSources;
  },
  expectedScanId?: string,
): Promise<ReducerArtifactValidation> {
  const {
    artifacts,
    artifactDir,
    resultPath,
    reducerId,
    previousReducerResultPath,
  } = input;

  await requireRegularFile(resultPath, artifactDir);
  let result = parseStoredScanDraft(
    await readJsonObject(resultPath),
    reducerId,
    expectedScanId,
    (value) => parseDeepReduction(value, true),
  );
  if (result.complete === false)
    throw new Error(
      "Deep reduction wrote only a checkpoint; its audit is not complete.",
    );

  let previous = input.sources?.previous ?? undefined;
  if (!input.sources && previousReducerResultPath) {
    await requireRegularFile(previousReducerResultPath, artifacts.dedupRoot);
    previous = parseStoredScanDraft(
      await readJsonObject(previousReducerResultPath),
      "Previous successful reducer",
      result.scanId,
      (value) => parseDeepReduction(value, true),
    );
  }

  if (input.sources) {
    result = reconcileDeepReduction(
      result,
      input.sources.discoveries,
      input.sources.previous,
    );
    await saveScanDraftCheckpoint(
      { root: artifactDir, repoRoot: artifacts.scanDir, layout: "reducer" },
      result,
    );
    await writeJsonAtomic(resultPath, result);
  } else {
    validateRetainedFindings(result, [], previous);
  }
  const previousFindingIds = new Set(
    (previous?.findings ?? []).map(scanFindingIdentity),
  );
  return {
    result,
    newFindings: result.findings.filter(
      (finding) => !previousFindingIds.has(scanFindingIdentity(finding)),
    ).length,
  };
}

/** Reconcile a reducer output against the immutable inputs captured before dispatch. */
export function reconcileDeepReduction(
  input: DeepReductionInput,
  discoveries: DeepReductionSources["discoveries"],
  previous: DeepReductionInput | null,
): DeepReductionInput {
  const result = structuredClone(input);
  for (const source of [
    ...discoveries.map((discovery) => discovery.result),
    ...(previous ? [previous] : []),
  ]) {
    if (source.scanId !== result.scanId)
      throw new Error("Deep reduction source belongs to a different scan.");
    if (source.complete === false)
      throw new Error(
        "Deep reduction source is only a checkpoint, not a complete result.",
      );
  }
  validateRetainedFindings(
    result,
    discoveries.map((discovery) => discovery.result),
    previous ?? undefined,
  );
  retainSourceFindings(result, { discoveries, previous });
  result.scanCoverage = mergeDeepScanCoverage(discoveries, previous);
  const unmatched = new Set(result.findings);
  for (const finding of previous?.findings ?? []) {
    const previousRefs = findingSourceIds(finding);
    const retained =
      (previousRefs.length > 0
        ? result.findings.find((current) =>
            findingSourceIds(current).some((ref) => previousRefs.includes(ref)),
          )
        : undefined) ??
      [...unmatched].find(
        (current) =>
          scanFindingIdentity(current) === scanFindingIdentity(finding),
      );
    if (retained) {
      preserveFindingDetails(retained, finding);
      unmatched.delete(retained);
    }
  }
  retainSourceFindings(result, { discoveries, previous });
  for (const [field, label] of [["scope", "scopes"]] as const) {
    if (result[field] !== undefined) continue;
    const sourceValues = [
      ...discoveries.map((discovery) => discovery.result[field]),
      previous?.[field],
    ].filter((value): value is Record<string, unknown> => value !== undefined);
    const distinctValues = sourceValues.filter(
      (value, index) =>
        sourceValues.findIndex((candidate) =>
          isDeepStrictEqual(candidate, value),
        ) === index,
    );
    if (distinctValues.length > 1) {
      throw new Error(
        `Deep reduction has ambiguous ${label}; provide the reconciled ${field} explicitly.`,
      );
    }
    if (distinctValues[0] !== undefined) {
      result[field] = structuredClone(distinctValues[0]);
    }
  }
  return result;
}

function mergeDeepScanCoverage(
  discoveries: DeepReductionSources["discoveries"],
  previous: DeepReductionInput | null,
): Record<string, unknown> {
  const coverages = [
    ...discoveries.map(({ result }) => result.scanCoverage),
    previous?.scanCoverage,
  ].filter(
    (coverage): coverage is Record<string, unknown> =>
      coverage !== undefined && coverage !== null,
  );
  const surfaces: Record<string, unknown>[] = [];
  const exclusions = new Map<string, Record<string, unknown>>();
  const questions = new Map<string, unknown>();
  const deferred = new Map<
    string,
    { value: Record<string, unknown>; sourceWorkerIds: Set<string> }
  >();
  for (const coverage of coverages) {
    for (const surface of Array.isArray(coverage.surfaces) ? coverage.surfaces : []) {
      if (surface && typeof surface === "object" && !Array.isArray(surface)) {
        const value = structuredClone(surface as Record<string, unknown>);
        const sourceWorkerIds = Array.isArray(value.sourceWorkerIds)
          ? value.sourceWorkerIds.filter(
              (workerId): workerId is string => typeof workerId === "string",
            )
          : [];
        delete value.sourceWorkerIds;
        value.sourceWorkerIds = [...new Set(sourceWorkerIds)].sort();
        surfaces.push(value);
      }
    }
    for (const exclusion of Array.isArray(coverage.explicitExclusions)
      ? coverage.explicitExclusions
      : []) {
      if (!exclusion || typeof exclusion !== "object" || Array.isArray(exclusion))
        continue;
      const value = structuredClone(exclusion as Record<string, unknown>);
      exclusions.set(JSON.stringify(value), value);
    }
    for (const question of Array.isArray(coverage.openQuestions)
      ? coverage.openQuestions
      : []) {
      questions.set(JSON.stringify(question), structuredClone(question));
    }
    for (const candidate of Array.isArray(coverage.deferred)
      ? coverage.deferred
      : []) {
      if (!candidate || typeof candidate !== "object" || Array.isArray(candidate))
        continue;
      const value = structuredClone(candidate as Record<string, unknown>);
      const sourceWorkerIds = Array.isArray(value.sourceWorkerIds)
        ? value.sourceWorkerIds.filter(
            (workerId): workerId is string => typeof workerId === "string",
          )
        : [];
      delete value.sourceWorkerIds;
      const key = JSON.stringify(value);
      const existing = deferred.get(key);
      if (existing) {
        for (const workerId of sourceWorkerIds)
          existing.sourceWorkerIds.add(workerId);
      } else {
        deferred.set(key, {
          value,
          sourceWorkerIds: new Set(sourceWorkerIds),
        });
      }
    }
  }
  const deferredRows = [...deferred.values()].map(({ value, sourceWorkerIds }) => ({
    ...value,
    ...(sourceWorkerIds.size
      ? { sourceWorkerIds: [...sourceWorkerIds].sort() }
      : {}),
  }));
  const needsFollowUp = surfaces.some(
    (surface) => surface.disposition === "needs_follow_up",
  );
  const incompleteSource = coverages.some(
    (coverage) => coverage.completeness !== undefined && coverage.completeness !== "complete",
  );
  return {
    completeness:
      incompleteSource || deferredRows.length > 0 || needsFollowUp
        ? "partial"
        : "complete",
    surfaces,
    explicitExclusions: [...exclusions.values()],
    deferred: deferredRows,
    openQuestions: [...questions.values()],
  };
}

function findingSourceIds(finding: Record<string, unknown>): string[] {
  const provenance = finding.provenance as Record<string, unknown>;
  const ids = provenance.sourceFindingIds;
  if (Array.isArray(ids))
    return ids.filter((id): id is string => typeof id === "string");
  const sources = provenance.sourceFindings;
  if (!Array.isArray(sources)) return [];
  return sources.flatMap((source) =>
    typeof source === "object" &&
    source !== null &&
    typeof (source as { id?: unknown }).id === "string"
      ? [(source as { id: string }).id]
      : [],
  );
}

function retainSourceFindings(
  result: DeepReductionInput,
  inputs: DeepReductionSources,
): void {
  type Finding = Record<string, unknown>;
  const sources = new Map<string, Finding>();
  for (const discovery of inputs.discoveries) {
    for (const [index, finding] of discovery.result.findings.entries()) {
      const original = structuredClone(finding);
      delete (original.provenance as Finding).sourceFindingIds;
      sources.set(`${discovery.workerId}:${index}`, original);
    }
  }
  for (const [index, finding] of (inputs.previous?.findings ?? []).entries()) {
    const provenance = finding.provenance as Finding;
    const originals = provenance.sourceFindings as
      Array<{ id: string; finding: Finding }> | undefined;
    if (originals?.length) {
      for (const original of originals)
        sources.set(original.id, original.finding);
    } else {
      sources.set(`previous:${index}`, finding);
    }
  }
  const claimed = new Set<string>();
  for (const finding of result.findings) {
    const provenance = finding.provenance as Finding;
    let refs = provenance.sourceFindingIds as string[] | undefined;
    if (refs === undefined) {
      const matches = [...sources].filter(
        ([, source]) =>
          scanFindingIdentity(source) === scanFindingIdentity(finding),
      );
      if (
        new Set(matches.map(([, source]) => JSON.stringify(source))).size > 1
      ) {
        throw new Error(
          "Deep reduction has ambiguous source findings; preserve each sourceFindingIds reference explicitly.",
        );
      }
      refs = matches.map(([id]) => id);
    }
    if (refs.length === 0)
      throw new Error(
        "Deep reduction contains a finding with no assigned source finding.",
      );
    for (const id of refs) {
      if (!sources.has(id))
        throw new Error(
          `Deep reduction references unknown source finding ${id}.`,
        );
      if (claimed.has(id))
        throw new Error(
          `Deep reduction attributes source finding ${id} more than once.`,
        );
      claimed.add(id);
    }
    provenance.sourceFindingIds = refs;
    provenance.sourceFindings = refs.map((id) => ({
      id,
      finding: structuredClone(sources.get(id)!),
    }));
  }
  const missing = [...sources.keys()].filter((id) => !claimed.has(id));
  if (missing.length)
    throw new Error(
      `Deep reduction left unaccounted source findings: ${missing.join(", ")}.`,
    );
}

/** Preserve previously accepted identities and never discard every reported finding. */
export function validateRetainedFindings(
  result: DeepReductionInput,
  sources: DeepReductionInput[],
  previous?: DeepReductionInput,
): void {
  if (
    result.findings.length === 0 &&
    (sources.some((source) => source.findings.length > 0) ||
      (previous?.findings.length ?? 0) > 0)
  ) {
    throw new Error(
      "Deep reduction discarded every accepted bug finding.",
    );
  }

  const currentFindingIds = new Set(result.findings.map(scanFindingIdentity));
  for (const finding of previous?.findings ?? []) {
    if (currentFindingIds.has(scanFindingIdentity(finding))) continue;
    throw Object.assign(
      new Error(
        "Deep reduction discarded or changed a previously accepted finding identity.",
      ),
      {
        code: "merge_traceability_unstable_candidate_id",
      },
    );
  }
}

export function parseStoredScanDraft<Result extends DeepReductionInput>(
  value: Record<string, unknown>,
  label: string,
  expectedScanId: string | undefined,
  parse: (input: Record<string, unknown>) => Result,
  invalidResultMessage = " returned an invalid bug-scan result: ",
  differentScanMessage = " returned a result for a different scan.",
): Result {
  let parsed: Result;
  try {
    parsed = parse(value);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(label + invalidResultMessage + detail, {
      cause: error,
    });
  }
  if (expectedScanId !== undefined && parsed.scanId !== expectedScanId) {
    throw new Error(label + differentScanMessage);
  }
  return parsed;
}
