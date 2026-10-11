export const scanId = "7fc17317-9594-49e0-b06a-d72fd7e14bba";

export function workerDraft<Finding extends Record<string, unknown>>(
  findings: Finding[],
  extra = {},
) {
  return {
    scanId,
    reviewType: "functional_bug",
    findings,
    coverage: {
      completeness: "complete",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
    ...extra,
  };
}

export function finding(id: string, repositoryPath: string) {
  return {
    ruleId: "incorrect-result." + id,
    identity: { anchor: id },
    title: "Incorrect result " + id,
    summary: "The implementation returns a value that differs from its contract.",
    priority: "P2",
    category: "algorithm",
    confidence: {
      level: "high",
      rationale: "A focused reproduction returns the wrong result.",
    },
    locations: [{ path: repositoryPath, startLine: 1, endLine: 2 }],
    expected: "The function returns the documented result for the input.",
    actual: "The function returns an incorrect value.",
    impact: "The caller receives incorrect data.",
    validation: {
      status: "validated",
      method: "Focused deterministic reproduction.",
      evidence: ["The fixture input produced an incorrect result."],
      reproduction: ["Call the function with the fixture input."],
      counterEvidence: ["The safe implementation returns the expected result."],
    },
    suggestedCorrection: "Correct the operation at the source location.",
    tests: ["Add a regression test for this input."],
    provenance: { source: "local_plugin" },
  };
}
