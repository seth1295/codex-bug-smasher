import { readJson } from "./support/json.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { finding } from "./scan-draft-fixture.ts";
import { draftApi, draftFixture } from "./scan-draft-recovery-fixture.ts";
import assert from "node:assert/strict";
import { rm } from "node:fs/promises";
import path from "node:path";

const root = await temporaryDirectory("functional-bug-scan-draft-");
try {
  const { context, draft } = draftFixture(root, "deep");
  const bug = finding("proration-order", "src/proration.mjs");
  const result = await draftApi.recordCodexSecurityScanDraft(context, {
    ...draft(
      {
        completeness: "complete",
        surfaces: [
          { label: "Integer proration", disposition: "reported" },
          { label: "Safe proration", disposition: "no_issue_found" },
        ],
        explicitExclusions: [],
        deferred: [],
      },
      true,
    ),
    findings: [bug],
    reviewType: "functional_bug",
  });

  assert.equal(result.findingCount, 1);
  assert.equal(result.surfaceCount, 2);
  const savedFindings = await readJson(root, "findings.json");
  const savedCoverage = await readJson(root, "coverage.json");
  const savedManifest = await readJson(root, "scan-manifest.json");
  assert.equal(savedFindings.documentType, "functional-bug-scan.findings");
  assert.equal(savedFindings.findings[0].priority, "P2");
  assert.deepEqual(savedFindings.hypotheses, []);
  assert.equal(savedCoverage.documentType, "functional-bug-scan.coverage");
  assert.equal(savedCoverage.reviewedAreas.length, 2);
  assert.equal(savedManifest.scan.reviewType, "functional_bug");
  assert.equal("threatModel" in savedManifest.scan, false);
  assert.equal("severity" in savedFindings.findings[0], false);
  assert.equal("taxonomy" in savedFindings.findings[0], false);
  assert.equal("attackPath" in savedFindings.findings[0], false);
} finally {
  await rm(root, { recursive: true, force: true });
}

console.log("functional bug scan draft artifacts were saved");
