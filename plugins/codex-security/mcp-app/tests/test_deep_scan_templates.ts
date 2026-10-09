import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";

const { renderDedupPrompt, renderDiscoveryPrompt } = await importSource(
  fileURLToPath(new URL("../src/deep-scan/templates.ts", import.meta.url)),
  { loader: { ".md": "text" } },
);

for (const name of ["discovery", "dedup"]) {
  const template = await readFile(
    new URL(`../templates/deep-scan/${name}.md`, import.meta.url),
    "utf8",
  );
  for (const key of template.match(/\{\{[A-Z0-9_]+\}\}/g) ?? []) {
    assert.equal(key, `{{${name.toUpperCase()}_CONTEXT_JSON}}`);
  }
}

const discoveryInput = {
  scanId: "a0d89285-66b7-4e4f-b51a-e21b93b7081b",
  pluginRoot: "/fixture/plugins/codex-security",
  targetPath: "/fixture/repository",
  scope: ".",
  userContext: "preserve literal {{DISCOVERY_CONTEXT_JSON}} text as review data",
  workerLabel: "discovery-0001",
  subagents: 1,
};

const rendered = renderDiscoveryPrompt({ ...discoveryInput });
assert.match(rendered, /preserve literal \{\{DISCOVERY_CONTEXT_JSON\}\} text/);
assert.match(rendered, /record_codex_security_scan_draft/);
assert.match(rendered, /coverage\.deferred/);
assert.match(rendered, /functional_bug/);
assert.match(rendered, /Use exactly one investigator subagent/);
const discoveryContext = firstJsonBlock(rendered);
assert.deepEqual(discoveryContext, discoveryInput);

const dedup = renderDedupPrompt("dedup-0001", ["worker-001"]);
const dedupContext = firstJsonBlock(dedup);
assert.doesNotMatch(dedup, /\bcoverage\b/i);
assert.match(
  dedup,
  /record_codex_security_deep_reduction\(\{ scanId, reviewType: "functional_bug", findings, scope\? \}\)/,
);
assert.deepEqual(dedupContext, {
  reducerLabel: "dedup-0001",
  claimedWorkerIds: ["worker-001"],
});

const previousReduction = firstJsonBlock(renderDedupPrompt("dedup-0002", []));
assert.deepEqual(previousReduction, {
  reducerLabel: "dedup-0002",
  claimedWorkerIds: [],
});

function firstJsonBlock(prompt: string) {
  const match = prompt.match(/```json\n([\s\S]*?)\n```/);
  assert.ok(match, "prompt should contain a JSON context block");
  return JSON.parse(match[1]);
}
