import discoveryTemplate from "../../templates/deep-scan/discovery.md";
import dedupTemplate from "../../templates/deep-scan/dedup.md";

export interface DiscoveryPromptInput {
  scanId: string;
  pluginRoot: string;
  targetPath: string;
  scope: string;
  userContext?: string;
  workerLabel: string;
  subagents: number;
}

// Every worker starts in a fresh Codex thread. A single typed JSON object
// makes its complete input explicit without duplicating raw and escaped values.

export function renderDiscoveryPrompt(
  input: DiscoveryPromptInput,
): string {
  const context = formattedJson({
    scanId: input.scanId,
    pluginRoot: input.pluginRoot,
    targetPath: input.targetPath,
    scope: input.scope,
    userContext: input.userContext ?? null,
    workerLabel: input.workerLabel,
    subagents: input.subagents,
  });
  const prompt = discoveryTemplate.replaceAll(
    "{{DISCOVERY_CONTEXT_JSON}}",
    () => context,
  );
  return prompt;
}

export function renderDedupPrompt(
  reducerLabel: string,
  claimedWorkerIds: string[],
): string {
  const context = formattedJson({
    reducerLabel,
    claimedWorkerIds,
  });
  return dedupTemplate.replaceAll("{{DEDUP_CONTEXT_JSON}}", () => context);
}

function formattedJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}
