import { realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { DeepScanNonRetryableError } from "./errors.js";

export interface DeepScanSourceReadRootsOptions {
  repoRoot: string;
  sourceReadPaths: readonly string[];
}

/** Resolve persisted scan paths into canonical read-only worker roots. */
export async function resolveDeepScanSourceReadRoots(
  options: DeepScanSourceReadRootsOptions,
): Promise<string[]> {
  if (!isAbsolute(options.repoRoot)) {
    throw sourceScopeError("the target repository path is not absolute");
  }
  if (
    !Array.isArray(options.sourceReadPaths) ||
    options.sourceReadPaths.length === 0
  ) {
    throw sourceScopeError("the workbench returned no selected target paths");
  }

  const repoRoot = await realpath(options.repoRoot);
  const roots = new Set<string>();
  for (const sourcePath of options.sourceReadPaths) {
    if (typeof sourcePath !== "string" || sourcePath.length === 0) {
      throw sourceScopeError(
        "the workbench returned an invalid selected target path",
      );
    }
    const candidate = isAbsolute(sourcePath)
      ? resolve(sourcePath)
      : sourcePath === "."
        ? repoRoot
        : resolve(repoRoot, ...validateRelativeTargetPath(sourcePath));
    const canonical = await realpath(candidate).catch(() => {
      throw sourceScopeError("a selected target path is no longer available");
    });
    if (!pathIsWithin(repoRoot, canonical)) {
      throw sourceScopeError(
        "a selected target path resolves outside the repository",
      );
    }
    roots.add(canonical);
  }
  return [...roots];
}

function validateRelativeTargetPath(path: string): string[] {
  const parts = path.split("/");
  if (
    (sep === "\\" && path.includes("\\")) ||
    parts.some((part) => part === "" || part === "." || part === "..")
  ) {
    throw sourceScopeError(
      "a selected target path is not normalized and repository-relative",
    );
  }
  return parts;
}

function pathIsWithin(root: string, candidate: string): boolean {
  const relativePath = relative(root, candidate);
  return (
    relativePath === "" ||
    (relativePath !== ".." &&
      !relativePath.startsWith(`..${sep}`) &&
      !isAbsolute(relativePath))
  );
}

function sourceScopeError(reason: string): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(
    `Deep Scan cannot safely establish the selected source read scope: ${reason}.`,
  );
}
