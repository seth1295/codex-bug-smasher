import assert from "node:assert/strict";
import { mkdtemp, mkdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";

const { resolveDeepScanSourceReadRoots } = await importSource(
  fileURLToPath(
    new URL("../src/deep-scan/source-read-roots.ts", import.meta.url),
  ),
);

const temporaryRoot = await mkdtemp(
  join(tmpdir(), "codex-security-read-roots-"),
);
try {
  const repository = join(temporaryRoot, "repository");
  const sourcePath = join(repository, "src", "invoice_math.py");
  const testPath = join(repository, "tests", "test_invoice_math.py");
  const outsidePath = join(temporaryRoot, "outside.py");
  await Promise.all([
    mkdir(join(repository, "src"), { recursive: true }),
    mkdir(join(repository, "tests"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(sourcePath, "def prorate(): return 0\n"),
    writeFile(testPath, "def test_prorate(): pass\n"),
    writeFile(outsidePath, "def outside(): pass\n"),
  ]);

  assert.deepEqual(
    await resolveDeepScanSourceReadRoots({
      repoRoot: repository,
      sourceReadPaths: ["."],
    }),
    [await realpath(repository)],
  );
  assert.deepEqual(
    await resolveDeepScanSourceReadRoots({
      repoRoot: repository,
      sourceReadPaths: [repository],
    }),
    [await realpath(repository)],
  );
  assert.deepEqual(
    await resolveDeepScanSourceReadRoots({
      repoRoot: repository,
      sourceReadPaths: ["src"],
    }),
    [await realpath(join(repository, "src"))],
  );
  assert.deepEqual(
    await resolveDeepScanSourceReadRoots({
      repoRoot: repository,
      sourceReadPaths: ["src/invoice_math.py", "tests/test_invoice_math.py"],
    }),
    [await realpath(sourcePath), await realpath(testPath)],
  );

  const bracketPath = join(repository, "src", "invoice[one].py");
  await writeFile(bracketPath, "def literal_path(): return 0\n");
  assert.deepEqual(
    await resolveDeepScanSourceReadRoots({
      repoRoot: repository,
      sourceReadPaths: ["src/invoice[one].py"],
    }),
    [await realpath(bracketPath)],
  );
  if (process.platform !== "win32") {
    const wildcardPath = join(repository, "src", "invoice*?.py");
    await writeFile(wildcardPath, "def literal_wildcard_path(): return 0\n");
    assert.deepEqual(
      await resolveDeepScanSourceReadRoots({
        repoRoot: repository,
        sourceReadPaths: ["src/invoice*?.py"],
      }),
      [await realpath(wildcardPath)],
    );
  }

  for (const sourceReadPaths of [["../outside.py"], [resolve(outsidePath)]]) {
    await assert.rejects(
      resolveDeepScanSourceReadRoots({ repoRoot: repository, sourceReadPaths }),
    );
  }
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
