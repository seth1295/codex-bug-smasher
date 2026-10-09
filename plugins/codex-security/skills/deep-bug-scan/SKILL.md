---
name: deep-bug-scan
description: Use for a thorough, resumable, multi-worker scan of a repository or selected paths for functional software correctness bugs. Produces persisted Markdown and JSON reports without modifying source files.
---

# Deep Bug Scan

Run a correctness scan with the durable deep-scan coordinator. The coordinator owns the configured independent discovery workers, each investigator subagent allowance, checkpoints, resume, source coverage, validation, counterevidence, deduplication, aggregation, and saved reports. The default is two independent discovery workers and one investigator subagent per worker. Configuration may change those values.

For an SDK or CLI invocation, the scan is already registered. Call `start_codex_functional_bug_scan` with its supplied `scanId`. Preserve the requested repository or selected-path scope. Do not edit the scanned repository.

Each discovery worker reads `../../references/core-bug-scan.md`, completes an independent review, and saves checkpoints. The reducer combines complete worker results, preserves source references, and deduplicates only defects with the same underlying incorrect behavior where one correction fixes every instance.

Do not create additional discovery pools or replace the coordinator with a one-pass review. Do not use security or vulnerability criteria, CWE, attack paths, threat models, exploit requirements, or security severity. Keep unreproduced hypotheses outside validated findings with their evidence and proof gap. Do not apply fixes.

When the coordinator returns the authoritative scan directory and manifest path, confirm its canonical manifest, findings, and coverage artifacts exist. Then call `complete_codex_security_scan` exactly once for the same scan. Completion seals those artifacts, persists the complete report, and records the finished scan. Do not reconstruct or overwrite coordinator artifacts.

If the durable scan is interrupted, rejoin the same scan so completed workers and checkpoints can resume. Do not start a replacement scan to recover a detached wait. Report the exact stored failure if the coordinator cannot resume or its artifacts fail validation.
