# Functional bug scan

Review the selected repository or path for ordinary software correctness defects. Do not perform a security audit. Do not use attacker, exploit, trust-boundary, CWE, vulnerability, policy, or security-severity framing.

## Review method

1. Map program behavior from entry points through state changes, algorithms, persistence, error handling, API boundaries, and tests. Use project documentation and tests to establish intended behavior.
2. Look for incorrect results, lost or duplicated data, invalid state transitions, boundary and numerical errors, incorrect error handling, contract mismatches, race conditions, and behavior that diverges across supported inputs.
3. For each candidate, trace a concrete input or reachable state through the implementation to the incorrect result. Compare expected and actual behavior and cite the smallest useful source locations.
4. Try to disprove the candidate. Check documented behavior, callers, invariants, tests, and counterexamples. Run focused existing tests or a minimal reproduction when practical and safe. Do not modify the target repository.
5. Put only confirmed, code-grounded bugs in `findings`. Confirm with a passing reproduction/test that demonstrates the wrong behavior, or a complete source-backed proof where execution is unavailable. Put unresolved hypotheses in `coverage.deferred` as `{ "candidate": { ... }, "reason": "..." }`, including evidence and the unresolved proof gap; never present them as confirmed bugs.
6. Record meaningful source coverage, including inspected areas, tests run or unavailable, explicit exclusions, and remaining work. A clean result is not a claim that every possible input is correct.

## Finding contract

Each confirmed finding includes a concise title and behavior-focused summary; `priority` P0, P1, P2, or P3; a plain correctness `category`; confidence with rationale; repository-relative source locations; `expected` and `actual` behavior; `validation.status: "validated"` with method, direct evidence, reproduction steps where feasible, and counterevidence; reachable conditions; practical impact; and a suggested correction with regression tests where useful. Never edit files or apply fixes.

Use P0 for catastrophic or widespread breakage such as unrecoverable data corruption or a core service outage; P1 for serious failure of a core workflow with broad impact; P2 for a concrete, bounded user-visible defect with a workaround or narrower reach; and P3 for low-impact or uncommon edge behavior. Priority describes impact, not confidence. Confidence describes how well the evidence proves the defect. Do not invent a bug to fill a quota. Keep independently reachable root causes separate, even when they share a module. Deduplicate only when one correction closes every merged behavior defect.

## Outputs

Use the durable deep-scan worker and reducer workflow. Save partial checkpoints as review progresses. Retain unresolved candidates separately from confirmed findings. Preserve all source references through reduction. The coordinator writes canonical JSON and Markdown reports.
