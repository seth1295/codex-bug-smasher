from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from workbench_test_support import mark_deep_coordinator_succeeded, run_workbench


def begin_functional_bug_scan(
    state_dir: Path, codex_home: Path, target: Path, scan_root: Path
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "thread-functional-bug",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--scan-root",
        str(scan_root),
        "--available-parallelism",
        "16",
        environment={"CODEX_HOME": str(codex_home)},
    )


def test_functional_bug_scan_is_saved_with_priority_results(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "invoice-fixture"
    target.mkdir()
    (target / "invoice.py").write_text(
        "def prorate(amount, numerator, denominator):\n"
        "    return numerator // denominator * amount\n"
    )
    deep_scan = begin_functional_bug_scan(state_dir, codex_home, target, tmp_path / "scans")[
        "deepScan"
    ]
    scan_id = str(deep_scan["scanId"])
    scan_dir = Path(str(deep_scan["scanDir"]))
    persisted_scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    target_binding = persisted_scan["contract"]["target"]
    target_kind = target_binding["allowedKinds"][0]
    target_coordinates = {
        "kind": target_kind,
        "targetId": target_binding["targetId"],
        "displayName": target_binding["displayName"],
    }
    if "requiredSnapshotDigest" in target_binding:
        target_coordinates["snapshotDigest"] = target_binding["requiredSnapshotDigest"]
    elif target_kind == "git_revision":
        target_coordinates["revision"] = persisted_scan["targetRevision"]
    mark_deep_coordinator_succeeded(state_dir, scan_id, scan_dir)

    finding = {
        "ruleId": "invoice.proration.integer-order",
        "identity": {"anchor": "invoice-proration-integer-order"},
        "title": "Proration truncates the ratio too early",
        "summary": "Integer division runs before the amount is multiplied.",
        "priority": "P1",
        "category": "algorithm",
        "confidence": {
            "level": "high",
            "rationale": "A direct reproduction returns the wrong amount.",
        },
        "locations": [{"path": "invoice.py", "startLine": 2}],
        "expected": "Prorating 500 cents at two fifths returns 200 cents.",
        "actual": "The implementation returns 0 cents.",
        "impact": "A customer invoice can be undercharged.",
        "validation": {
            "status": "validated",
            "method": "A direct execution of the fixture function.",
            "evidence": ["prorate(500, 2, 5) returned 0 instead of 200."],
            "reproduction": ["Call prorate(500, 2, 5)."],
            "counterEvidence": ["A safe sibling implementation returns 200."],
        },
        "suggestedCorrection": "Multiply before dividing using the documented rounding rule.",
        "tests": ["Add a regression test for a fractional ratio."],
        "provenance": {"source": "local_plugin", "sourceFindingIds": ["worker-a:0"]},
    }
    deferred = {
        "id": "possible-overwrite",
        "candidate": {"title": "Possible concurrent overwrite"},
        "reason": "The concurrent call ordering could not be proven.",
    }
    (scan_dir / "scan-manifest.json").write_text(
        json.dumps(
            {
                "scan": {
                    "id": scan_id,
                    "reviewType": "functional_bug",
                    "target": target_coordinates,
                    "scope": {"includePaths": ["."], "excludePaths": []},
                }
            }
        )
    )
    (scan_dir / "findings.json").write_text(
        json.dumps({"findings": [finding], "hypotheses": [deferred]})
    )
    (scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                "documentType": "functional-bug-scan.coverage",
                "schemaVersion": "1.0",
                "scanId": scan_id,
                "mode": "deep_repository",
                "completeness": "partial",
                "inventoryStrategy": "repository",
                "includePaths": ["."],
                "excludePaths": [],
                "reviewedAreas": [
                    {"label": "Invoice arithmetic", "disposition": "reviewed"},
                    {"label": "Safe arithmetic", "disposition": "reviewed"},
                ],
                "explicitExclusions": [],
                "deferred": [deferred],
            }
        )
    )

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == 1
    assert completed["priorityCounts"] == {"P1": 1}
    assert "severityCounts" not in completed
    assert completed["bugs"][0]["priority"] == "P1"
    assert completed["remediationAvailable"] is False
    assert completed["reportAvailable"] is True
    saved_findings = json.loads((scan_dir / "findings.json").read_text())
    saved_coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert saved_findings["documentType"] == "functional-bug-scan.findings"
    assert saved_coverage["documentType"] == "functional-bug-scan.coverage"
    assert saved_findings["findings"][0]["priority"] == "P1"
    assert saved_findings["findings"][0]["validation"]["status"] == "validated"
    assert not {"severity", "taxonomy", "attackPath"}.intersection(saved_findings["findings"][0])
    assert len(saved_findings["hypotheses"]) == 1
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM finding_occurrences WHERE scan_id = ?", (scan_id,)
        ).fetchone() == (0,)
