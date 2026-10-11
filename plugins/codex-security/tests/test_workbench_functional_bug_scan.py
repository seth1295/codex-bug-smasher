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


def bug_finding(index: int) -> dict[str, object]:
    priorities = ("P0", "P1", "P2", "P3")
    return {
        "ruleId": f"invoice.proration.integer-order.{index:02d}",
        "identity": {"anchor": f"invoice-proration-integer-order-{index:02d}"},
        "title": f"Proration issue {index:02d} truncates the ratio too early",
        "summary": "Integer division runs before the amount is multiplied.",
        "priority": priorities[index % len(priorities)],
        "category": "algorithm",
        "confidence": {
            "level": "high",
            "rationale": "A direct reproduction returns the wrong amount.",
        },
        "locations": [{"path": "invoice.py", "startLine": index + 2}],
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
        "provenance": {
            "source": "local_plugin",
            "sourceFindingIds": [f"worker-a:{index}"],
        },
    }


def write_functional_bug_artifacts(
    scan_dir: Path,
    scan_id: str,
    target_coordinates: dict[str, object],
    findings: list[dict[str, object]],
    deferred: dict[str, object],
) -> None:
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
        json.dumps({"findings": findings, "hypotheses": [deferred]})
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

    findings = [bug_finding(index) for index in range(23)]
    deferred = {
        "id": "possible-overwrite",
        "candidate": {"title": "Possible concurrent overwrite"},
        "reason": "The concurrent call ordering could not be proven.",
    }
    write_functional_bug_artifacts(
        scan_dir, scan_id, target_coordinates, findings, deferred
    )

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == 23
    assert completed["priorityCounts"] == {"P0": 6, "P1": 6, "P2": 6, "P3": 5}
    assert "severityCounts" not in completed
    assert completed["bugs"][0]["priority"] == "P0"
    assert completed["hypotheses"] == [deferred]
    assert completed["remediationAvailable"] is False
    assert completed["reportAvailable"] is True
    saved_findings = json.loads((scan_dir / "findings.json").read_text())
    saved_coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert saved_findings["documentType"] == "functional-bug-scan.findings"
    assert saved_coverage["documentType"] == "functional-bug-scan.coverage"
    assert saved_findings["findings"][0]["priority"] == "P0"
    assert saved_findings["findings"][0]["validation"]["status"] == "validated"
    assert not {"severity", "taxonomy", "attackPath"}.intersection(saved_findings["findings"][0])
    assert len(saved_findings["hypotheses"]) == 1
    expected_ids = {item["occurrenceId"] for item in saved_findings["findings"]}
    assert len(expected_ids) == 23
    history = run_workbench(
        state_dir, "list-scans", "--mode", "deep", "--status", "complete"
    )["scans"]
    assert next(item for item in history if item["scanId"] == scan_id)["findingCount"] == 23
    first_page = run_workbench(
        state_dir, "list-findings", "--scan-id", scan_id
    )["findingsPage"]
    second_page = run_workbench(
        state_dir, "list-findings", "--scan-id", scan_id, "--offset", "20"
    )["findingsPage"]
    assert first_page["total"] == second_page["total"] == 23
    assert first_page["offset"] == 0
    assert first_page["nextOffset"] == 20
    assert second_page["offset"] == 20
    assert second_page["nextOffset"] is None
    assert len(first_page["findings"]) == 20
    assert len(second_page["findings"]) == 3
    page_findings = [*first_page["findings"], *second_page["findings"]]
    assert {item["priority"] for item in page_findings} == {"P0", "P1", "P2", "P3"}
    assert all("severity" not in item for item in page_findings)
    first_page_ids = {item["occurrenceId"] for item in first_page["findings"]}
    second_page_ids = {item["occurrenceId"] for item in second_page["findings"]}
    assert first_page_ids.isdisjoint(second_page_ids)
    assert first_page_ids | second_page_ids == expected_ids
    queried = run_workbench(
        state_dir,
        "list-findings",
        "--scan-id",
        scan_id,
        "--query",
        "Proration issue 07",
    )["findingsPage"]
    assert queried["total"] == 1
    assert queried["findings"][0]["title"].startswith("Proration issue 07")
    assert run_workbench(
        state_dir,
        "list-findings",
        "--scan-id",
        scan_id,
        "--severity",
        "high",
    )["findingsPage"]["total"] == 0
    assert run_workbench(
        state_dir,
        "list-findings",
        "--scan-id",
        scan_id,
        "--status",
        "open",
    )["findingsPage"]["total"] == 23
    assert run_workbench(
        state_dir,
        "list-findings",
        "--scan-id",
        scan_id,
        "--status",
        "closed",
    )["findingsPage"]["total"] == 0
    occurrence_id = saved_findings["findings"][0]["occurrenceId"]
    selected = run_workbench(
        state_dir,
        "get-scan",
        "--scan-id",
        scan_id,
        "--occurrence-id",
        occurrence_id,
    )["scan"]
    assert selected["findingCount"] == 23
    assert selected["findings"] == selected["bugs"]
    assert selected["findings"][0]["occurrenceId"] == occurrence_id
    assert selected["priorityCounts"] == {"P0": 6, "P1": 6, "P2": 6, "P3": 5}
    assert "severityCounts" not in selected
    missing = run_workbench(
        state_dir,
        "get-scan",
        "--scan-id",
        scan_id,
        "--occurrence-id",
        "occurrence-from-another-scan",
        check=False,
    )
    assert missing["returncode"] != 0
    assert "not found in the selected scan" in str(missing["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM finding_occurrences WHERE scan_id = ?", (scan_id,)
        ).fetchone() == (0,)


def test_canceled_functional_bug_scan_keeps_saved_results(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "invoice-fixture"
    target.mkdir()
    (target / "invoice.py").write_text("return numerator // denominator * amount\n")
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
    deferred = {
        "id": "possible-overwrite",
        "candidate": {"title": "Possible concurrent overwrite"},
        "reason": "The concurrent call ordering could not be proven.",
    }
    write_functional_bug_artifacts(
        scan_dir, scan_id, target_coordinates, [bug_finding(1)], deferred
    )

    run_workbench(
        state_dir,
        "cancel-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-functional-bug",
        environment={"CODEX_HOME": str(codex_home)},
    )
    canceled = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert canceled["progress"]["status"] == "canceled"
    assert canceled["findingCount"] == 1
    assert canceled["priorityCounts"] == {"P1": 1}
    assert canceled["hypotheses"] == [deferred]
    assert "severityCounts" not in canceled
    history = run_workbench(
        state_dir, "list-scans", "--mode", "deep", "--status", "canceled"
    )["scans"]
    assert next(item for item in history if item["scanId"] == scan_id)["findingCount"] == 1
    page = run_workbench(state_dir, "list-findings", "--scan-id", scan_id)["findingsPage"]
    assert page["total"] == 1
    assert page["findings"][0]["priority"] == "P1"
    assert page["findings"][0]["occurrenceId"] == canceled["bugs"][0]["occurrenceId"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM finding_occurrences WHERE scan_id = ?", (scan_id,)
        ).fetchone() == (0,)
