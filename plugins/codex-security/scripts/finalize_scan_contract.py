#!/usr/bin/env python3
"""Validate and seal additive Codex Security scan-contract artifacts."""

from __future__ import annotations

import argparse
import copy
import csv
import errno
import hashlib
import importlib.util
import io
import json
import math
import os
import re
import secrets
import stat
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, TextIO
from urllib.parse import quote, urlsplit

SCHEMA_VERSION = "1.0"
PRODUCER_NAME = "codex-security-plugin"
BUG_PRODUCER_NAME = "functional-bug-scan-plugin"
FINGERPRINT_ALGORITHM = "codex-security/v1"
BUG_FINGERPRINT_ALGORITHM = "functional-bug/v1"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
SEVERITIES = {"critical", "high", "medium", "low", "informational"}
CONFIDENCES = {"high", "medium", "low"}
TARGET_KINDS = {"git_revision", "git_worktree", "git_diff", "directory_snapshot"}
TARGET_COORDINATE_FIELDS = {
    "revision",
    "baseRevision",
    "headRevision",
    "snapshotDigest",
}
TARGET_REQUIRED_COORDINATE_FIELDS = {
    "git_revision": {"revision"},
    "git_worktree": {"snapshotDigest"},
    "git_diff": {"snapshotDigest"},
    "directory_snapshot": {"snapshotDigest"},
}
DISPOSITIONS = {"reported", "no_issue_found", "rejected", "not_applicable", "needs_follow_up"}
SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}
SARIF_SECURITY_SCORES = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.0,
    "informational": 0.0,
}
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)
GITHUB_HASH_BLOCK_SIZE = 100
GITHUB_HASH_MOD = 37
GITHUB_HASH_MASK = (1 << 64) - 1
GITHUB_HASH_EOF = 65535
SOURCE_READ_CHUNK_SIZE = 64 * 1024
MAX_JSON_INTEGER = (1 << 53) - 1
EXPORT_PATHS = {
    "csv": "exports/findings.csv",
    "json": "exports/findings.json",
    "sarif": "exports/results.sarif",
}
THREAT_MODEL_EXPORT_PATH = "exports/threatmodel.md"
_LEGACY_THREAT_MODEL_PATHS = (
    "threatmodel.md",
    "THREAT_MODEL.md",
    "artifacts/01_context/threat_model.md",
    "threat_model.md",
)
WINDOWS_UNSAFE_PATH_COMPONENT_RE = re.compile(
    r'[<>:"|?*\x00-\x1f]|[ .]$|^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$',
    re.IGNORECASE,
)


class ContractError(ValueError):
    """Raised when a completed scan does not satisfy the additive contract."""


class RecoverableContractError(ContractError):
    """Raised when report projection can safely be retried before publication."""


def _reject_non_finite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is not supported")


def _loads_json(value: str | bytes) -> Any:
    return json.loads(value, parse_constant=_reject_non_finite_json)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = _loads_json(path.read_text(encoding="utf-8"))
        _require_safe_json_value(payload, str(path))
    except FileNotFoundError as exc:
        raise ContractError(f"missing required contract artifact: {path}") from exc
    except ContractError:
        raise
    except ValueError as exc:
        raise ContractError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ContractError(f"{path}: expected a JSON object")
    return payload


def _generate_report_projection(
    manifest: dict[str, Any],
    findings: dict[str, Any],
    coverage: dict[str, Any],
) -> bytes:
    script = Path(__file__).resolve().parent / "report_projection.py"
    spec = importlib.util.spec_from_file_location("codex_security_report_projection", script)
    if spec is None or spec.loader is None:
        raise ContractError(f"could not load report projection helper: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    attempts = (
        getattr(sys.modules.get("workbench_constants"), "SQLITE_RETRY_ATTEMPTS", 1)
        if coverage.get("mode") == "deep_repository"
        else 1
    )
    for attempt in range(attempts):
        try:
            return module.generate_report_markdown(manifest, findings, coverage)
        except OSError as exc:
            if attempt == attempts - 1:
                raise RecoverableContractError(f"report projection failed: {exc}") from exc
            time.sleep(0.05 * (2**attempt))
        except ValueError as exc:
            raise ContractError(f"report projection failed: {exc}") from exc
    raise AssertionError("Report projection retry loop exhausted unexpectedly.")


def _threat_model_renderer() -> Any:
    script = Path(__file__).resolve().with_name("threat_model_projection.py")
    spec = importlib.util.spec_from_file_location("codex_security_threat_model_projection", script)
    if spec is None or spec.loader is None:
        raise ContractError(f"could not load threat model projection helper: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def threat_model_provenance(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("documentType") == "codex-security.policy-draft":
        scope = manifest.get("scope")
        return {
            "source": "policy",
            "target": manifest.get("repository"),
            "revision": manifest.get("revision"),
            "scanScope": {"includePaths": [scope], "excludePaths": []} if scope else None,
            "status": manifest.get("status", "completed"),
            "provisional": manifest.get("status", "completed") != "completed",
        }
    scan = _require_dict(manifest, "scan", "manifest")
    target = _require_dict(scan, "target", "manifest.scan") if "target" in scan else {}
    status = scan.get("status")
    if status == "completed" and not scan.get("sealedAt"):
        status = "draft"
    return {
        "source": "scan",
        "scanId": scan.get("id"),
        "target": target.get("displayName"),
        "revision": target.get("revision") or target.get("headRevision"),
        "snapshotDigest": target.get("snapshotDigest"),
        "scanScope": scan.get("scope"),
        "status": status,
        "provisional": scan.get("status") != "completed" or not scan.get("sealedAt"),
    }


def _render_threat_model(model: dict[str, Any], provenance: dict[str, Any]) -> bytes:
    try:
        return _threat_model_renderer().render_threat_model(model, provenance)
    except (TypeError, ValueError) as exc:
        raise ContractError(f"threat model projection failed: {exc}") from exc


def _read_saved_threat_model(
    scan_dir: Path, *, validate_seal: bool = True, schema_dir: Path | None = None
) -> tuple[dict[str, Any], bytes] | None:
    """Read canonical content first; old documents are a read-only compatibility path."""
    scan_dir = _require_scan_directory(scan_dir)
    saved_provenance: dict[str, Any] | None = None
    sealed_artifact_paths: set[str] | None = None
    scan_manifest_path = scan_dir / "scan-manifest.json"
    filename = (
        "scan-manifest.json"
        if scan_manifest_path.exists() or scan_manifest_path.is_symlink()
        else "policy-draft.json"
    )
    manifest_path = scan_dir / filename
    if manifest_path.exists() or manifest_path.is_symlink():
        manifest = _read_scan_local_json(scan_dir, filename, filename)
        scan = (
            _require_dict(manifest, "scan", "manifest")
            if filename == "scan-manifest.json"
            else manifest
        )
        if (
            validate_seal
            and filename == "scan-manifest.json"
            and (scan.get("sealedAt") is not None or scan.get("artifacts"))
        ):
            if "threatModel" not in scan:
                _validate_manifest(manifest)
                recorded_paths = {
                    _require_portable_relative_path(artifact["path"], "sealed artifact path")
                    for artifact in scan["artifacts"]
                }
                if recorded_paths.isdisjoint(_LEGACY_THREAT_MODEL_PATHS):
                    validate_against_schema(
                        manifest,
                        (schema_dir or Path(__file__).resolve().parent.parent / "schemas")
                        / "scan-manifest.schema.json",
                    )
                    return None
            manifest, _, _, _ = _read_sealed_scan(scan_dir, schema_dir, "threat model export")
            scan = manifest["scan"]
            sealed_artifact_paths = {
                _require_portable_relative_path(artifact["path"], "sealed artifact path")
                for artifact in scan["artifacts"]
            }
        provenance = threat_model_provenance(manifest)
        saved_provenance = provenance
        if "threatModel" in scan:
            model = _require_dict(
                scan,
                "threatModel",
                "manifest.scan" if filename == "scan-manifest.json" else "policy draft",
            )
            contents = _render_threat_model(model, provenance)
            path = scan_dir / "threatmodel.md"
            current_path = None
            try:
                descriptor = open_scan_local_file_descriptor(
                    scan_dir, "threatmodel.md", "Saved threat model"
                )
                with os.fdopen(descriptor, "rb") as handle:
                    if handle.read() == contents:
                        current_path = str(path)
            except (ContractError, OSError):
                # An unavailable projection does not invalidate the canonical model.
                pass
            return {
                "threatModel": model,
                "provenance": provenance,
                "path": current_path,
            }, contents
    for filename in _LEGACY_THREAT_MODEL_PATHS:
        if sealed_artifact_paths is not None and filename not in sealed_artifact_paths:
            continue
        path = scan_dir / filename
        if not path.exists() and not path.is_symlink():
            continue
        descriptor, filename = _open_scan_local_file_with_path(
            scan_dir,
            filename,
            "Saved threat model",
            resolve_spelling=sealed_artifact_paths is None,
        )
        path = scan_dir / filename
        with os.fdopen(descriptor, "rb") as handle:
            contents = handle.read()
        try:
            body = contents.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ContractError(f"{filename}: expected UTF-8 Markdown") from exc
        if body.strip():
            return {
                "threatModel": {"format": "markdown", "content": body},
                "provenance": saved_provenance
                or {"source": filename, "status": "unknown", "provisional": True},
                "path": str(path),
            }, contents
    return None


def describe_threat_model(scan_dir: Path, schema_dir: Path | None = None) -> dict[str, Any]:
    saved = _read_saved_threat_model(scan_dir, schema_dir=schema_dir)
    if saved is None:
        raise ContractError("No saved threat model is available for this result.")
    return saved[0]


def build_threat_model_export(scan_dir: Path, schema_dir: Path | None = None) -> bytes:
    saved = _read_saved_threat_model(scan_dir, schema_dir=schema_dir)
    if saved is None:
        raise ContractError("No saved threat model is available for this result.")
    return saved[1]


def write_threat_model_projection_if_possible(
    scan_dir: Path, manifest: dict[str, Any] | None = None
) -> str | None:
    """A convenience document failure must not discard saved canonical content."""
    try:
        saved_manifest = manifest
        if saved_manifest is None and (scan_dir / "scan-manifest.json").exists():
            saved_manifest = _read_scan_local_json(
                scan_dir, "scan-manifest.json", "scan-manifest.json"
            )
        if (
            saved_manifest is not None
            and saved_manifest.get("documentType") != "codex-security.policy-draft"
        ):
            scan = _require_dict(saved_manifest, "scan", "manifest")
            artifacts = (
                _require_list(scan, "artifacts", "manifest.scan") if "artifacts" in scan else []
            )
            for index, artifact in enumerate(artifacts):
                if not isinstance(artifact, dict):
                    continue
                context = f"manifest.scan.artifacts[{index}]"
                path = _require_portable_relative_path(
                    _require_str(artifact, "path", context), f"{context}.path"
                )
                if path.lower() == "threatmodel.md":
                    return None
        if manifest is None:
            saved = _read_saved_threat_model(scan_dir, validate_seal=False)
            if saved is None:
                return None
            contents = saved[1]
        else:
            scan = (
                manifest
                if manifest.get("documentType") == "codex-security.policy-draft"
                else _require_dict(manifest, "scan", "manifest")
            )
            model = scan.get("threatModel")
            if not isinstance(model, dict):
                return None
            contents = _render_threat_model(model, threat_model_provenance(manifest))
        write_scan_local_bytes(scan_dir, "threatmodel.md", contents, owner_read_write=True)
        return None
    except (ContractError, OSError) as exc:
        warning = (
            f"Automatic threat model save failed: {exc}. "
            "Saved canonical content can be exported with `codex-security export "
            "<result-dir> --artifact threat-model`."
        )
        print(f"codex-security: warning: {warning}", file=sys.stderr)
        return warning


def _json_bytes(payload: Any) -> bytes:
    try:
        encoded = json.dumps(payload, allow_nan=False, indent=2, sort_keys=True)
    except ValueError as exc:
        raise ContractError(f"cannot encode canonical JSON: {exc}") from exc
    return (encoded + "\n").encode("utf-8")


def _contract_json_bytes(relative_path: str, payload: Any) -> bytes:
    _require_safe_json_value(payload, relative_path)
    return _json_bytes(payload)


def _require_safe_json_value(value: Any, context: str, *, validate_strings: bool = True) -> None:
    def visit(item: Any, location: str) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ContractError(f"{location}: expected string JSON property names")
                if validate_strings:
                    _require_safe_json_string(key, location)
                visit(child, f"{location}.<property>")
        elif isinstance(item, list):
            for index, child in enumerate(item):
                visit(child, f"{location}[{index}]")
        elif isinstance(item, str) and validate_strings:
            _require_safe_json_string(item, location)
        elif isinstance(item, int) and not isinstance(item, bool):
            if abs(item) > MAX_JSON_INTEGER:
                raise ContractError(
                    f"{location}: unsafe integer-valued JSON numbers are not supported"
                )
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ContractError(f"{location}: non-finite JSON numbers are not supported")
            if item.is_integer() and abs(item) > MAX_JSON_INTEGER:
                raise ContractError(
                    f"{location}: unsafe integer-valued JSON numbers are not supported"
                )

    visit(value, context)


def _require_safe_json_string(value: str, context: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(f"{context}: expected well-formed Unicode JSON strings") from exc


def _require_dict(payload: dict[str, Any], key: str, context: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ContractError(f"{context}.{key}: expected an object")
    return value


def _require_list(payload: dict[str, Any], key: str, context: str) -> list[Any]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise ContractError(f"{context}.{key}: expected an array")
    return value


def _require_str(payload: dict[str, Any], key: str, context: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{context}.{key}: expected a non-empty string")
    return value


def _require_safe_relative_path(value: str, context: str, *, allow_dot: bool = False) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(f"{context}: expected a safe repository-relative POSIX path") from exc
    path = PurePosixPath(value)
    normalized = path.as_posix()
    if (
        not value.strip()
        or (normalized == "." and not allow_dot)
        or (len(value) >= 2 and value[0].isalpha() and value[1] == ":")
        or "\\" in value
        or "\0" in value
        or any(ord(character) < 32 for character in value)
        or path.is_absolute()
        or ".." in path.parts
    ):
        raise ContractError(f"{context}: expected a safe repository-relative POSIX path")
    return normalized


def _require_portable_relative_path(value: str, context: str, *, allow_dot: bool = False) -> str:
    normalized = _require_safe_relative_path(value, context, allow_dot=allow_dot)
    if any(_windows_unsafe_path_component(part) for part in value.split("/")):
        raise ContractError(f"{context}: expected a safe scan-relative POSIX path")
    return normalized


def _windows_unsafe_path_component(value: str) -> bool:
    if not value or value == ".":
        return False
    return WINDOWS_UNSAFE_PATH_COMPONENT_RE.search(value) is not None


def _require_scan_directory(scan_dir: Path) -> Path:
    scan_dir = scan_dir.absolute()
    try:
        metadata = scan_dir.lstat()
    except OSError as exc:
        raise ContractError("scan directory: expected an existing non-symlink directory") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ContractError("scan directory: expected an existing non-symlink directory")
    try:
        resolved = scan_dir.resolve(strict=True)
    except OSError as exc:
        raise ContractError("scan directory: expected an existing non-symlink directory") from exc
    if os.path.normcase(resolved) != os.path.normcase(scan_dir):
        raise ContractError("scan directory: expected a canonical non-symlink directory")
    return resolved


def _validate_scan_local_output_path(scan_dir: Path, path: Path, relative_path: str) -> None:
    try:
        resolved_parent = path.parent.resolve(strict=True)
        resolved_parent.relative_to(scan_dir)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ContractError(f"{relative_path}: expected a path inside the scan directory") from exc
    if os.path.normcase(resolved_parent) != os.path.normcase(path.parent) or path.is_symlink():
        raise ContractError(
            f"{relative_path}: expected a non-symlink path inside the scan directory"
        )
    if path.exists() and not path.is_file():
        raise ContractError(f"{relative_path}: expected a regular file")


def _is_windows() -> bool:
    return os.name == "nt"


def _descriptor_relative_writes_available() -> bool:
    # os.replace accepts src_dir_fd/dst_dir_fd wherever descriptor-relative
    # os.rename is supported, but Python lists only os.rename in supports_dir_fd.
    required_operations = (os.mkdir, os.open, os.rename, os.stat, os.unlink)
    return hasattr(os, "O_NOFOLLOW") and all(
        operation in os.supports_dir_fd for operation in required_operations
    )


_WINDOWS_SCAN_LOCAL_FILES: Any | None = None


def _windows_scan_local_files() -> Any:
    """Load the Win32 backend and shared stream comparison lazily."""

    global _WINDOWS_SCAN_LOCAL_FILES
    if _WINDOWS_SCAN_LOCAL_FILES is None:
        script = Path(__file__).resolve().with_name("windows_scan_local_files.py")
        spec = importlib.util.spec_from_file_location("codex_security_windows_scan_files", script)
        if spec is None or spec.loader is None:
            raise ContractError(f"could not load Windows scan-local file helper: {script}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _WINDOWS_SCAN_LOCAL_FILES = module
    return _WINDOWS_SCAN_LOCAL_FILES


def _open_verified_scan_directory(
    scan_dir: Path, expected_root_identity: tuple[int, int] | None = None
) -> int:
    scan_dir = scan_dir.absolute()
    try:
        expected = scan_dir.lstat()
        observed_identity = (expected.st_dev, expected.st_ino)
        if expected_root_identity is not None and observed_identity != expected_root_identity:
            raise ContractError("scan directory: changed after artifact restoration setup")
        canonical = _require_scan_directory(scan_dir)
        descriptor = os.open(
            canonical,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise ContractError("scan directory: expected an existing non-symlink directory") from exc
    opened = os.fstat(descriptor)
    opened_identity = (opened.st_dev, opened.st_ino)
    if opened_identity != observed_identity or (
        expected_root_identity is not None and opened_identity != expected_root_identity
    ):
        os.close(descriptor)
        raise ContractError("scan directory: changed while it was being opened")
    return descriptor


def scan_root_identity(scan_dir: Path) -> tuple[Path, tuple[int, int]]:
    """Return a canonical scan root and its identity from a held handle."""

    scan_dir = _require_scan_directory(scan_dir)
    if not _descriptor_relative_writes_available():
        if not _is_windows():
            raise ContractError("scan-local output requires descriptor-relative file operations")
        return _windows_scan_local_files().scan_root_identity(scan_dir)
    descriptor = _open_verified_scan_directory(scan_dir)
    try:
        metadata = os.fstat(descriptor)
        return scan_dir, (metadata.st_dev, metadata.st_ino)
    finally:
        os.close(descriptor)


def _open_scan_local_directory(root_fd: int, parts: tuple[str, ...], *, create: bool) -> int:
    descriptor = os.dup(root_fd)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            next_descriptor = os.open(
                part,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_scan_local_file_descriptor(scan_dir: Path, relative_path: str, context: str) -> int:
    return _open_scan_local_file_with_path(scan_dir, relative_path, context)[0]


def _open_scan_local_file_with_path(
    scan_dir: Path, relative_path: str, context: str, *, resolve_spelling: bool = False
) -> tuple[int, str]:
    scan_dir = _require_scan_directory(scan_dir)
    relative_path = _require_portable_relative_path(relative_path, context)
    if not (os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW")):
        if not _is_windows():
            raise ContractError("scan-local input requires descriptor-relative file operations")
        try:
            backend = _windows_scan_local_files()
            if resolve_spelling:
                return backend.open_read_fd_with_path(scan_dir, relative_path, context)
            return backend.open_read_fd(scan_dir, relative_path, context), relative_path
        except OSError as exc:
            raise ContractError(str(exc)) from exc
    root_fd: int | None = None
    parent_fd: int | None = None
    descriptor: int | None = None
    try:
        root_fd = _open_verified_scan_directory(scan_dir)
        parts = PurePosixPath(relative_path).parts
        try:
            parent_fd = _open_scan_local_directory(root_fd, parts[:-1], create=False)
            descriptor = os.open(
                parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                try:
                    link_target = Path(os.readlink(parts[-1], dir_fd=parent_fd))
                    if not link_target.is_absolute():
                        link_target = scan_dir.joinpath(*parts[:-1], link_target)
                    link_target.resolve(strict=False).relative_to(scan_dir)
                except (OSError, RuntimeError, ValueError):
                    raise ContractError(
                        f"{context}: expected a file inside the scan directory"
                    ) from exc
                raise ContractError(f"{context}: expected a regular non-symlink file") from exc
            raise ContractError(f"{context}: expected a file inside the scan directory") from exc
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError(f"{context}: expected a regular non-symlink file")
        if resolve_spelling:
            names = os.listdir(parent_fd)
            if parts[-1] not in names:
                for name in names:
                    if name.casefold() != parts[-1].casefold():
                        continue
                    try:
                        entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if os.path.samestat(metadata, entry):
                        relative_path = PurePosixPath(relative_path).with_name(name).as_posix()
                        break
        result = descriptor
        descriptor = None
        return result, relative_path
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_fd is not None:
            os.close(parent_fd)
        if root_fd is not None:
            os.close(root_fd)


def _require_scan_local_file(scan_dir: Path, relative_path: str, context: str) -> None:
    descriptor = open_scan_local_file_descriptor(scan_dir, relative_path, context)
    os.close(descriptor)


def _require_derived_writeup_files(scan_dir: Path, findings: dict[str, Any]) -> None:
    for index, finding in enumerate(findings.get("findings", [])):
        if not isinstance(finding, dict):
            continue
        writeup = finding.get("writeup")
        if not isinstance(writeup, dict):
            continue
        report_path = writeup.get("reportPath")
        if isinstance(report_path, str):
            _require_scan_local_file(
                scan_dir,
                report_path,
                f"findings[{index}].writeup.reportPath",
            )


def _require_hardening_portfolio_file(scan_dir: Path, scan: dict[str, Any]) -> None:
    hardening = scan.get("hardening")
    if not isinstance(hardening, dict):
        return
    portfolio_path = hardening.get("portfolioPath")
    if isinstance(portfolio_path, str):
        _require_scan_local_file(
            scan_dir,
            portfolio_path,
            "manifest.scan.hardening.portfolioPath",
        )


def _read_scan_local_json_with_metadata(
    scan_dir: Path, relative_path: str, context: str
) -> tuple[dict[str, Any], bytes, os.stat_result]:
    descriptor = open_scan_local_file_descriptor(scan_dir, relative_path, context)
    try:
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read()
            metadata = os.fstat(handle.fileno())
        try:
            payload = _loads_json(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ContractError(f"{context}: invalid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise ContractError(f"{context}: expected a JSON object")
        _require_safe_json_value(payload, context, validate_strings=False)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return payload, raw, metadata


def _read_scan_local_json_bytes(
    scan_dir: Path, relative_path: str, context: str
) -> tuple[dict[str, Any], bytes]:
    payload, raw, _ = _read_scan_local_json_with_metadata(scan_dir, relative_path, context)
    return payload, raw


def _read_scan_local_json(scan_dir: Path, relative_path: str, context: str) -> dict[str, Any]:
    payload, _ = _read_scan_local_json_bytes(scan_dir, relative_path, context)
    return payload


def _sha256_scan_local_file(scan_dir: Path, relative_path: str, context: str) -> str:
    descriptor = open_scan_local_file_descriptor(scan_dir, relative_path, context)
    digest = hashlib.sha256()
    try:
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return digest.hexdigest()


def write_scan_local_bytes(
    scan_dir: Path,
    relative_path: str,
    payload: bytes,
    *,
    external_name: bool = False,
    expected_root_identity: tuple[int, int] | None = None,
    owner_read_write: bool = False,
) -> None:
    scan_dir = _require_scan_directory(scan_dir)
    if external_name:
        if relative_path in {"", ".", ".."} or "/" in relative_path or "\0" in relative_path:
            raise ContractError("external output path: expected a safe file name")
    else:
        relative_path = _require_portable_relative_path(relative_path, "scan-local output path")
    path = scan_dir / relative_path
    if not _descriptor_relative_writes_available():
        if not _is_windows():
            raise ContractError("scan-local output requires descriptor-relative file operations")
        try:
            _windows_scan_local_files().atomic_write(
                scan_dir,
                relative_path,
                payload,
                expected_root_identity=expected_root_identity,
            )
        except OSError as exc:
            raise ContractError(f"{relative_path}: {exc}") from exc
        return
    root_fd: int | None = None
    parent_fd: int | None = None
    temp_name: str | None = None
    try:
        root_fd = _open_verified_scan_directory(scan_dir, expected_root_identity)
        parts = PurePosixPath(relative_path).parts
        try:
            parent_fd = _open_scan_local_directory(root_fd, parts[:-1], create=True)
        except OSError as exc:
            raise ContractError(
                f"{relative_path}: expected a path inside the scan directory"
            ) from exc
        # The held descriptor is the authority for the validated parent. A
        # concurrent rename cannot redirect later operations through a
        # replacement path or link.
        try:
            metadata = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(metadata.st_mode):
                raise ContractError(f"{relative_path}: expected a regular non-symlink file")
            try:
                existing_fd = os.open(
                    parts[-1],
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=parent_fd,
                )
            except OSError as exc:
                if exc.errno not in {errno.ENOENT, errno.EACCES, errno.EPERM}:
                    raise
            else:
                try:
                    opened = os.fstat(existing_fd)
                    if not stat.S_ISREG(opened.st_mode):
                        raise ContractError(f"{relative_path}: expected a regular non-symlink file")
                    if (opened.st_dev, opened.st_ino) != (
                        metadata.st_dev,
                        metadata.st_ino,
                    ):
                        raise ContractError(f"{relative_path}: changed while it was being opened")
                    if expected_root_identity is not None and opened.st_size == len(payload):
                        try:
                            with os.fdopen(existing_fd, "rb") as handle:
                                existing_fd = -1
                                if _windows_scan_local_files().stream_matches_payload(
                                    handle, payload
                                ):
                                    return
                        except OSError:
                            pass
                finally:
                    if existing_fd >= 0:
                        os.close(existing_fd)
        temp_name = f".{path.name}.{secrets.token_hex(8)}.tmp"
        temp_fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd)
        with os.fdopen(temp_fd, "wb") as handle:
            if owner_read_write:
                # Generated Markdown must remain editable under a restrictive umask.
                os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, parts[-1], src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temp_name = None
    finally:
        if temp_name is not None and parent_fd is not None:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        if parent_fd is not None:
            os.close(parent_fd)
        if root_fd is not None:
            os.close(root_fd)


def _remove_scan_local_file_if_exists(scan_dir: Path, relative_path: str) -> None:
    scan_dir = _require_scan_directory(scan_dir)
    relative_path = _require_portable_relative_path(relative_path, "scan-local cleanup path")
    if not _descriptor_relative_writes_available():
        if not _is_windows():
            raise ContractError("scan-local cleanup requires descriptor-relative file operations")
        try:
            _windows_scan_local_files().unlink_if_exists(scan_dir, relative_path)
        except OSError as exc:
            raise ContractError(f"{relative_path}: {exc}") from exc
        return
    root_fd: int | None = None
    parent_fd: int | None = None
    try:
        root_fd = _open_verified_scan_directory(scan_dir)
        parts = PurePosixPath(relative_path).parts
        parent_fd = _open_scan_local_directory(root_fd, parts[:-1], create=False)
        try:
            metadata = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
            raise ContractError(f"{relative_path}: expected a regular file or symlink")
        os.unlink(parts[-1], dir_fd=parent_fd)
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        if root_fd is not None:
            os.close(root_fd)


def _write_scan_local_json(scan_dir: Path, relative_path: str, payload: Any) -> None:
    write_scan_local_bytes(scan_dir, relative_path, _contract_json_bytes(relative_path, payload))


def _validate_remote(remote: str, context: str) -> None:
    parsed = urlsplit(remote)
    if "\\" in remote or not parsed.scheme or not parsed.netloc:
        raise ContractError(f"{context}: expected a sanitized canonical absolute URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ContractError(
            f"{context}: remote URL must not contain credentials, query, or fragment"
        )


def _validate_date_time(value: str, context: str) -> None:
    if not RFC3339_RE.fullmatch(value):
        raise ContractError(f"{context}: expected an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value[-1] in "Zz" else value)
    except ValueError as exc:
        raise ContractError(f"{context}: expected an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ContractError(f"{context}: expected an RFC 3339 timestamp")


def _validate_target(target: dict[str, Any]) -> None:
    kind = _require_str(target, "kind", "scan.target")
    if kind not in TARGET_KINDS:
        raise ContractError(f"scan.target.kind: unsupported target kind: {kind}")
    _require_str(target, "targetId", "scan.target")
    _require_str(target, "displayName", "scan.target")
    remote = target.get("remote")
    if remote is not None:
        if not isinstance(remote, str):
            raise ContractError("scan.target.remote: expected a string")
        _validate_remote(remote, "scan.target.remote")
    if kind == "git_revision":
        _require_str(target, "revision", "scan.target")
    elif kind in ("git_worktree", "git_diff", "directory_snapshot"):
        _require_str(target, "snapshotDigest", "scan.target")


def _fingerprint(
    target_id: str, finding: dict[str, Any], algorithm: str = FINGERPRINT_ALGORITHM
) -> str:
    identity = _require_dict(finding, "identity", "finding")
    anchor = _require_str(identity, "anchor", "finding.identity")
    if not SLUG_RE.fullmatch(anchor):
        raise ContractError("finding.identity.anchor: expected a stable lowercase semantic slug")
    instance = identity.get("instance", "")
    if not isinstance(instance, str):
        raise ContractError("finding.identity.instance: expected a string")
    if instance and not SLUG_RE.fullmatch(instance):
        raise ContractError("finding.identity.instance: expected a stable lowercase semantic slug")
    rule_id = _require_str(finding, "ruleId", "finding")
    if not SLUG_RE.fullmatch(rule_id):
        raise ContractError("finding.ruleId: expected a stable lowercase rule slug")
    material = "\0".join((algorithm, target_id, rule_id, anchor, instance))
    return f"{algorithm}:sha256:{hashlib.sha256(material.encode('utf-8')).hexdigest()}"


def _stable_id(prefix: str, *parts: str) -> str:
    return f"{prefix}_{hashlib.sha256(chr(0).join(parts).encode('utf-8')).hexdigest()[:24]}"


def _validate_location(location: dict[str, Any], context: str) -> None:
    _require_safe_relative_path(_require_str(location, "path", context), f"{context}.path")
    start = location.get("startLine")
    end = location.get("endLine", start)
    if not isinstance(start, int) or start < 1:
        raise ContractError(f"{context}.startLine: expected a positive integer")
    if not isinstance(end, int) or end < start:
        raise ContractError(f"{context}.endLine: expected an integer >= startLine")
    role = location.get("role")
    if role is not None and (not isinstance(role, str) or not role):
        raise ContractError(f"{context}.role: expected a non-empty string")


def _derived_finding_identity_rows(
    manifest: dict[str, Any],
    findings: dict[str, Any],
) -> list[tuple[str, dict[str, Any], str, str, dict[str, str]]]:
    scan = _require_dict(manifest, "scan", "manifest")
    scan_id = _require_str(scan, "id", "manifest.scan")
    target_id = _require_str(
        _require_dict(scan, "target", "manifest.scan"), "targetId", "scan.target"
    )
    review_type = scan.get("reviewType")
    algorithm = (
        BUG_FINGERPRINT_ALGORITHM if review_type == "functional_bug" else FINGERPRINT_ALGORITHM
    )
    if findings.get("scanId") != scan_id:
        raise ContractError("findings.scanId: must match manifest scan id")

    finding_ids: set[str] = set()
    occurrence_ids: set[str] = set()
    rows: list[tuple[str, dict[str, Any], str, str, dict[str, str]]] = []
    for index, finding in enumerate(_require_list(findings, "findings", "findings")):
        context = f"findings.findings[{index}]"
        if not isinstance(finding, dict):
            raise ContractError(f"{context}: expected an object")
        fingerprint = _fingerprint(target_id, finding, algorithm)
        expected_finding_id = _stable_id(
            "bug" if review_type == "functional_bug" else "csf", fingerprint
        )
        expected_occurrence_id = _stable_id("occ", scan_id, fingerprint)
        expected_fingerprints = {"algorithm": algorithm, "primary": fingerprint}
        rows.append(
            (
                context,
                finding,
                expected_finding_id,
                expected_occurrence_id,
                expected_fingerprints,
            )
        )
        finding_ids.add(expected_finding_id)
        if expected_occurrence_id in occurrence_ids:
            raise ContractError(
                f"{context}: duplicate occurrence identity; use identity.instance to split siblings"
            )
        occurrence_ids.add(expected_occurrence_id)

    if len(finding_ids) != len(occurrence_ids):
        raise ContractError("findings: duplicate logical findings in one scan")
    return rows


def _populate_unsealed_finding_identities(
    manifest: dict[str, Any],
    findings: dict[str, Any],
) -> None:
    """Replace draft-owned finding identities with deterministic finalizer values."""

    for _, finding, finding_id, occurrence_id, fingerprints in _derived_finding_identity_rows(
        manifest,
        findings,
    ):
        finding["findingId"] = finding_id
        finding["occurrenceId"] = occurrence_id
        finding["fingerprints"] = fingerprints


def _finding_strength(finding: dict[str, Any]) -> tuple[int, int, int]:
    return (
        ("informational", "low", "medium", "high", "critical").index(finding["severity"]["level"]),
        ("low", "medium", "high").index(finding["confidence"]["level"]),
        _finding_evidence_strength(finding),
    )


def _recover_unsealed_findings(
    manifest: dict[str, Any],
    findings: dict[str, Any],
    schema_dir: Path,
    scan_dir: Path,
    warnings: list[str],
) -> list[str]:
    scan = _require_dict(manifest, "scan", "manifest")
    if scan.get("reviewType") == "functional_bug":
        return _recover_unsealed_bug_findings(manifest, findings, schema_dir, warnings)
    schema = _read_json(schema_dir / "findings.schema.json")
    properties = _require_dict(schema, "properties", "findings.schema")
    finding_array = _require_dict(properties, "findings", "findings.schema.properties")
    finding_schema = _require_dict(finding_array, "items", "findings.schema.properties.findings")
    finding_properties = _require_dict(
        finding_schema, "properties", "findings.schema.properties.findings.items"
    )
    writeup_schema = _require_dict(
        finding_properties, "writeup", "findings.schema.properties.findings.items.properties"
    )
    auxiliary_schemas = {
        name: _require_dict(
            finding_properties, name, "findings.schema.properties.findings.items.properties"
        )
        for name in ("remediationTests", "preventiveControls")
    }
    scan = _require_dict(manifest, "scan", "manifest")
    scan_id = _require_str(scan, "id", "manifest.scan")
    if findings.get("scanId") != scan_id:
        raise ContractError("findings.scanId: must match manifest scan id")

    recovered: list[dict[str, Any]] = []
    discarded: list[str] = []
    finding_positions: dict[str, int] = {}
    writeup_paths: set[str] = set()
    for index, finding in enumerate(_require_list(findings, "findings", "findings")):
        context = f"findings.findings[{index}]"
        try:
            if not isinstance(finding, dict):
                raise ContractError(f"{context}: expected an object")
            compatible_findings = _legacy_sealed_findings_for_validation({"findings": [finding]})[
                "findings"
            ]
            compatible_finding = compatible_findings[0]
            normalized_legacy_details = compatible_finding != finding
            finding = compatible_finding
            identity = _require_dict(finding, "identity", context)
            fields: list[tuple[dict[str, Any], str, str, str]] = [
                (finding, "ruleId", context, "rule identifier"),
                (identity, "anchor", f"{context}.identity", "semantic anchor"),
            ]
            if "instance" in identity:
                fields.append((identity, "instance", f"{context}.identity", "instance"))
            normalized_fields = ["legacy finding details"] if normalized_legacy_details else []
            for parent, field, field_context, label in fields:
                value = _require_str(parent, field, field_context)
                if SLUG_RE.fullmatch(value):
                    continue
                normalized = re.sub(r"[^a-z0-9._/-]+", "-", value.lower()).strip("._/-")
                if not SLUG_RE.fullmatch(normalized):
                    raise ContractError(
                        f"{field_context}.{field}: expected a stable lowercase semantic slug"
                    )
                parent[field] = normalized
                normalized_fields.append(label)

            severity = finding.get("severity")
            if isinstance(severity, dict):
                change_conditions = severity.get("changeConditions")
                if (
                    isinstance(change_conditions, list)
                    and change_conditions
                    and all(
                        isinstance(condition, str) and condition.strip()
                        for condition in change_conditions
                    )
                ):
                    for condition_index, condition in enumerate(change_conditions):
                        _require_safe_json_string(
                            condition,
                            f"{context}.severity.changeConditions[{condition_index}]",
                        )
                    severity["changeConditions"] = " ".join(
                        condition.strip() for condition in change_conditions
                    )
                    normalized_fields.append("severity change conditions")

            _populate_unsealed_finding_identities(
                manifest,
                {"scanId": scan_id, "findings": [finding]},
            )
            finding_id = finding["findingId"]
            previous_position = finding_positions.get(finding_id)
            _validate_finding(finding, context)
            if "writeup" in finding:
                try:
                    _validate_schema_node(finding["writeup"], writeup_schema, f"{context}.writeup")
                    report_path = finding["writeup"]["reportPath"]
                    previous_writeup = (
                        recovered[previous_position].get("writeup")
                        if previous_position is not None
                        else None
                    )
                    if report_path in writeup_paths and (
                        previous_writeup is None or previous_writeup["reportPath"] != report_path
                    ):
                        raise ContractError(f"{context}.writeup.reportPath: duplicate report path")
                    _require_scan_local_file(scan_dir, report_path, f"{context}.writeup.reportPath")
                except ContractError as exc:
                    finding.pop("writeup")
                    warnings.append(f"Skipped malformed writeup for finding {index + 1}: {exc}.")
            for auxiliary, auxiliary_schema in auxiliary_schemas.items():
                if auxiliary not in finding:
                    continue
                try:
                    _validate_schema_node(
                        finding[auxiliary], auxiliary_schema, f"{context}.{auxiliary}"
                    )
                except ContractError as exc:
                    finding.pop(auxiliary)
                    warnings.append(
                        f"Skipped malformed {auxiliary} for finding {index + 1}: {exc}."
                    )
            _validate_schema_node(finding, finding_schema, context)
        except ContractError as exc:
            warning = f"Skipped malformed finding {index + 1}: {exc}."
            warnings.append(warning)
            discarded.append(warning)
            continue

        if previous_position is not None:
            previous = recovered[previous_position]
            strongest, earlier = (
                (previous, finding)
                if _finding_strength(finding) <= _finding_strength(previous)
                else (finding, previous)
            )
            if strongest != earlier:
                original = copy.deepcopy(earlier)
                older = original["provenance"].pop("previousFindings", [])
                if not isinstance(strongest["provenance"].get("previousFindings"), list):
                    strongest["provenance"]["previousFindings"] = []
                history = strongest["provenance"]["previousFindings"]
                for record in [*(older if isinstance(older, list) else []), original]:
                    if record not in history:
                        history.append(record)
            if _finding_strength(finding) <= _finding_strength(previous):
                warnings.append(
                    f"Skipped malformed finding {index + 1}: duplicate logical finding."
                )
                continue
            previous_writeup = previous.get("writeup")
            if previous_writeup is not None:
                writeup_paths.discard(previous_writeup["reportPath"])
            recovered[previous_position] = finding
            warnings.append(
                f"Recovered finding {index + 1}: retained stronger duplicate logical finding."
            )
        else:
            finding_positions[finding_id] = len(recovered)
            recovered.append(finding)

        if "writeup" in finding:
            writeup_paths.add(finding["writeup"]["reportPath"])
        if normalized_fields:
            warnings.append(
                f"Recovered finding {index + 1}: normalized {', '.join(normalized_fields)}."
            )

    findings["findings"] = recovered
    return discarded


def _recover_unsealed_bug_findings(
    manifest: dict[str, Any],
    findings: dict[str, Any],
    schema_dir: Path,
    warnings: list[str],
) -> list[str]:
    schema = _read_json(schema_dir / "bug-findings.schema.json")
    properties = _require_dict(schema, "properties", "bug-findings.schema")
    finding_array = _require_dict(properties, "findings", "bug-findings.schema.properties")
    finding_schema = _require_dict(
        finding_array, "items", "bug-findings.schema.properties.findings"
    )
    rows = findings.get("findings")
    if not isinstance(rows, list):
        warnings.append("Recovered malformed bug findings: expected an array.")
        findings["findings"] = []
        return ["Bug findings were discarded because the findings value was not an array."]

    recovered: list[dict[str, Any]] = []
    discarded: list[str] = []
    finding_ids: set[str] = set()
    occurrence_ids: set[str] = set()
    scan_id = _require_str(_require_dict(manifest, "scan", "manifest"), "id", "manifest.scan")
    for index, raw in enumerate(rows, 1):
        context = f"findings.findings[{index - 1}]"
        try:
            if not isinstance(raw, dict):
                raise ContractError(f"{context}: expected an object")
            finding = copy.deepcopy(raw)
            rule_id = _require_str(finding, "ruleId", context)
            if not SLUG_RE.fullmatch(rule_id):
                rule_id = re.sub(r"[^a-z0-9._/-]+", "-", rule_id.lower()).strip("._/-")
                if not SLUG_RE.fullmatch(rule_id):
                    rule_id = f"bug-{index}"
                finding["ruleId"] = rule_id
            identity = finding.get("identity")
            if not isinstance(identity, dict):
                identity = {}
                finding["identity"] = identity
            anchor = identity.get("anchor")
            if not isinstance(anchor, str) or not anchor.strip():
                extensions = finding.get("extensions")
                candidate_id = (
                    extensions.get("candidateId") if isinstance(extensions, dict) else None
                )
                anchor = (
                    candidate_id
                    if isinstance(candidate_id, str) and candidate_id.strip()
                    else finding.get("title")
                )
            if not isinstance(anchor, str) or not anchor.strip():
                raise ContractError(f"{context}.identity.anchor: expected a non-empty string")
            if not SLUG_RE.fullmatch(anchor):
                anchor = re.sub(r"[^a-z0-9._/-]+", "-", anchor.lower()).strip("._/-")
                if not SLUG_RE.fullmatch(anchor):
                    anchor = f"bug-{index}"
            identity["anchor"] = anchor
            instance = identity.get("instance")
            if instance is not None:
                if not isinstance(instance, str) or not instance.strip():
                    identity.pop("instance", None)
                elif not SLUG_RE.fullmatch(instance):
                    normalized = re.sub(r"[^a-z0-9._/-]+", "-", instance.lower()).strip("._/-")
                    if SLUG_RE.fullmatch(normalized):
                        identity["instance"] = normalized
                    else:
                        identity.pop("instance", None)

            _populate_unsealed_finding_identities(
                manifest,
                {"scanId": scan_id, "findings": [finding]},
            )
            _validate_bug_finding(finding, context)
            _validate_schema_node(finding, finding_schema, context)
        except ContractError as exc:
            warning = f"Skipped malformed bug finding {index}: {exc}."
            warnings.append(warning)
            discarded.append(warning)
            continue

        if finding["findingId"] in finding_ids or finding["occurrenceId"] in occurrence_ids:
            warning = f"Skipped duplicate bug finding {index}: duplicate identity."
            warnings.append(warning)
            discarded.append(warning)
            continue
        finding_ids.add(finding["findingId"])
        occurrence_ids.add(finding["occurrenceId"])
        recovered.append(finding)
    findings["findings"] = recovered
    return discarded


def _recover_unsealed_coverage(
    coverage: dict[str, Any],
    schema_dir: Path,
    scan_dir: Path,
    warnings: list[str],
    discarded_findings: list[str],
) -> None:
    bug_scan = coverage.get("documentType") == "functional-bug-scan.coverage"
    schema = _read_json(
        schema_dir / ("bug-coverage.schema.json" if bug_scan else "coverage.schema.json")
    )
    properties = _require_dict(schema, "properties", "coverage.schema")
    area_field = "reviewedAreas" if bug_scan else "surfaces"
    area_label = "reviewed area" if bug_scan else "coverage surface"
    area_dispositions = {"reviewed", "follow_up", "excluded"} if bug_scan else DISPOSITIONS
    if bug_scan and "surfaces" in coverage:
        surfaces = coverage.pop("surfaces")
        reviewed_areas = coverage.get("reviewedAreas")
        if not isinstance(surfaces, list):
            warnings.append("Recovered malformed functional bug review areas.")
            surfaces = []
            coverage["completeness"] = "partial"
        if not isinstance(reviewed_areas, list):
            reviewed_areas = []
        for index, surface in enumerate(surfaces, 1):
            if not isinstance(surface, dict):
                warnings.append(f"Skipped malformed functional bug review area {index}.")
                coverage["completeness"] = "partial"
                continue
            disposition = surface.get("disposition")
            if disposition in {"needs_follow_up", "follow_up"}:
                bug_disposition = "follow_up"
            elif disposition in {"not_applicable", "excluded"}:
                bug_disposition = "excluded"
            elif disposition in {"reported", "no_issue_found", "rejected", "reviewed"}:
                bug_disposition = "reviewed"
            else:
                warnings.append(
                    f"Recovered functional bug review area {index}: disposition could not be verified."
                )
                bug_disposition = "follow_up"
                coverage["completeness"] = "partial"
            area = {
                key: copy.deepcopy(surface[key])
                for key in ("label", "paths", "sourceWorkerIds", "notes")
                if key in surface
            }
            area["disposition"] = bug_disposition
            reviewed_areas.append(area)
        coverage["reviewedAreas"] = reviewed_areas
    completeness = coverage.get("completeness")
    partial = completeness not in ("complete", "partial", "unknown")
    if partial:
        warnings.append("Recovered malformed coverage completeness; marked coverage as partial.")
    if (
        coverage.get("mode") == "deep_repository"
        and coverage.get("inventoryStrategy") != "repository"
    ):
        coverage["inventoryStrategy"] = "repository"
        warnings.append(
            "Recovered malformed Deep Scan inventory strategy; marked coverage as partial."
        )
        partial = True

    surface_ids: set[str] = set()
    for field, label in (
        (area_field, area_label),
        ("explicitExclusions", "coverage exclusion"),
        ("deferred", "deferred coverage item"),
    ):
        array_schema = _require_dict(properties, field, "coverage.schema.properties")
        item_schema = _require_dict(array_schema, "items", f"coverage.schema.properties.{field}")
        items = coverage.get(field)
        if not isinstance(items, list):
            warnings.append(f"Skipped malformed {label} records: expected an array.")
            coverage[field] = []
            partial = True
            continue

        recovered: list[dict[str, Any]] = []
        for index, item in enumerate(items):
            context = f"coverage.{field}[{index}]"
            try:
                if not isinstance(item, dict):
                    raise ContractError(f"{context}: expected an object")
                if field == area_field:
                    if not bug_scan:
                        surface_id = _require_str(item, "id", context)
                        if surface_id in surface_ids:
                            raise ContractError(f"{context}.id: duplicate surface id")
                    else:
                        _require_str(item, "label", context)
                    disposition = item.get("disposition")
                    surface_recovered = False
                    if not isinstance(disposition, str) or disposition not in area_dispositions:
                        warnings.append(
                            f"Recovered {area_label} {index + 1}: "
                            "the review disposition could not be verified."
                        )
                        item["disposition"] = "follow_up" if bug_scan else "needs_follow_up"
                        surface_recovered = True

                    if not bug_scan:
                        receipt_refs = item.get("receiptRefs")
                        if not isinstance(receipt_refs, list):
                            warnings.append(
                                f"Skipped malformed receipt references for coverage surface "
                                f"{index + 1}: expected an array."
                            )
                            receipt_refs = []
                            surface_recovered = True

                        recovered_receipts: list[str] = []
                        for ref_index, ref in enumerate(receipt_refs):
                            ref_context = f"{context}.receiptRefs[{ref_index}]"
                            try:
                                if not isinstance(ref, str):
                                    raise ContractError(f"{ref_context}: expected a string")
                                normalized_ref = _require_portable_relative_path(ref, ref_context)
                                if not normalized_ref.startswith("artifacts/"):
                                    raise ContractError(
                                        f"{ref_context}: expected a file under artifacts/"
                                    )
                                _require_scan_local_file(scan_dir, normalized_ref, ref_context)
                            except ContractError as exc:
                                warnings.append(
                                    f"Skipped malformed coverage receipt "
                                    f"{index + 1}.{ref_index + 1}: {exc}."
                                )
                                surface_recovered = True
                                continue
                            recovered_receipts.append(normalized_ref)

                        item["receiptRefs"] = recovered_receipts
                    if surface_recovered or item["disposition"] in {
                        "needs_follow_up",
                        "follow_up",
                    }:
                        if not surface_recovered and completeness != "partial":
                            warnings.append(
                                f"{area_label.capitalize()} {index + 1} requires follow-up; "
                                "marked coverage as partial."
                            )
                        item["disposition"] = "follow_up" if bug_scan else "needs_follow_up"
                        partial = True

                _validate_schema_node(item, item_schema, context)
            except ContractError as exc:
                warnings.append(f"Skipped malformed {label} {index + 1}: {exc}.")
                partial = True
                continue

            if field == area_field and not bug_scan:
                surface_ids.add(surface_id)
            recovered.append(item)

        coverage[field] = recovered

    if discarded_findings:
        for surface in coverage[area_field]:
            surface["disposition"] = "follow_up" if bug_scan else "needs_follow_up"
        coverage["deferred"].extend(
            {"id": f"discarded-finding-{index}", "reason": warning}
            for index, warning in enumerate(discarded_findings, 1)
        )
        partial = True

    if "resolvedDeferred" in coverage:
        if bug_scan:
            coverage.pop("resolvedDeferred")
            warnings.append(
                "Skipped unsupported resolved deferred records in functional bug coverage."
            )
            partial = True
        else:
            try:
                _validate_schema_node(
                    coverage["resolvedDeferred"],
                    properties["resolvedDeferred"],
                    "coverage.resolvedDeferred",
                )
                _validate_resolved_deferred(coverage)
            except ContractError as exc:
                coverage.pop("resolvedDeferred")
                warnings.append(f"Skipped malformed resolved deferred work: {exc}.")
                partial = True

    if coverage["deferred"] and completeness != "partial":
        if not discarded_findings:
            warnings.append("Coverage has deferred review work; marked coverage as partial.")
        partial = True
    if partial:
        coverage["completeness"] = "partial"


def _recover_unsealed_hardening(
    manifest: dict[str, Any],
    scan_dir: Path,
    warnings: list[str],
) -> None:
    scan = _require_dict(manifest, "scan", "manifest")
    if "hardening" not in scan:
        return

    try:
        hardening = _require_dict(scan, "hardening", "manifest.scan")
        portfolio_path = _require_str(hardening, "portfolioPath", "manifest.scan.hardening")
        if portfolio_path != "hardening/hardening.md":
            raise ContractError(
                "manifest.scan.hardening.portfolioPath: expected hardening/hardening.md"
            )
        _require_hardening_portfolio_file(scan_dir, scan)
    except ContractError as exc:
        scan.pop("hardening")
        warnings.append(f"Skipped malformed hardening portfolio: {exc}.")


def _validate_derived_finding_identities(
    manifest: dict[str, Any],
    findings: dict[str, Any],
) -> None:
    """Require sealed finding identities to equal their deterministic values."""

    for context, finding, finding_id, occurrence_id, fingerprints in _derived_finding_identity_rows(
        manifest,
        findings,
    ):
        if finding.get("findingId") != finding_id:
            raise ContractError(f"{context}.findingId: does not match derived fingerprint identity")
        if finding.get("occurrenceId") != occurrence_id:
            raise ContractError(f"{context}.occurrenceId: does not match scan occurrence identity")
        if finding.get("fingerprints") != fingerprints:
            raise ContractError(f"{context}.fingerprints: does not match derived fingerprint")


def _populate_unsealed_manifest_envelope(
    manifest: dict[str, Any],
    scan: dict[str, Any],
    completion_binding: dict[str, Any] | None,
) -> None:
    """Populate non-semantic draft fields owned by finalization or the workbench."""

    manifest["documentType"] = (
        "functional-bug-scan.scan-manifest"
        if scan.get("reviewType") == "functional_bug"
        else "codex-security.scan-manifest"
    )
    manifest["schemaVersion"] = SCHEMA_VERSION
    scan["status"] = (
        completion_binding.get("status", "completed") if completion_binding else "completed"
    )
    scan["coverageRef"] = "coverage.json"
    scan["findingsRef"] = "findings.json"
    if completion_binding is None:
        started_at = os.environ.get("CODEX_SECURITY_STARTED_AT")
        if started_at is not None:
            _validate_date_time(started_at, "CODEX_SECURITY_STARTED_AT")
            scan["startedAt"] = started_at
            scan["completedAt"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return

    scan["id"] = completion_binding["scanId"]
    scan["startedAt"] = completion_binding["startedAt"]
    scan["completedAt"] = completion_binding["completedAt"]
    scan["producer"] = copy.deepcopy(completion_binding["producer"])

    target = scan.setdefault("target", {})
    if isinstance(target, dict):
        allowed_kinds = completion_binding["allowedTargetKinds"]
        if len(allowed_kinds) == 1:
            target.setdefault("kind", allowed_kinds[0])
        _populate_unsealed_target_binding(target, completion_binding["target"])

    scope = scan.setdefault("scope", {})
    if isinstance(scope, dict):
        scope.update(copy.deepcopy(completion_binding["scope"]))


def _populate_unsealed_target_binding(
    target: dict[str, Any],
    target_binding: dict[str, Any],
) -> None:
    """Replace workbench-owned target coordinates without retaining incompatible drafts."""

    target_kind = target.get("kind")
    required_coordinates = (
        TARGET_REQUIRED_COORDINATE_FIELDS.get(target_kind, set())
        if isinstance(target_kind, str)
        else set()
    )
    for field in TARGET_COORDINATE_FIELDS:
        if field not in target_binding and field not in required_coordinates:
            target.pop(field, None)
    target.update(copy.deepcopy(target_binding))


def _populate_unsealed_artifact_envelope(
    manifest: dict[str, Any],
    findings: dict[str, Any],
    coverage: dict[str, Any],
    completion_binding: dict[str, Any] | None,
) -> None:
    """Populate deterministic top-level draft fields after refs have been resolved."""

    bug_scan = manifest.get("documentType") == "functional-bug-scan.scan-manifest"
    findings["documentType"] = (
        "functional-bug-scan.findings" if bug_scan else "codex-security.findings"
    )
    findings["schemaVersion"] = SCHEMA_VERSION
    coverage["documentType"] = (
        "functional-bug-scan.coverage" if bug_scan else "codex-security.coverage"
    )
    coverage["schemaVersion"] = SCHEMA_VERSION
    if bug_scan:
        findings["hypotheses"] = _functional_bug_hypotheses(coverage)
    if completion_binding is None:
        return

    scan_id = completion_binding["scanId"]
    findings["scanId"] = scan_id
    coverage["scanId"] = scan_id
    coverage["mode"] = completion_binding["coverageMode"]

    scan = _require_dict(manifest, "scan", "manifest")
    scope = _require_dict(scan, "scope", "manifest.scan")
    if "includePaths" in scope:
        coverage["includePaths"] = copy.deepcopy(scope["includePaths"])
    if "excludePaths" in scope:
        coverage["excludePaths"] = copy.deepcopy(scope["excludePaths"])


def _functional_bug_hypotheses(coverage: dict[str, Any]) -> list[dict[str, Any]]:
    deferred = coverage.get("deferred", [])
    if not isinstance(deferred, list):
        return []
    return [
        copy.deepcopy(item)
        for item in deferred
        if isinstance(item, dict)
        and ("candidate" in item or "finding" in item or isinstance(item.get("hypothesis"), str))
    ]


def _normalize_unsealed_open_questions(coverage: dict[str, Any]) -> None:
    """Keep only schema-valid optional open-question rows without inventing content."""

    open_questions = coverage.get("openQuestions")
    if not isinstance(open_questions, list):
        coverage.pop("openQuestions", None)
        return

    normalized: list[Any] = []
    for item in open_questions:
        if isinstance(item, str):
            question = item.strip()
            if question:
                normalized.append({"question": question})
            continue
        if not isinstance(item, dict):
            continue

        question = item.get("question")
        if not isinstance(question, str) or not question.strip():
            continue
        row = dict(item)
        row["question"] = question.strip()
        follow_up = row.get("followUpPrompt")
        if not isinstance(follow_up, str) or not follow_up.strip():
            row.pop("followUpPrompt", None)
        normalized.append(row)
    coverage["openQuestions"] = normalized


def _normalize_unsealed_deep_repository_inventory_strategy(
    coverage: dict[str, Any],
    *,
    expected_coverage_mode: str | None,
) -> None:
    """Label whole-repository Deep scans as using the repository inventory."""

    if expected_coverage_mode == "deep_repository":
        coverage["inventoryStrategy"] = "repository"


def _validate_completion_binding(
    manifest: dict[str, Any],
    findings: dict[str, Any],
    coverage: dict[str, Any],
    completion_binding: dict[str, Any] | None,
) -> None:
    """Verify populated workbench-owned fields before an unsealed draft is written."""

    if completion_binding is None:
        return
    scan = _require_dict(manifest, "scan", "manifest")
    if scan.get("id") != completion_binding["scanId"]:
        raise ContractError("manifest.scan.id: must match the workbench scan")
    if scan.get("status") != completion_binding.get("status", "completed"):
        raise ContractError("manifest.scan.status: must match the workbench outcome")
    if scan.get("startedAt") != completion_binding["startedAt"]:
        raise ContractError("manifest.scan.startedAt: must match the workbench scan")
    if scan.get("completedAt") != completion_binding["completedAt"]:
        raise ContractError("manifest.scan.completedAt: must match the workbench completion")
    if scan.get("producer") != completion_binding["producer"]:
        raise ContractError("manifest.scan.producer: must match the workbench producer")
    target = _require_dict(scan, "target", "manifest.scan")
    allowed_target_kinds = completion_binding["allowedTargetKinds"]
    if target.get("kind") not in allowed_target_kinds:
        raise ContractError("scan.target.kind: must match the workbench target")
    for key, expected in completion_binding["target"].items():
        if target.get(key) != expected:
            raise ContractError(f"scan.target.{key}: must match the workbench target")
    scope = _require_dict(scan, "scope", "manifest.scan")
    for key, expected in completion_binding["scope"].items():
        if scope.get(key) != expected:
            raise ContractError(f"manifest.scan.scope.{key}: must match the workbench scan")
    if findings.get("scanId") != completion_binding["scanId"]:
        raise ContractError("findings.scanId: must match the workbench scan")
    if coverage.get("scanId") != completion_binding["scanId"]:
        raise ContractError("coverage.scanId: must match the workbench scan")
    if coverage.get("mode") != completion_binding["coverageMode"]:
        raise ContractError("coverage.mode: must match the workbench scan")
    for key, expected in completion_binding["scope"].items():
        if coverage.get(key) != expected:
            raise ContractError(f"coverage.{key}: must match the workbench scan")


def _validate_finding(finding: dict[str, Any], context: str) -> None:
    for key in ("findingId", "occurrenceId", "ruleId", "title", "summary", "remediation"):
        _require_str(finding, key, context)
    _require_dict(finding, "identity", context)
    fingerprints = _require_dict(finding, "fingerprints", context)
    if fingerprints.get("algorithm") != FINGERPRINT_ALGORITHM:
        raise ContractError(f"{context}.fingerprints.algorithm: unsupported algorithm")
    _require_str(fingerprints, "primary", f"{context}.fingerprints")

    severity = _require_dict(finding, "severity", context)
    level = _require_str(severity, "level", f"{context}.severity")
    if level not in SEVERITIES:
        raise ContractError(f"{context}.severity.level: unsupported severity: {level}")
    score = severity.get("score")
    if score is not None:
        if not isinstance(score, (int, float)) or isinstance(score, bool) or not 0 <= score <= 10:
            raise ContractError(f"{context}.severity.score: expected a number from 0 through 10")
        _require_str(severity, "scoringSystem", f"{context}.severity")

    confidence = _require_dict(finding, "confidence", context)
    confidence_level = _require_str(confidence, "level", f"{context}.confidence")
    if confidence_level not in CONFIDENCES:
        raise ContractError(
            f"{context}.confidence.level: unsupported confidence: {confidence_level}"
        )
    _require_str(confidence, "rationale", f"{context}.confidence")

    taxonomy = _require_dict(finding, "taxonomy", context)
    _require_str(taxonomy, "category", f"{context}.taxonomy")
    cwe = taxonomy.get("cwe", [])
    if not isinstance(cwe, list) or any(not isinstance(item, str) or not item for item in cwe):
        raise ContractError(f"{context}.taxonomy.cwe: expected an array of strings")

    locations = _require_list(finding, "locations", context)
    if not locations:
        raise ContractError(f"{context}.locations: expected at least one location")
    for index, location in enumerate(locations):
        if not isinstance(location, dict):
            raise ContractError(f"{context}.locations[{index}]: expected an object")
        _validate_location(location, f"{context}.locations[{index}]")

    evidence_ids: set[str] = set()
    for evidence_key in ("codeEvidence", "code_evidence"):
        if evidence_key not in finding:
            continue
        code_evidence = finding[evidence_key]
        if not isinstance(code_evidence, list):
            raise ContractError(f"{context}.{evidence_key}: expected an array")
        for index, evidence in enumerate(code_evidence):
            evidence_context = f"{context}.{evidence_key}[{index}]"
            if not isinstance(evidence, dict):
                raise ContractError(f"{evidence_context}: expected an object")
            evidence_id = _require_str(evidence, "id", evidence_context)
            if evidence_id in evidence_ids:
                raise ContractError(f"{evidence_context}.id: duplicate code-evidence id")
            evidence_ids.add(evidence_id)
            _require_str(evidence, "code", evidence_context)

    referenced_sections = [
        (section_name, finding.get(section_name))
        for section_name in ("rootCause", "root_cause", "validation", "attackPath")
    ]
    attack_path = finding.get("attackPath")
    if isinstance(attack_path, dict):
        referenced_sections.extend(
            (f"attackPath.{section_name}", attack_path.get(section_name))
            for section_name in ("dataFlow", "dataflow", "data_flow", "reachability")
        )
    for section_name, section in referenced_sections:
        if not isinstance(section, dict):
            continue
        for refs_key in ("evidenceRefs", "evidence_refs"):
            if refs_key not in section:
                continue
            refs = section[refs_key]
            if not isinstance(refs, list) or any(
                not isinstance(ref, str) or not ref for ref in refs
            ):
                raise ContractError(f"{context}.{section_name}.{refs_key}: expected strings")
            unknown_refs = sorted(set(refs) - evidence_ids)
            if unknown_refs:
                raise ContractError(
                    f"{context}.{section_name}.{refs_key}: unknown code-evidence ids: "
                    + ", ".join(unknown_refs)
                )

    provenance = _require_dict(finding, "provenance", context)
    _require_str(provenance, "source", f"{context}.provenance")
    extensions = finding.get("extensions")
    if extensions is not None and not isinstance(extensions, dict):
        raise ContractError(f"{context}.extensions: expected an object")


def _validate_bug_finding(finding: dict[str, Any], context: str) -> None:
    for key in (
        "findingId",
        "occurrenceId",
        "ruleId",
        "title",
        "summary",
        "category",
        "expected",
        "actual",
        "impact",
    ):
        _require_str(finding, key, context)
    if not re.fullmatch(r"bug_[a-f0-9]{24}", finding["findingId"]):
        raise ContractError(f"{context}.findingId: unsupported functional bug identity")
    if not re.fullmatch(r"occ_[a-f0-9]{24}", finding["occurrenceId"]):
        raise ContractError(f"{context}.occurrenceId: unsupported occurrence identity")
    if finding.get("priority") not in {"P0", "P1", "P2", "P3"}:
        raise ContractError(f"{context}.priority: expected P0, P1, P2, or P3")
    identity = _require_dict(finding, "identity", context)
    _require_str(identity, "anchor", f"{context}.identity")
    fingerprints = _require_dict(finding, "fingerprints", context)
    if fingerprints.get("algorithm") != BUG_FINGERPRINT_ALGORITHM:
        raise ContractError(f"{context}.fingerprints.algorithm: unsupported algorithm")
    _require_str(fingerprints, "primary", f"{context}.fingerprints")
    confidence = _require_dict(finding, "confidence", context)
    if confidence.get("level") not in CONFIDENCES:
        raise ContractError(f"{context}.confidence.level: unsupported confidence")
    _require_str(confidence, "rationale", f"{context}.confidence")

    locations = _require_list(finding, "locations", context)
    if not locations:
        raise ContractError(f"{context}.locations: expected at least one location")
    for index, location in enumerate(locations):
        if not isinstance(location, dict):
            raise ContractError(f"{context}.locations[{index}]: expected an object")
        _validate_location(location, f"{context}.locations[{index}]")

    validation = _require_dict(finding, "validation", context)
    if validation.get("status") != "validated":
        raise ContractError(f"{context}.validation.status: only validated bugs belong in findings")
    _require_str(validation, "method", f"{context}.validation")
    evidence = _require_list(validation, "evidence", f"{context}.validation")
    if not evidence or any(not isinstance(item, str) or not item.strip() for item in evidence):
        raise ContractError(f"{context}.validation.evidence: expected non-empty evidence")
    for field in ("reproduction", "counterEvidence", "limitations"):
        items = validation.get(field, [])
        if not isinstance(items, list) or any(
            not isinstance(item, str) or not item.strip() for item in items
        ):
            raise ContractError(f"{context}.validation.{field}: expected strings")
    provenance = _require_dict(finding, "provenance", context)
    _require_str(provenance, "source", f"{context}.provenance")
    _require_safe_json_value(finding, context)


def _validate_resolved_deferred(coverage: dict[str, Any]) -> None:
    if "resolvedDeferred" not in coverage:
        return
    active = {
        identity
        for row in coverage.get("deferred", [])
        if isinstance(row, dict)
        for identity in (row.get("id"), row.get("candidateId"))
        if isinstance(identity, str)
    }
    resolved: set[str] = set()
    for index, closure in enumerate(_require_list(coverage, "resolvedDeferred", "coverage")):
        context = f"coverage.resolvedDeferred[{index}]"
        if not isinstance(closure, dict):
            raise ContractError(f"{context}: expected an object")
        closure_id = _require_str(closure, "id", context)
        _require_str(closure, "reason", context)
        if closure_id in resolved:
            raise ContractError(f"{context}.id: duplicate resolved deferred id")
        if closure_id in active:
            raise ContractError(f"{context}.id: deferred work is still active")
        resolved.add(closure_id)


def _validate_coverage(manifest: dict[str, Any], coverage: dict[str, Any], scan_dir: Path) -> None:
    scan = _require_dict(manifest, "scan", "manifest")
    scan_id = _require_str(scan, "id", "manifest.scan")
    if coverage.get("scanId") != scan_id:
        raise ContractError("coverage.scanId: must match manifest scan id")
    _require_str(coverage, "mode", "coverage")
    completeness = _require_str(coverage, "completeness", "coverage")
    _require_str(coverage, "inventoryStrategy", "coverage")
    scope = _require_dict(scan, "scope", "manifest.scan")
    if coverage.get("includePaths") != scope.get("includePaths"):
        raise ContractError("coverage.includePaths: must match manifest scope")
    if coverage.get("excludePaths") != scope.get("excludePaths"):
        raise ContractError("coverage.excludePaths: must match manifest scope")
    if scan.get("reviewType") == "functional_bug":
        reviewed_areas = _require_list(coverage, "reviewedAreas", "coverage")
        follow_up = False
        for index, area in enumerate(reviewed_areas):
            context = f"coverage.reviewedAreas[{index}]"
            if not isinstance(area, dict):
                raise ContractError(f"{context}: expected an object")
            _require_str(area, "label", context)
            disposition = _require_str(area, "disposition", context)
            if disposition not in {"reviewed", "follow_up", "excluded"}:
                raise ContractError(f"{context}.disposition: unsupported value")
            follow_up = follow_up or disposition == "follow_up"
        for field in ("explicitExclusions", "deferred"):
            if not isinstance(coverage.get(field), list):
                raise ContractError(f"coverage.{field}: expected an array")
        if completeness == "complete" and (follow_up or coverage["deferred"]):
            raise ContractError("coverage.completeness: complete coverage cannot have open work")
        _require_safe_json_value(coverage, "coverage.json")
        return
    surface_ids: set[str] = set()
    has_needs_follow_up = False
    for index, surface in enumerate(_require_list(coverage, "surfaces", "coverage")):
        context = f"coverage.surfaces[{index}]"
        if not isinstance(surface, dict):
            raise ContractError(f"{context}: expected an object")
        surface_id = _require_str(surface, "id", context)
        if surface_id in surface_ids:
            raise ContractError(f"{context}.id: duplicate surface id")
        surface_ids.add(surface_id)
        _require_str(surface, "label", context)
        disposition = _require_str(surface, "disposition", context)
        if disposition not in DISPOSITIONS:
            raise ContractError(f"{context}.disposition: unsupported disposition: {disposition}")
        has_needs_follow_up = has_needs_follow_up or disposition == "needs_follow_up"
        receipt_refs = surface.get("receiptRefs", [])
        if not isinstance(receipt_refs, list):
            raise ContractError(f"{context}.receiptRefs: expected an array")
        for ref_index, ref in enumerate(receipt_refs):
            if not isinstance(ref, str):
                raise ContractError(f"{context}.receiptRefs[{ref_index}]: expected a string")
            normalized_ref = _require_portable_relative_path(
                ref, f"{context}.receiptRefs[{ref_index}]"
            )
            if not normalized_ref.startswith("artifacts/"):
                raise ContractError(
                    f"{context}.receiptRefs[{ref_index}]: expected a file under artifacts/"
                )
            receipt_refs[ref_index] = normalized_ref
            _require_scan_local_file(
                scan_dir, normalized_ref, f"{context}.receiptRefs[{ref_index}]"
            )
    for field in ("explicitExclusions", "deferred"):
        if not isinstance(coverage.get(field, []), list):
            raise ContractError(f"coverage.{field}: expected an array")
    _validate_resolved_deferred(coverage)
    if completeness == "complete" and (has_needs_follow_up or coverage.get("deferred")):
        raise ContractError("coverage.completeness: complete coverage cannot have deferred work")
    _require_safe_json_value(coverage, "coverage.json")


def _validate_manifest(manifest: dict[str, Any]) -> None:
    scan = _require_dict(manifest, "scan", "manifest")
    is_bug_scan = scan.get("reviewType") == "functional_bug"
    expected_type = (
        "functional-bug-scan.scan-manifest" if is_bug_scan else "codex-security.scan-manifest"
    )
    if manifest.get("documentType") != expected_type:
        raise ContractError(f"manifest.documentType: expected {expected_type}")
    if manifest.get("schemaVersion") != SCHEMA_VERSION:
        raise ContractError(f"manifest.schemaVersion: expected {SCHEMA_VERSION}")
    if is_bug_scan and scan.get("reviewType") != "functional_bug":
        raise ContractError("manifest.scan.reviewType: expected functional_bug")
    for key in ("id", "startedAt", "completedAt", "sealedAt"):
        _require_str(scan, key, "manifest.scan")
    if scan.get("status") not in {"completed", "failed", "canceled", "interrupted"}:
        raise ContractError("manifest.scan.status: expected a terminal scan outcome")
    producer = _require_dict(scan, "producer", "manifest.scan")
    _require_str(producer, "name", "manifest.scan.producer")
    _require_str(producer, "version", "manifest.scan.producer")
    _validate_target(_require_dict(scan, "target", "manifest.scan"))
    scope = _require_dict(scan, "scope", "manifest.scan")
    for field in ("includePaths", "excludePaths"):
        values = _require_list(scope, field, "manifest.scan.scope")
        for index, value in enumerate(values):
            if not isinstance(value, str):
                raise ContractError(f"manifest.scan.scope.{field}[{index}]: expected a string")
            _require_safe_relative_path(
                value, f"manifest.scan.scope.{field}[{index}]", allow_dot=True
            )
    _validate_contract_refs(scan)
    artifacts = _require_list(scan, "artifacts", "manifest.scan")
    if not artifacts:
        raise ContractError("manifest.scan.artifacts: expected generated artifact records")
    artifact_paths: set[str] = set()
    artifact_collision_keys: set[str] = set()
    for index, artifact in enumerate(artifacts):
        context = f"manifest.scan.artifacts[{index}]"
        if not isinstance(artifact, dict):
            raise ContractError(f"{context}: expected an object")
        path = _require_portable_relative_path(
            _require_str(artifact, "path", context), f"{context}.path"
        )
        collision_key = path.lower()
        if collision_key in artifact_collision_keys:
            raise ContractError(f"{context}.path: duplicate artifact path")
        artifact_paths.add(path)
        artifact_collision_keys.add(collision_key)
        _require_str(artifact, "sha256", context)
        _require_str(artifact, "mediaType", context)
    for required_path in ("findings.json", "coverage.json"):
        if required_path not in artifact_paths:
            raise ContractError(
                f"manifest.scan.artifacts: missing required artifact: {required_path}"
            )
    _require_safe_json_value(manifest, "scan-manifest.json")


def _validate_findings(manifest: dict[str, Any], findings: dict[str, Any]) -> None:
    scan = _require_dict(manifest, "scan", "manifest")
    is_bug_scan = scan.get("reviewType") == "functional_bug"
    expected_type = "functional-bug-scan.findings" if is_bug_scan else "codex-security.findings"
    if findings.get("documentType") != expected_type:
        raise ContractError(f"findings.documentType: expected {expected_type}")
    if findings.get("schemaVersion") != SCHEMA_VERSION:
        raise ContractError(f"findings.schemaVersion: expected {SCHEMA_VERSION}")
    scan_id = _require_str(_require_dict(manifest, "scan", "manifest"), "id", "manifest.scan")
    if findings.get("scanId") != scan_id:
        raise ContractError("findings.scanId: must match manifest scan id")
    finding_ids: set[str] = set()
    occurrence_ids: set[str] = set()
    for index, finding in enumerate(_require_list(findings, "findings", "findings")):
        context = f"findings.findings[{index}]"
        if not isinstance(finding, dict):
            raise ContractError(f"{context}: expected an object")
        if is_bug_scan:
            _validate_bug_finding(finding, context)
        else:
            _validate_finding(finding, context)
        finding_id = str(finding["findingId"])
        occurrence_id = str(finding["occurrenceId"])
        if finding_id in finding_ids or occurrence_id in occurrence_ids:
            raise ContractError(f"{context}: duplicate finding or occurrence id")
        finding_ids.add(finding_id)
        occurrence_ids.add(occurrence_id)
    if is_bug_scan and not isinstance(findings.get("hypotheses"), list):
        raise ContractError("findings.hypotheses: expected an array")
    _require_safe_json_value(findings, "findings.json")


def _schema_type_matches(value: Any, expected: str) -> bool:
    return {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
        "null": value is None,
    }[expected]


def _schema_values_equal(left: Any, right: Any) -> bool:
    if (
        isinstance(left, (int, float))
        and not isinstance(left, bool)
        and isinstance(right, (int, float))
        and not isinstance(right, bool)
    ):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _schema_values_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _schema_values_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


def _resolve_schema_reference(
    root_schema: dict[str, Any], reference: str, context: str
) -> dict[str, Any]:
    if reference == "#":
        return root_schema
    if not reference.startswith("#/"):
        raise ContractError(f"{context}: unsupported schema reference {reference!r}")
    target: Any = root_schema
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, dict) or part not in target:
            raise ContractError(f"{context}: unresolved schema reference {reference!r}")
        target = target[part]
    if not isinstance(target, dict):
        raise ContractError(f"{context}: schema reference {reference!r} is not an object")
    return target


def _validate_schema_node(
    value: Any,
    schema: dict[str, Any],
    context: str,
    root_schema: dict[str, Any] | None = None,
) -> None:
    root_schema = schema if root_schema is None else root_schema
    alternatives = schema.get("anyOf")
    if isinstance(alternatives, list):
        errors = []
        for alternative in alternatives:
            try:
                _validate_schema_node(value, alternative, context, root_schema)
                break
            except ContractError as exc:
                errors.append(str(exc))
        else:
            raise ContractError(f"{context}: no schema alternative matched: {'; '.join(errors)}")
    reference = schema.get("$ref")
    if reference is not None:
        if not isinstance(reference, str):
            raise ContractError(f"{context}: schema reference must be a string")
        _validate_schema_node(
            value,
            _resolve_schema_reference(root_schema, reference, context),
            context,
            root_schema,
        )
    expected = schema.get("type")
    if isinstance(expected, list):
        if not any(_schema_type_matches(value, item) for item in expected):
            raise ContractError(f"{context}: does not match schema type {expected}")
    elif isinstance(expected, str) and not _schema_type_matches(value, expected):
        raise ContractError(f"{context}: expected schema type {expected}")
    if "const" in schema and not _schema_values_equal(value, schema["const"]):
        raise ContractError(f"{context}: expected {schema['const']!r}")
    if "enum" in schema and not any(
        _schema_values_equal(value, candidate) for candidate in schema["enum"]
    ):
        raise ContractError(f"{context}: unsupported value {value!r}")
    if isinstance(value, str):
        if schema.get("minLength", 0) and len(value) < schema["minLength"]:
            raise ContractError(f"{context}: string is too short")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            raise ContractError(f"{context}: string does not match schema pattern")
        if schema.get("format") == "date-time":
            _validate_date_time(value, context)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ContractError(f"{context}: value is below schema minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise ContractError(f"{context}: value is above schema maximum")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise ContractError(f"{context}: array has too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise ContractError(f"{context}: array has too many items")
        if schema.get("uniqueItems") is True:
            for index, item in enumerate(value):
                if any(_schema_values_equal(item, candidate) for candidate in value[:index]):
                    raise ContractError(f"{context}: array items must be unique")
        contains = schema.get("contains")
        if isinstance(contains, dict):
            matches = 0
            for item in value:
                try:
                    _validate_schema_node(item, contains, context, root_schema)
                except ContractError:
                    pass
                else:
                    matches += 1
            if matches < schema.get("minContains", 1):
                raise ContractError(f"{context}: array contains too few matching items")
            if "maxContains" in schema and matches > schema["maxContains"]:
                raise ContractError(f"{context}: array contains too many matching items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate_schema_node(item, item_schema, f"{context}[{index}]", root_schema)
    if isinstance(value, dict):
        for item_schema in schema.get("allOf", []):
            _validate_schema_node(value, item_schema, context, root_schema)
        condition = schema.get("if")
        if isinstance(condition, dict):
            try:
                _validate_schema_node(value, condition, context, root_schema)
            except ContractError:
                pass
            else:
                then_schema = schema.get("then")
                if isinstance(then_schema, dict):
                    _validate_schema_node(value, then_schema, context, root_schema)
        for key in schema.get("required", []):
            if key not in value:
                raise ContractError(f"{context}.{key}: missing required schema property")
        if "minProperties" in schema and len(value) < schema["minProperties"]:
            raise ContractError(f"{context}: object has too few properties")
        properties = schema.get("properties", {})
        additional_properties = schema.get("additionalProperties", True)
        for key, item in value.items():
            item_schema = properties.get(key)
            if isinstance(item_schema, dict):
                _validate_schema_node(item, item_schema, f"{context}.{key}", root_schema)
            elif additional_properties is False:
                raise ContractError(f"{context}.{key}: unexpected schema property")
            elif isinstance(additional_properties, dict):
                _validate_schema_node(
                    item,
                    additional_properties,
                    f"{context}.{key}",
                    root_schema,
                )


def validate_against_schema(payload: dict[str, Any], schema_path: Path) -> None:
    schema = _read_json(schema_path)
    _validate_schema_node(payload, schema, schema_path.stem, schema)


def _filter_unknown_legacy_evidence_refs(section: dict[str, Any], evidence_ids: set[str]) -> None:
    for refs_field in ("evidenceRefs", "evidence_refs"):
        refs = section.get(refs_field)
        if isinstance(refs, list):
            section[refs_field] = [
                ref for ref in refs if isinstance(ref, str) and ref.strip() and ref in evidence_ids
            ]


def _normalize_legacy_string_list_fields(section: dict[str, Any], fields: tuple[str, ...]) -> None:
    for field in fields:
        if field not in section:
            continue
        value = section[field]
        if isinstance(value, str):
            normalized = [value] if value.strip() else []
        elif isinstance(value, list):
            normalized = [item for item in value if isinstance(item, str) and item.strip()]
        else:
            normalized = []
        if normalized:
            section[field] = normalized
        else:
            section.pop(field)


def _remove_unsupported_legacy_scalar_fields(
    section: dict[str, Any], fields: tuple[str, ...]
) -> None:
    for field in fields:
        if field in section and (not isinstance(section[field], str) or section[field] == ""):
            section.pop(field)


def _legacy_sealed_findings_for_validation(findings: dict[str, Any]) -> dict[str, Any]:
    compatible = copy.deepcopy(findings)
    finding_items = compatible.get("findings")
    if not isinstance(finding_items, list):
        return compatible
    for finding in finding_items:
        if not isinstance(finding, dict):
            continue
        canonical_evidence = finding.get("codeEvidence")
        canonical_evidence = canonical_evidence if isinstance(canonical_evidence, list) else []
        evidence_ids = {
            evidence["id"]
            for evidence in canonical_evidence
            if isinstance(evidence, dict) and isinstance(evidence.get("id"), str) and evidence["id"]
        }
        legacy_evidence = finding.get("code_evidence")
        if isinstance(legacy_evidence, list):
            compatible_legacy_evidence = []
            for evidence in legacy_evidence:
                if not isinstance(evidence, dict):
                    continue
                evidence_id = evidence.get("id")
                evidence_code = evidence.get("code")
                if (
                    not isinstance(evidence_id, str)
                    or not evidence_id.strip()
                    or not isinstance(evidence_code, str)
                    or not evidence_code.strip()
                ):
                    continue
                if evidence_id in evidence_ids:
                    continue
                evidence_ids.add(evidence_id)
                compatible_legacy_evidence.append(evidence)
            finding["code_evidence"] = compatible_legacy_evidence
        elif "code_evidence" in finding:
            finding.pop("code_evidence")
        for section_name, list_fields in (
            ("rootCause", ("evidenceRefs", "evidence_refs")),
            ("root_cause", ("evidenceRefs", "evidence_refs")),
            (
                "validation",
                (
                    "assertions",
                    "counterEvidence",
                    "evidence",
                    "evidenceRefs",
                    "evidence_refs",
                    "limitations",
                ),
            ),
            (
                "attackPath",
                (
                    "assumptions",
                    "blindspots",
                    "controls",
                    "evidenceRefs",
                    "evidence_refs",
                    "limitations",
                    "preconditions",
                    "steps",
                ),
            ),
        ):
            section = finding.get(section_name)
            if not isinstance(section, dict):
                continue
            _normalize_legacy_string_list_fields(section, list_fields)
            _filter_unknown_legacy_evidence_refs(section, evidence_ids)
        legacy_root_cause = finding.get("root_cause")
        if isinstance(legacy_root_cause, dict):
            _remove_unsupported_legacy_scalar_fields(
                legacy_root_cause, ("summary", "code", "language")
            )
        elif (
            "root_cause" in finding
            and legacy_root_cause is not None
            and (not isinstance(legacy_root_cause, str) or legacy_root_cause == "")
        ):
            finding.pop("root_cause")
        validation = finding.get("validation")
        if isinstance(validation, dict):
            _remove_unsupported_legacy_scalar_fields(
                validation, ("method", "status", "summary", "disposition", "result")
            )
        attack_path = finding.get("attackPath")
        if not isinstance(attack_path, dict):
            continue
        _remove_unsupported_legacy_scalar_fields(attack_path, ("summary",))
        for field in ("dataFlow", "data_flow", "dataflow", "reachability"):
            if field not in attack_path:
                continue
            detail = attack_path.get(field)
            if detail is None:
                attack_path.pop(field)
                continue
            if not isinstance(detail, (str, dict)):
                attack_path.pop(field)
                continue
            if isinstance(detail, str):
                if detail == "":
                    attack_path.pop(field)
                continue
            detail_scalar_fields = ("summary", "source", "sink", "outcome")
            if field == "reachability":
                detail_scalar_fields += ("attacker", "entrypoint")
            _remove_unsupported_legacy_scalar_fields(detail, detail_scalar_fields)
            _normalize_legacy_string_list_fields(
                detail, ("evidenceRefs", "evidence_refs", "transformations")
            )
            _filter_unknown_legacy_evidence_refs(detail, evidence_ids)
            if field == "reachability":
                _normalize_legacy_string_list_fields(detail, ("preconditions",))
        for field in ("impact", "likelihood"):
            detail = attack_path.get(field)
            if isinstance(detail, dict):
                _remove_unsupported_legacy_scalar_fields(detail, ("level", "rationale", "why"))
            elif detail is not None and (not isinstance(detail, str) or detail == ""):
                attack_path.pop(field)
    return compatible


def _validate_canonical_schemas_before_projection(
    manifest: dict[str, Any],
    findings: dict[str, Any],
    coverage: dict[str, Any],
    schema_dir: Path,
) -> None:
    provisional_manifest = copy.deepcopy(manifest)
    provisional_scan = _require_dict(provisional_manifest, "scan", "manifest")
    provisional_scan["artifacts"] = [
        {"path": "findings.json", "sha256": "0" * 64, "mediaType": "application/json"},
        {"path": "coverage.json", "sha256": "0" * 64, "mediaType": "application/json"},
    ]
    manifest_schema, findings_schema, coverage_schema = _contract_schema_paths(
        provisional_manifest, schema_dir
    )
    validate_against_schema(provisional_manifest, manifest_schema)
    validate_against_schema(findings, findings_schema)
    validate_against_schema(coverage, coverage_schema)


def _contract_schema_paths(manifest: dict[str, Any], schema_dir: Path) -> tuple[Path, Path, Path]:
    scan = _require_dict(manifest, "scan", "manifest")
    if scan.get("reviewType") == "functional_bug":
        return (
            schema_dir / "bug-scan-manifest.schema.json",
            schema_dir / "bug-findings.schema.json",
            schema_dir / "bug-coverage.schema.json",
        )
    return (
        schema_dir / "scan-manifest.schema.json",
        schema_dir / "findings.schema.json",
        schema_dir / "coverage.schema.json",
    )


def _validate_contract_refs(scan: dict[str, Any]) -> None:
    for field, expected in (
        ("coverageRef", "coverage.json"),
        ("findingsRef", "findings.json"),
    ):
        actual = _require_str(scan, field, "manifest.scan")
        if actual != expected:
            raise ContractError(f"manifest.scan.{field}: expected {expected!r}")


def _sarif_label(value: str) -> str:
    words = re.sub(r"[-_./]+", " ", value).split()
    acronyms = {"api", "csrf", "html", "http", "id", "rce", "sql", "ssrf", "url", "xml", "xss"}
    label = " ".join(word.upper() if word.lower() in acronyms else word for word in words)
    return label[:1].upper() + label[1:]


def _sarif_rule(rule_id: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    name = ": ".join(_sarif_label(part) for part in rule_id.split("."))
    categories = sorted({finding["taxonomy"]["category"] for finding in findings})
    cwes = sorted({cwe for finding in findings for cwe in finding["taxonomy"]["cwe"]})
    tags = {"security", *categories}
    for cwe in cwes:
        match = re.fullmatch(r"CWE-([0-9]+)", cwe, re.IGNORECASE)
        if match and int(match[1]) > 0:
            tags.add(f"external/cwe/cwe-{int(match[1]):03d}")
    description = f"{name}. Categories: {', '.join(map(_sarif_label, categories))}."
    if cwes:
        description += f" Weaknesses: {', '.join(cwes)}."
    remediation = "\n\n".join(sorted({finding["remediation"] for finding in findings}))
    properties: dict[str, Any] = {"tags": sorted(tags)}
    # GitHub assigns security severity to the shared rule, not each result.
    score = max(
        finding["severity"].get("score", SARIF_SECURITY_SCORES[finding["severity"]["level"]])
        for finding in findings
    )
    if score > 0:
        properties["security-severity"] = str(score)
    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": name},
        "fullDescription": {"text": description},
        "help": {
            "text": f"{description}\n\nRemediation:\n\n{remediation}",
            "markdown": f"{description}\n\n## Remediation\n\n{remediation}",
        },
        "properties": properties,
    }


def _sarif_finding_message(finding: dict[str, Any]) -> str:
    taxonomy = finding["taxonomy"]
    details = [
        finding["title"],
        finding["summary"],
        f"Severity: {finding['severity']['level']}",
        f"Category: {_sarif_label(taxonomy['category'])}",
    ]
    if taxonomy["cwe"]:
        details.append(f"Weaknesses: {', '.join(taxonomy['cwe'])}")
    details.append(f"Remediation:\n{finding['remediation']}")
    for key, label in (
        ("remediationTests", "Remediation tests"),
        ("preventiveControls", "Preventive controls"),
    ):
        if finding.get(key):
            details.append(f"{label}:\n" + "\n".join(f"- {item}" for item in finding[key]))
    return "\n\n".join(details)


def _github_line_hashes(
    handle: TextIO,
    requested_lines: set[int] | None = None,
) -> dict[int, str]:
    window = [0] * GITHUB_HASH_BLOCK_SIZE
    line_numbers = [-1] * GITHUB_HASH_BLOCK_SIZE
    hash_counts: dict[str, int] = {}
    hashes: dict[int, str] = {}
    first_mod = pow(GITHUB_HASH_MOD, GITHUB_HASH_BLOCK_SIZE, 1 << 64)
    hash_raw = 0
    index = 0
    line_number = 0
    line_start = True
    previous_was_cr = False

    def output_hash() -> None:
        nonlocal index
        hash_value = format(hash_raw & GITHUB_HASH_MASK, "x")
        hash_counts[hash_value] = hash_counts.get(hash_value, 0) + 1
        line_number = line_numbers[index]
        if requested_lines is None or line_number in requested_lines:
            hashes[line_number] = f"{hash_value}:{hash_counts[hash_value]}"
        line_numbers[index] = -1

    def update_hash(current: int) -> None:
        nonlocal hash_raw, index
        beginning = window[index]
        window[index] = current
        hash_raw = (GITHUB_HASH_MOD * hash_raw + current - first_mod * beginning) & GITHUB_HASH_MASK
        index = (index + 1) % GITHUB_HASH_BLOCK_SIZE

    def process_character(current: int) -> None:
        nonlocal line_number, line_start, previous_was_cr
        if current in {ord(" "), ord("\t")} or (previous_was_cr and current == ord("\n")):
            previous_was_cr = False
            return
        if current == ord("\r"):
            current = ord("\n")
            previous_was_cr = True
        else:
            previous_was_cr = False
        if line_numbers[index] != -1:
            output_hash()
        if line_start:
            line_start = False
            line_number += 1
            line_numbers[index] = line_number
        if current == ord("\n"):
            line_start = True
        update_hash(current)

    while chunk := handle.read(SOURCE_READ_CHUNK_SIZE):
        for (code_unit,) in struct.iter_unpack("<H", chunk.encode("utf-16-le")):
            process_character(code_unit)
    process_character(GITHUB_HASH_EOF)
    for _ in range(GITHUB_HASH_BLOCK_SIZE):
        if line_numbers[index] != -1:
            output_hash()
        update_hash(0)
    return hashes


def _open_source_file(source_root: Path, relative_path: str) -> TextIO | None:
    file_fd: int | None = None
    try:
        file_fd = open_scan_local_file_descriptor(
            source_root, relative_path, f"source file {relative_path}"
        )
        handle = os.fdopen(file_fd, "r", encoding="utf-8", errors="replace")
        file_fd = None
        return handle
    except (ContractError, OSError, ValueError):
        return None
    finally:
        if file_fd is not None:
            os.close(file_fd)


def _github_line_hashes_for_source(
    source_root: Path,
    relative_path: str,
    requested_lines: set[int] | None = None,
) -> dict[int, str] | None:
    handle = _open_source_file(source_root, relative_path)
    if handle is None:
        return None
    try:
        with handle:
            return _github_line_hashes(handle, requested_lines)
    except OSError:
        return None


def _sarif_primary_location(finding: dict[str, Any]) -> dict[str, Any]:
    return next(
        (location for location in finding["locations"] if location.get("role") == "root_control"),
        finding["locations"][0],
    )


def _merged_code_evidence(finding: dict[str, Any]) -> list[dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    for evidence_key in ("codeEvidence", "code_evidence"):
        code_evidence = finding.get(evidence_key)
        if not isinstance(code_evidence, list):
            continue
        for evidence in code_evidence:
            if not isinstance(evidence, dict):
                continue
            evidence_id = evidence.get("id")
            if isinstance(evidence_id, str) and evidence_id:
                catalog.setdefault(evidence_id, evidence)
    return list(catalog.values())


def _finding_evidence_strength(finding: dict[str, Any]) -> int:
    evidence = _merged_code_evidence(finding)
    seen_ids = {
        item["id"] for item in evidence if isinstance(item.get("id"), str) and item["id"].strip()
    }
    seen_codes = {
        item["code"]
        for item in evidence
        if isinstance(item.get("code"), str) and item["code"].strip()
    }
    strength = len(evidence)
    for section_name in ("rootCause", "root_cause"):
        section = finding.get(section_name)
        if not isinstance(section, dict):
            continue
        for evidence_name in ("codeEvidence", "code_evidence"):
            embedded = section.get(evidence_name)
            if not isinstance(embedded, list):
                continue
            for item in embedded:
                if not isinstance(item, dict):
                    continue
                code = item.get("code")
                if not isinstance(code, str) or not code.strip() or code in seen_codes:
                    continue
                evidence_id = item.get("id")
                if isinstance(evidence_id, str) and evidence_id.strip():
                    if evidence_id in seen_ids:
                        continue
                    seen_ids.add(evidence_id)
                seen_codes.add(code)
                strength += 1
        code = section.get("code")
        if isinstance(code, str) and code.strip() and code not in seen_codes:
            seen_codes.add(code)
            strength += 1
    return strength


def _sarif_locations(finding: dict[str, Any]) -> list[dict[str, Any]]:
    primary = _sarif_primary_location(finding)
    locations = [
        primary,
        *(location for location in finding["locations"] if location is not primary),
    ]
    for evidence in _merged_code_evidence(finding):
        path = evidence.get("path")
        start_line = evidence.get("startLine")
        if (
            not isinstance(path, str)
            or not isinstance(start_line, int)
            or isinstance(start_line, bool)
            or start_line < 1
        ):
            continue
        try:
            path = _require_safe_relative_path(path, "SARIF evidence location")
        except ContractError:
            continue
        locations.append(
            {
                "path": path,
                "startLine": start_line,
                "endLine": (
                    evidence["endLine"]
                    if isinstance(evidence.get("endLine"), int)
                    and not isinstance(evidence["endLine"], bool)
                    and evidence["endLine"] >= start_line
                    else start_line
                ),
                "role": f"evidence:{evidence['id']}",
            }
        )
    unique: dict[tuple[str, int, int], dict[str, Any]] = {}
    for location in locations:
        key = (
            location["path"],
            location["startLine"],
            location.get("endLine", location["startLine"]),
        )
        unique.setdefault(key, location)
    return list(unique.values())


def _github_primary_location_line_hash(
    finding: dict[str, Any],
    source_root: Path | None,
    line_hash_cache: dict[tuple[Path, int], str | None] | None = None,
) -> str | None:
    if source_root is None:
        return None
    primary_location = _sarif_primary_location(finding)
    try:
        source_root = source_root.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    relative_path = _require_safe_relative_path(primary_location["path"], "SARIF source location")
    source_path = source_root / relative_path
    start_line = primary_location["startLine"]
    cache_key = (source_path, start_line)
    if line_hash_cache is not None and cache_key in line_hash_cache:
        return line_hash_cache[cache_key]
    line_hashes = _github_line_hashes_for_source(source_root, relative_path, {start_line})
    line_hash = None if line_hashes is None else line_hashes.get(start_line)
    if line_hash_cache is not None:
        line_hash_cache[cache_key] = line_hash
    return line_hash


def _github_line_hash_cache(
    findings: list[dict[str, Any]], source_root: Path | None
) -> dict[tuple[Path, int], str | None]:
    if source_root is None:
        return {}
    try:
        source_root = source_root.resolve(strict=True)
    except (OSError, RuntimeError):
        return {}
    requested_lines_by_path: dict[str, set[int]] = {}
    for finding in findings:
        primary_location = _sarif_primary_location(finding)
        relative_path = _require_safe_relative_path(
            primary_location["path"], "SARIF source location"
        )
        requested_lines_by_path.setdefault(relative_path, set()).add(primary_location["startLine"])
    line_hash_cache: dict[tuple[Path, int], str | None] = {}
    for relative_path, requested_lines in requested_lines_by_path.items():
        line_hashes = _github_line_hashes_for_source(source_root, relative_path, requested_lines)
        source_path = source_root / relative_path
        for line_number in requested_lines:
            line_hash_cache[(source_path, line_number)] = (
                None if line_hashes is None else line_hashes.get(line_number)
            )
    return line_hash_cache


def _sarif_location(location: dict[str, Any], location_id: int | None = None) -> dict[str, Any]:
    sarif_location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {
                "uri": quote(location["path"], safe="/"),
            },
            "region": {
                "startLine": location["startLine"],
                "endLine": location.get("endLine", location["startLine"]),
            },
        }
    }
    if location_id is not None:
        sarif_location["id"] = location_id
    if location.get("role"):
        sarif_location["message"] = {"text": location["role"]}
    return sarif_location


def _sarif_result(
    finding: dict[str, Any],
    rule_index: int,
    source_root: Path | None = None,
    line_hash_cache: dict[tuple[Path, int], str | None] | None = None,
) -> dict[str, Any]:
    properties = {
        "category": finding["taxonomy"]["category"],
        "confidence": finding["confidence"]["level"],
        "findingId": finding["findingId"],
        "occurrenceId": finding["occurrenceId"],
        "severity": finding["severity"]["level"],
    }
    extensions = finding.get("extensions")
    candidate_id = extensions.get("candidateId") if isinstance(extensions, dict) else None
    if isinstance(candidate_id, str) and candidate_id:
        properties["candidateId"] = candidate_id
    partial_fingerprints = {
        "codexSecurity/v1": finding["fingerprints"]["primary"],
    }
    line_hash = _github_primary_location_line_hash(finding, source_root, line_hash_cache)
    if line_hash is not None:
        partial_fingerprints["primaryLocationLineHash"] = line_hash
    result = {
        "ruleId": finding["ruleId"],
        "ruleIndex": rule_index,
        "level": SARIF_LEVELS[finding["severity"]["level"]],
        "message": {"text": _sarif_finding_message(finding)},
        "locations": [_sarif_location(location) for location in _sarif_locations(finding)],
        "partialFingerprints": partial_fingerprints,
        "properties": properties,
    }
    return result


def build_sarif(
    manifest: dict[str, Any], findings: dict[str, Any], source_root: Path | None = None
) -> dict[str, Any]:
    scan = manifest["scan"]
    target = scan["target"]
    ordered_findings = sorted(findings["findings"], key=lambda finding: finding["occurrenceId"])
    findings_by_rule: dict[str, list[dict[str, Any]]] = {}
    for finding in ordered_findings:
        findings_by_rule.setdefault(finding["ruleId"], []).append(finding)
    ordered_rule_ids = sorted(findings_by_rule)
    rule_index = {rule_id: index for index, rule_id in enumerate(ordered_rule_ids)}
    line_hash_cache = _github_line_hash_cache(ordered_findings, source_root)
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "Codex Security",
                "version": scan["producer"]["version"],
                "rules": [
                    _sarif_rule(rule_id, findings_by_rule[rule_id]) for rule_id in ordered_rule_ids
                ],
            }
        },
        "automationDetails": {"id": scan["id"]},
        "results": [
            _sarif_result(finding, rule_index[finding["ruleId"]], source_root, line_hash_cache)
            for finding in ordered_findings
        ],
        "properties": {
            "codexSecuritySchemaVersion": manifest["schemaVersion"],
            "codexSecurityTargetKind": target["kind"],
        },
    }
    if target["kind"] == "git_revision" and target.get("remote") and target.get("revision"):
        run["versionControlProvenance"] = [
            {
                "repositoryUri": target["remote"],
                "revisionId": target["revision"],
            }
        ]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


def _artifact_record(
    scan_dir: Path, relative_path: str, media_type: str, contents: bytes | None = None
) -> dict[str, str]:
    relative_path = _require_portable_relative_path(relative_path, "artifact path")
    if contents is not None:
        _validate_scan_local_output_path(scan_dir, scan_dir / relative_path, relative_path)
    return {
        "mediaType": media_type,
        "path": relative_path,
        "sha256": (
            hashlib.sha256(contents).hexdigest()
            if contents is not None
            else _sha256_scan_local_file(scan_dir, relative_path, relative_path)
        ),
    }


def _coverage_receipt_refs(coverage: dict[str, Any]) -> list[str]:
    if coverage.get("documentType") == "functional-bug-scan.coverage":
        return []
    refs = {ref for surface in coverage["surfaces"] for ref in surface.get("receiptRefs", [])}
    return sorted(refs)


def _validate_sealed_coverage_receipts(scan: dict[str, Any], coverage: dict[str, Any]) -> None:
    artifact_paths = {
        _require_portable_relative_path(artifact["path"], "sealed artifact path")
        for artifact in scan["artifacts"]
    }
    for ref in _coverage_receipt_refs(coverage):
        if ref not in artifact_paths:
            raise ContractError(f"coverage receipt is missing from sealed artifacts: {ref}")


def _validate_existing_seal(
    scan_dir: Path,
    scan: dict[str, Any],
    *,
    artifact_contents: dict[str, bytes] | None = None,
) -> None:
    sealed_at = scan.get("sealedAt")
    artifacts = scan.get("artifacts")
    if sealed_at is None and artifacts is None:
        return
    if sealed_at != scan.get("completedAt"):
        raise ContractError("manifest.scan.sealedAt: must match completedAt")
    if not isinstance(artifacts, list) or not artifacts:
        raise ContractError("manifest.scan.artifacts: sealed manifest requires artifact records")
    artifact_collision_keys: set[str] = set()
    for index, artifact in enumerate(artifacts):
        context = f"manifest.scan.artifacts[{index}]"
        if not isinstance(artifact, dict):
            raise ContractError(f"{context}: expected an object")
        path = _require_portable_relative_path(
            _require_str(artifact, "path", context), f"{context}.path"
        )
        collision_key = path.lower()
        if collision_key in artifact_collision_keys:
            raise ContractError(f"{context}.path: duplicate artifact path")
        artifact_collision_keys.add(collision_key)
        expected_sha256 = _require_str(artifact, "sha256", context)
        contents = (artifact_contents or {}).get(path)
        actual_sha256 = (
            hashlib.sha256(contents).hexdigest()
            if contents is not None
            else _sha256_scan_local_file(scan_dir, path, context)
        )
        if actual_sha256 != expected_sha256:
            raise ContractError(f"{context}: sealed artifact changed or is missing")


def _read_sealed_scan(
    scan_dir: Path, schema_dir: Path | None, required_for: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bytes]:
    scan_dir = _require_scan_directory(scan_dir)
    schema_dir = schema_dir or Path(__file__).resolve().parent.parent / "schemas"
    manifest = _read_scan_local_json(scan_dir, "scan-manifest.json", "scan-manifest.json")
    scan = _require_dict(manifest, "scan", "manifest")
    _validate_contract_refs(scan)
    if scan.get("sealedAt") is None or scan.get("artifacts") is None:
        raise ContractError(f"manifest.scan: {required_for} requires a sealed scan")
    findings, findings_bytes = _read_scan_local_json_bytes(
        scan_dir, scan["findingsRef"], scan["findingsRef"]
    )
    coverage, coverage_bytes = _read_scan_local_json_bytes(
        scan_dir, scan["coverageRef"], scan["coverageRef"]
    )
    _validate_existing_seal(
        scan_dir,
        scan,
        artifact_contents={
            scan["findingsRef"]: findings_bytes,
            scan["coverageRef"]: coverage_bytes,
        },
    )
    _validate_manifest(manifest)
    is_bug_scan = scan.get("reviewType") == "functional_bug"
    findings_for_validation = (
        findings if is_bug_scan else _legacy_sealed_findings_for_validation(findings)
    )
    _validate_findings(manifest, findings_for_validation)
    _validate_coverage(manifest, coverage, scan_dir)
    manifest_schema, findings_schema, coverage_schema = _contract_schema_paths(manifest, schema_dir)
    if not is_bug_scan:
        _validate_sealed_coverage_receipts(scan, coverage)
    validate_against_schema(manifest, manifest_schema)
    validate_against_schema(findings_for_validation, findings_schema)
    validate_against_schema(coverage, coverage_schema)
    _validate_derived_finding_identities(manifest, findings)
    return manifest, findings, coverage, findings_bytes


def build_sarif_projection(
    scan_dir: Path, source_root: Path | None = None, schema_dir: Path | None = None
) -> dict[str, Any]:
    if source_root is not None:
        try:
            source_root = source_root.resolve(strict=True)
            source_root_is_directory = source_root.is_dir()
        except (OSError, RuntimeError):
            source_root_is_directory = False
        if not source_root_is_directory:
            raise ContractError("source root: expected an existing directory")
    manifest, findings, coverage, _ = _read_sealed_scan(scan_dir, schema_dir, "SARIF projection")
    if manifest["scan"].get("reviewType") == "functional_bug":
        raise ContractError("SARIF export is not available for functional bug scan results")
    sarif = build_sarif(manifest, findings, source_root)
    execution_successful = manifest["scan"]["status"] == "completed"
    if not execution_successful or coverage["completeness"] != "complete":
        run = sarif["runs"][0]
        run["properties"]["codexSecurityCoverageCompleteness"] = coverage["completeness"]
        run["invocations"] = [
            {
                "executionSuccessful": execution_successful,
                "toolExecutionNotifications": [
                    {"level": "warning", "message": {"text": item["reason"]}}
                    for item in coverage["deferred"]
                ],
            }
        ]
    return sarif


def write_sarif_projection(
    scan_dir: Path, source_root: Path | None = None, schema_dir: Path | None = None
) -> None:
    sarif = build_sarif_projection(scan_dir, source_root, schema_dir)
    _write_scan_local_json(scan_dir, "exports/results.sarif", sarif)


def csv_cell(value: Any) -> Any:
    if isinstance(value, str) and (
        value.startswith(("'", "\t", "\r", "\n"))
        or value.lstrip().startswith(("=", "+", "-", "@", "＝", "＋", "－", "＠"))
    ):
        return f"'{value}"
    return value


def finding_candidate_id(finding: dict[str, Any]) -> str | None:
    provenance = finding.get("provenance")
    if (
        isinstance(provenance, dict)
        and isinstance(value := provenance.get("candidateId"), str)
        and value.strip()
    ):
        return value
    extensions = finding.get("extensions")
    if not isinstance(extensions, dict):
        return None
    return next(
        (
            value
            for field in ("candidateId", "reportId", "ledgerRowId")
            if isinstance(value := extensions.get(field), str) and value.strip()
        ),
        None,
    )


def finding_csv_columns(deep_scan: bool) -> tuple[str, ...]:
    return (
        "occurrence_id",
        "finding_id",
        *(("candidate_id",) if deep_scan else ()),
        "title",
        "summary",
        "severity",
        "confidence",
        "status",
        "close_reason",
        "note",
        "remediation",
        "path",
        "start_line",
        "end_line",
    )


def build_csv_projection(findings: dict[str, Any], coverage: dict[str, Any]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    if coverage.get("documentType") == "functional-bug-scan.coverage":
        writer.writerow(
            (
                "occurrence_id",
                "bug_id",
                "title",
                "summary",
                "priority",
                "confidence",
                "validation",
                "expected",
                "actual",
                "path",
                "start_line",
                "end_line",
            )
        )
        for finding in findings["findings"]:
            location = finding["locations"][0]
            writer.writerow(
                (
                    csv_cell(finding["occurrenceId"]),
                    csv_cell(finding["findingId"]),
                    csv_cell(finding["title"]),
                    csv_cell(finding["summary"]),
                    csv_cell(finding["priority"]),
                    csv_cell(finding["confidence"]["level"]),
                    csv_cell(finding["validation"]["status"]),
                    csv_cell(finding["expected"]),
                    csv_cell(finding["actual"]),
                    csv_cell(location["path"]),
                    location["startLine"],
                    location.get("endLine", location["startLine"]),
                )
            )
        return output.getvalue().encode("utf-8")
    deep_scan = coverage.get("mode") == "deep_repository" or (
        coverage.get("mode") == "scoped_path"
        and any(
            isinstance(finding.get("extensions"), dict)
            and any(
                isinstance(finding["extensions"].get(field), str)
                and finding["extensions"][field].strip()
                for field in ("candidateId", "reportId")
            )
            for finding in findings["findings"]
        )
    )
    writer.writerow(finding_csv_columns(deep_scan))
    for finding in findings["findings"]:
        locations = finding["locations"]
        location = next(
            (candidate for candidate in locations if candidate.get("role") == "root_control"),
            locations[0],
        )
        writer.writerow(
            (
                csv_cell(finding["occurrenceId"]),
                csv_cell(finding["findingId"]),
                *((csv_cell(finding_candidate_id(finding)),) if deep_scan else ()),
                csv_cell(finding["title"]),
                csv_cell(finding["summary"]),
                csv_cell(finding["severity"]["level"]),
                csv_cell(finding["confidence"]["level"]),
                "open",
                "",
                "",
                csv_cell(finding["remediation"]),
                csv_cell(location["path"]),
                location["startLine"],
                location.get("endLine", location["startLine"]),
            )
        )
    return output.getvalue().encode("utf-8")


def build_findings_export(
    scan_dir: Path,
    export_format: str,
    source_root: Path | None = None,
    schema_dir: Path | None = None,
) -> bytes:
    if export_format not in EXPORT_PATHS:
        raise ContractError(f"unsupported export format: {export_format}")
    if export_format == "sarif":
        return _json_bytes(build_sarif_projection(scan_dir, source_root, schema_dir))
    if source_root is not None:
        raise ContractError("source-root is only supported for SARIF exports")
    _, findings, coverage, findings_bytes = _read_sealed_scan(
        scan_dir, schema_dir, f"{export_format.upper()} export"
    )
    if export_format == "json":
        return findings_bytes
    return build_csv_projection(findings, coverage)


def write_export_output(scan_dir: Path, output: Path, export_format: str, contents: bytes) -> None:
    output_paths = {**EXPORT_PATHS, "md": THREAT_MODEL_EXPORT_PATH}
    if export_format not in output_paths:
        raise ContractError(f"unsupported export format: {export_format}")
    scan_dir = _require_scan_directory(scan_dir)
    output = Path(os.path.abspath(output))
    try:
        relative_output = output.relative_to(scan_dir).as_posix()
    except ValueError:
        for ancestor in output.parents:
            try:
                inside_scan = ancestor.samefile(scan_dir)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ContractError(
                    "export output path: unable to inspect output directory"
                ) from exc
            if inside_scan:
                if any(parent.is_symlink() for parent in (ancestor, *ancestor.parents)):
                    raise ContractError(
                        "export output path: symbolic links cannot alias the scan directory"
                    ) from None
                relative_output = output.relative_to(ancestor).as_posix()
                break
        else:
            write_scan_local_bytes(
                output.parent,
                output.name,
                contents,
                external_name=True,
                owner_read_write=export_format == "md",
            )
            return
    if relative_output != output_paths[export_format]:
        raise ContractError(f"{export_format.upper()} output path cannot overwrite a scan artifact")
    if (scan_dir / "scan-manifest.json").exists():
        manifest = _read_scan_local_json(scan_dir, "scan-manifest.json", "scan-manifest.json")
        scan = _require_dict(manifest, "scan", "manifest")
        artifacts = scan.get("artifacts", [])
    else:
        artifacts = []
    artifact_paths = [
        _require_portable_relative_path(
            _require_str(artifact, "path", f"manifest.scan.artifacts[{index}]"),
            f"manifest.scan.artifacts[{index}].path",
        )
        for index, artifact in enumerate(artifacts)
        if isinstance(artifact, dict)
    ]
    try:
        output_metadata = output.stat(follow_symlinks=False)
    except FileNotFoundError:
        output_metadata = None
    except OSError as exc:
        raise ContractError(f"{relative_output}: unable to inspect export output") from exc
    for artifact_path in artifact_paths:
        if artifact_path == relative_output:
            raise ContractError(
                f"{export_format.upper()} output path cannot overwrite a sealed scan artifact"
            )
        if output_metadata is None:
            continue
        descriptor = open_scan_local_file_descriptor(
            scan_dir, artifact_path, f"sealed artifact {artifact_path}"
        )
        try:
            artifact_metadata = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if os.path.samestat(output_metadata, artifact_metadata):
            raise ContractError(
                f"{export_format.upper()} output path cannot overwrite a sealed scan artifact"
            )
    write_scan_local_bytes(
        scan_dir, relative_output, contents, owner_read_write=export_format == "md"
    )


def _write_sarif_projection_if_possible(
    scan_dir: Path, source_root: Path | None = None, schema_dir: Path | None = None
) -> None:
    try:
        write_sarif_projection(scan_dir, source_root, schema_dir)
    except (ContractError, OSError) as error:
        print(
            f"codex-security: warning: automatic SARIF export failed: {error}. "
            "Run `codex-security export <scan-dir> --export-format sarif` to retry.",
            file=sys.stderr,
        )


PreparedScanFinalization = tuple[
    Path,
    Path,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    bool,
    bytes,
]


def _prepare_scan_finalization(
    scan_dir: Path,
    schema_dir: Path | None = None,
    *,
    expected_coverage_mode: str | None = None,
    completion_binding: dict[str, Any] | None = None,
    completion_warnings: list[str] | None = None,
    draft_documents: tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None = None,
) -> PreparedScanFinalization:
    """Read, populate, and validate a scan without writing any output files."""

    scan_dir = _require_scan_directory(scan_dir)
    schema_dir = schema_dir or Path(__file__).resolve().parent.parent / "schemas"
    manifest = (
        copy.deepcopy(draft_documents[0])
        if draft_documents is not None
        else _read_scan_local_json(scan_dir, "scan-manifest.json", "scan-manifest.json")
    )
    scan = _require_dict(manifest, "scan", "manifest")
    if scan.get("sealedAt") is None and scan.get("artifacts") == []:
        del scan["artifacts"]
    was_sealed = scan.get("sealedAt") is not None or scan.get("artifacts") is not None
    if not was_sealed:
        _populate_unsealed_manifest_envelope(manifest, scan, completion_binding)
    _validate_contract_refs(scan)
    if draft_documents is None:
        findings, findings_input_bytes = _read_scan_local_json_bytes(
            scan_dir, scan["findingsRef"], scan["findingsRef"]
        )
        coverage, coverage_input_bytes = _read_scan_local_json_bytes(
            scan_dir, scan["coverageRef"], scan["coverageRef"]
        )
    else:
        findings, coverage = copy.deepcopy(draft_documents[1:])
        findings_input_bytes, coverage_input_bytes = _json_bytes(findings), _json_bytes(coverage)
    if not was_sealed:
        _populate_unsealed_artifact_envelope(manifest, findings, coverage, completion_binding)
        _normalize_unsealed_deep_repository_inventory_strategy(
            coverage,
            expected_coverage_mode=expected_coverage_mode,
        )
        _normalize_unsealed_open_questions(coverage)

    if manifest.get("schemaVersion") != SCHEMA_VERSION:
        raise ContractError(f"manifest.schemaVersion: expected {SCHEMA_VERSION}")
    if scan.get("status") not in {"completed", "failed", "canceled", "interrupted"}:
        raise ContractError("manifest.scan.status: expected a terminal scan outcome before sealing")
    if (
        expected_coverage_mode is not None
        and completion_binding is not None
        and completion_binding["coverageMode"] != expected_coverage_mode
    ):
        raise ContractError("completion binding coverage mode does not match expected mode")
    if expected_coverage_mode is not None and coverage.get("mode") != expected_coverage_mode:
        raise ContractError(
            f"coverage.mode: must match selected scan mode {expected_coverage_mode}"
        )
    _validate_existing_seal(
        scan_dir,
        scan,
        artifact_contents={
            scan["findingsRef"]: findings_input_bytes,
            scan["coverageRef"]: coverage_input_bytes,
        },
    )
    scan["sealedAt"] = _require_str(scan, "completedAt", "manifest.scan")
    _validate_target(_require_dict(scan, "target", "manifest.scan"))
    _validate_completion_binding(manifest, findings, coverage, completion_binding)
    is_bug_scan = scan.get("reviewType") == "functional_bug"
    findings_for_validation = (
        findings
        if is_bug_scan or not was_sealed
        else _legacy_sealed_findings_for_validation(findings)
    )
    if not was_sealed and completion_warnings is not None:
        discarded_findings = _recover_unsealed_findings(
            manifest, findings, schema_dir, scan_dir, completion_warnings
        )
        _recover_unsealed_coverage(
            coverage, schema_dir, scan_dir, completion_warnings, discarded_findings
        )
        _recover_unsealed_hardening(manifest, scan_dir, completion_warnings)
        if is_bug_scan:
            findings["hypotheses"] = _functional_bug_hypotheses(coverage)
    elif not was_sealed:
        _populate_unsealed_finding_identities(manifest, findings)
    _validate_findings(manifest, findings_for_validation)
    if was_sealed:
        _validate_derived_finding_identities(manifest, findings)
    _validate_coverage(manifest, coverage, scan_dir)
    _validate_canonical_schemas_before_projection(
        manifest, findings_for_validation, coverage, schema_dir
    )
    _require_derived_writeup_files(scan_dir, findings)
    _require_hardening_portfolio_file(scan_dir, scan)
    if was_sealed:
        if not is_bug_scan:
            _validate_sealed_coverage_receipts(scan, coverage)
        _validate_manifest(manifest)
        manifest_schema, _, _ = _contract_schema_paths(manifest, schema_dir)
        validate_against_schema(manifest, manifest_schema)
        report_markdown_bytes = _generate_report_projection(manifest, findings, coverage)
        _validate_scan_local_output_path(scan_dir, scan_dir / "report.md", "report.md")
    else:
        findings_bytes = _contract_json_bytes("findings.json", findings)
        coverage_bytes = _contract_json_bytes("coverage.json", coverage)
        report_markdown_bytes = _generate_report_projection(manifest, findings, coverage)
        _validate_scan_local_output_path(scan_dir, scan_dir / "report.md", "report.md")
        scan["artifacts"] = [
            _artifact_record(scan_dir, "findings.json", "application/json", findings_bytes),
            _artifact_record(scan_dir, "coverage.json", "application/json", coverage_bytes),
            *[
                _artifact_record(scan_dir, ref, "application/octet-stream")
                for ref in _coverage_receipt_refs(coverage)
            ],
        ]
        _validate_manifest(manifest)
        manifest_schema, _, _ = _contract_schema_paths(manifest, schema_dir)
        validate_against_schema(manifest, manifest_schema)
        _contract_json_bytes("scan-manifest.json", manifest)
    return (
        scan_dir,
        schema_dir,
        manifest,
        findings,
        coverage,
        was_sealed,
        report_markdown_bytes,
    )


def _write_prepared_scan_finalization(
    prepared: PreparedScanFinalization,
    source_root: Path | None = None,
    *,
    projection_warnings: list[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Write a previously validated scan finalization result."""

    (
        scan_dir,
        schema_dir,
        manifest,
        findings,
        coverage,
        was_sealed,
        report_markdown_bytes,
    ) = prepared
    scan = _require_dict(manifest, "scan", "manifest")
    if not was_sealed:
        _write_scan_local_json(scan_dir, "findings.json", findings)
        _write_scan_local_json(scan_dir, "coverage.json", coverage)
    write_scan_local_bytes(scan_dir, "report.md", report_markdown_bytes)
    _remove_scan_local_file_if_exists(scan_dir, "report.html")
    if not was_sealed:
        _write_scan_local_json(scan_dir, "scan-manifest.json", manifest)
        _validate_existing_seal(scan_dir, scan)
    is_bug_scan = scan.get("reviewType") == "functional_bug"
    if not is_bug_scan:
        _write_sarif_projection_if_possible(scan_dir, source_root, schema_dir)
    warning = None if is_bug_scan else write_threat_model_projection_if_possible(scan_dir, manifest)
    if (
        warning is not None
        and projection_warnings is not None
        and warning not in projection_warnings
    ):
        projection_warnings.append(warning)
    return manifest, findings, coverage


def finalize_scan(
    scan_dir: Path,
    schema_dir: Path | None = None,
    source_root: Path | None = None,
    *,
    expected_coverage_mode: str | None = None,
    completion_binding: dict[str, Any] | None = None,
    projection_warnings: list[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    prepared = _prepare_scan_finalization(
        scan_dir,
        schema_dir,
        expected_coverage_mode=expected_coverage_mode,
        completion_binding=completion_binding,
    )
    return _write_prepared_scan_finalization(
        prepared, source_root, projection_warnings=projection_warnings
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-dir", required=True, type=Path)
    parser.add_argument("--schema-dir", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--sarif-only", action="store_true")
    parser.add_argument("--sarif-output", type=Path)
    parser.add_argument(
        "--export-artifact", choices=("findings", "threat-model"), default="findings"
    )
    parser.add_argument("--export-format", choices=[*sorted(EXPORT_PATHS), "md"])
    parser.add_argument("--export-output", type=Path)
    parser.add_argument("--export-metadata", action="store_true")
    parser.add_argument("--describe-threat-model", action="store_true")
    parser.add_argument("--write-threat-model", action="store_true")
    args = parser.parse_args()
    try:
        if args.describe_threat_model:
            sys.stdout.buffer.write(
                _json_bytes(describe_threat_model(args.scan_dir, args.schema_dir))
            )
            return 0
        if args.write_threat_model:
            write_threat_model_projection_if_possible(args.scan_dir)
            return 0
        if args.export_artifact == "threat-model" and args.export_format is None:
            args.export_format = "md"
        if args.export_metadata and (
            args.export_artifact != "threat-model" or args.export_output is None
        ):
            parser.error("--export-metadata requires a threat-model export with --export-output")
        if args.sarif_only and args.export_format is not None:
            parser.error("--sarif-only cannot be combined with --export-format")
        if args.export_output is not None and args.export_format is None:
            parser.error("--export-output requires --export-format")
        if args.sarif_output is not None and not args.sarif_only:
            parser.error("--sarif-output requires --sarif-only")
        if args.sarif_only:
            args.export_format, args.export_output = "sarif", args.sarif_output
        if args.export_format is not None:
            if args.export_artifact == "threat-model":
                if args.export_format != "md":
                    parser.error("threat-model exports require --export-format md")
                if args.source_root is not None:
                    parser.error("source-root is only supported for SARIF exports")
                saved = _read_saved_threat_model(args.scan_dir, schema_dir=args.schema_dir)
                if saved is None:
                    raise ContractError("No saved threat model is available for this result.")
                description, contents = saved
            else:
                contents = build_findings_export(
                    args.scan_dir, args.export_format, args.source_root, args.schema_dir
                )
            if args.export_output is None:
                sys.stdout.buffer.write(contents)
            else:
                write_export_output(args.scan_dir, args.export_output, args.export_format, contents)
                if args.export_metadata:
                    sys.stdout.buffer.write(
                        _json_bytes({**description, "path": str(args.export_output.absolute())})
                    )
        else:
            finalize_scan(args.scan_dir, args.schema_dir, args.source_root)
    except ContractError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
