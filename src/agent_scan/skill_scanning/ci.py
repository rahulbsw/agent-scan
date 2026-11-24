"""Single-pass passive scanning and report bundles for a read-only CI job."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING
from urllib.parse import quote

from agent_scan import __version__
from agent_scan.skill_scanning.analysis import scan_skills
from agent_scan.skill_scanning.html_report import html_document, text
from agent_scan.skill_scanning.models import Coverage, Limitation, Report
from agent_scan.skill_scanning.reporting import exit_code, render, sanitized, sarif

if TYPE_CHECKING:
    from typing import Any


def repository_sarif(report: Report, target: str, *, directory: bool) -> dict:
    """Map a scan-root-relative report onto the consuming repository, not scanner checkout."""
    result = sarif(report)
    prefix = PurePosixPath(target) if directory else PurePosixPath(target).parent
    encoded_prefix = quote(prefix.as_posix(), safe="/") + "/" if prefix.as_posix() != "." else ""
    for run in result["runs"]:
        run["automationDetails"] = {"id": f"open-agent-scan/{quote(target, safe='/')}/"}
        for finding in run["results"]:
            for location in finding["locations"]:
                artifact = location["physicalLocation"]["artifactLocation"]
                artifact["uri"] = encoded_prefix + artifact["uri"]
    return result


def _failed(reason: str) -> Report:
    return Report(
        scanner_version=__version__,
        execution_successful=False,
        coverage=Coverage(status="failed", limitations=[Limitation(path=".", reason=reason)]),
    )


def _write(path: Path, contents: str) -> None:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(contents)


def scan_repository(
    root: Path,
    reports: Path,
    targets: list[str],
    *,
    fail_on: str = "none",
    fail_on_incomplete: bool = True,
    include_sarif: bool = False,
) -> int:
    if not targets or len(targets) > 100 or len(set(targets)) != len(targets):
        raise ValueError("Supply between one and 100 distinct static targets")
    for target in targets:
        parts = PurePosixPath(target)
        if (
            len(target) > 256
            or parts.is_absolute()
            or parts.as_posix() != target
            or ".." in parts.parts
            or target == "."
            or "\\" in target
        ):
            raise ValueError("Targets must be normalized repository-relative paths")
    if fail_on not in ("none", "low", "medium", "high", "critical"):
        raise ValueError("Invalid finding threshold")
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Repository root must be a directory")
    reports = reports.expanduser().absolute()
    if reports.resolve().is_relative_to(root):
        raise ValueError("Report bundle must be outside the inspected repository")
    # A new output directory prevents stale files and author-controlled report links.
    reports.mkdir(parents=True, exist_ok=False)
    if include_sarif:
        (reports / "sarif").mkdir()
    rows: list[dict[str, Any]] = []
    status = 0
    scanned = 0
    for target in targets:
        candidate = root / target
        directory = False
        try:
            if not candidate.exists() and not candidate.is_symlink():
                rows.append(
                    {
                        "target": target,
                        "coverage": "not present",
                        "active": 0,
                        "suppressed": 0,
                        "highest": "none",
                        "exit": "skipped",
                        "html": None,
                    }
                )
                continue
            scanned += 1
            if not candidate.resolve().is_relative_to(root):
                report = _failed("target_outside_repository")
            else:
                directory = candidate.is_dir()
                report = scan_skills(candidate)
        except (OSError, ValueError, RuntimeError):
            report = _failed("unreadable_or_unsafe_target")
        code = exit_code(report, fail_on=fail_on, fail_on_incomplete=fail_on_incomplete)
        status = max(status, code)
        identifier = hashlib.sha256(target.encode()).hexdigest()[:24]
        _write(reports / f"{identifier}.json", render(report, "json") + "\n")
        _write(reports / f"{identifier}.html", render(report, "html"))
        if include_sarif and report.execution_successful and report.coverage.status == "complete":
            _write(
                reports / "sarif" / f"{identifier}.sarif",
                json.dumps(
                    repository_sarif(report, target, directory=directory),
                    ensure_ascii=True,
                    indent=2,
                )
                + "\n",
            )
        active = sum(finding.suppression is None for finding in report.findings)
        highest = max(
            (finding.severity for finding in report.findings if finding.suppression is None),
            key=("none", "low", "medium", "high", "critical").index,
            default="none",
        )
        rows.append(
            {
                "target": target,
                "coverage": report.coverage.status,
                "active": active,
                "suppressed": len(report.findings) - active,
                "highest": highest,
                "exit": code,
                "html": f"{identifier}.html",
            }
        )
    if scanned == 0:
        status = max(status, 1)
    rows = [{**row, "target": sanitized(row["target"])} for row in rows]
    table = (
        "<table><thead><tr><th>Target</th><th>Coverage</th><th>Active</th>"
        "<th>Suppressed</th><th>Highest severity</th><th>Exit</th></tr></thead><tbody>"
    )
    index_table = table
    labels = {
        "coverage": "Coverage",
        "active": "Active",
        "suppressed": "Suppressed",
        "highest": "Highest severity",
        "exit": "Exit",
    }
    for row in rows:
        cells = "".join(f'<td data-label="{labels[key]}">{text(row[key])}</td>' for key in labels)
        table += f'<tr><td data-label="Target">{text(row["target"])}</td>{cells}</tr>'
        label = f'<a href="{row["html"]}">{text(row["target"])}</a>' if row["html"] else text(row["target"])
        index_table += f'<tr><td data-label="Target">{label}</td>{cells}</tr>'
    table += "</tbody></table>"
    index_table += "</tbody></table>"
    policy = f"Finding threshold: {fail_on}. Incomplete coverage blocks: {fail_on_incomplete}."
    note = (
        f"Scanned {scanned} of {len(targets)} configured targets. Highest exit: {status}. "
        "No configured paths found; update the target list. "
        if not scanned
        else f"Scanned {scanned} of {len(targets)} configured targets. Highest exit: {status}. "
    )
    warning = "Experimental text checks only. No findings or complete profile coverage does not certify safety."
    _write(reports / "summary.md", f"## Open Agent Scan\n\n{note}\n\n{policy}\n\n{table}\n\n{warning}\n")
    _write(
        reports / "index.html",
        html_document(
            "Open Agent Scan repository report",
            f"<p>{text(note)}</p><p>{text(policy)}</p>{index_table}<p>{text(warning)}</p>",
        ),
    )
    _write(
        reports / "manifest.json",
        json.dumps(
            {
                "schema_version": "oas.ci/v1",
                "scanner_version": __version__,
                "scanned_targets": scanned,
                "exit_code": status,
                "targets": rows,
            },
            ensure_ascii=True,
            indent=2,
        )
        + "\n",
    )
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--reports", required=True, type=Path)
    parser.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="none")
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument("--sarif", action="store_true")
    parser.add_argument("targets", nargs="+")
    args = parser.parse_args()
    try:
        return scan_repository(
            args.root,
            args.reports,
            args.targets,
            fail_on=args.fail_on,
            fail_on_incomplete=not args.allow_incomplete,
            include_sarif=args.sarif,
        )
    except (OSError, ValueError):
        print("Report generation failed: invalid scope, existing output directory, or output write failure.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
