from __future__ import annotations

import sys
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING

from agent_scan.skill_scanning.analysis import scan_skills
from agent_scan.skill_scanning.baseline import apply_baseline, load_baseline, write_baseline
from agent_scan.skill_scanning.models import Limits
from agent_scan.skill_scanning.reporting import exit_code, render

if TYPE_CHECKING:
    import argparse


def add_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "skills",
        allow_abbrev=False,
        help="Passively scan an explicit local skill path; no MCP execution or network access",
        description="Experimental bounded text checks on a local file or directory. No discovery, services or execution.",
    )
    parser.add_argument("path", type=Path)
    parser.add_argument("--format", choices=["terminal", "json", "sarif"], default="terminal")
    parser.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="none")
    parser.add_argument("--fail-on-incomplete", action="store_true")
    baseline = parser.add_mutually_exclusive_group()
    baseline.add_argument("--baseline", type=Path, help="Caller-selected JSON acceptance file")
    baseline.add_argument("--write-baseline", type=Path, help="Create a new acceptance file outside the scan target")
    parser.add_argument("--baseline-reason")
    parser.add_argument("--baseline-owner")
    parser.add_argument("--baseline-expires", type=date.fromisoformat, metavar="YYYY-MM-DD")
    defaults = Limits()
    for name in ("max_entries", "max_depth", "max_file_bytes", "max_total_bytes", "max_findings", "max_seconds"):
        parser.add_argument(
            "--" + name.replace("_", "-"),
            type=float if name == "max_seconds" else int,
            default=getattr(defaults, name),
        )


def run(args: argparse.Namespace) -> int:
    try:
        limits = Limits(**{name: getattr(args, name) for name in Limits.__dataclass_fields__})
        baseline = load_baseline(args.baseline) if args.baseline else None
        if args.write_baseline:
            if not all((args.baseline_reason, args.baseline_owner, args.baseline_expires)):
                raise ValueError("Baseline creation requires reason, owner and expiry")
            root = args.path.expanduser().resolve()
            output = args.write_baseline.expanduser().resolve()
            if output == root or output.is_relative_to(root):
                raise ValueError("Write the baseline outside the scanned target")
        elif any((args.baseline_reason, args.baseline_owner, args.baseline_expires)):
            raise ValueError("Baseline metadata requires --write-baseline")
        report = scan_skills(
            args.path,
            limits,
            exclude=args.baseline.expanduser().absolute() if args.baseline else None,
        )
        if baseline:
            apply_baseline(report, baseline)
        if args.write_baseline:
            write_baseline(
                report,
                args.write_baseline,
                reason=args.baseline_reason,
                owner=args.baseline_owner,
                expires=args.baseline_expires,
            )
    except (OSError, ValueError):
        # Exception text can contain source data, secrets, control characters or paths.
        print(
            "Passive scan failed: invalid input, limits, baseline, or output. No acceptance was applied.",
            file=sys.stderr,
        )
        return 2
    print(render(report, args.format))
    return exit_code(report, fail_on=args.fail_on, fail_on_incomplete=args.fail_on_incomplete)
