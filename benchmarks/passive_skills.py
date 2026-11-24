"""Reproducible local benchmark; run with `uv run benchmarks/passive_skills.py`."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import statistics
import tempfile
import time
from pathlib import Path

from agent_scan import __version__
from agent_scan.local_analysis import analyze_locally
from agent_scan.models import InspectedPath, SkillFile
from agent_scan.models.inspect import InspectedSkill
from agent_scan.skill_scanning.analysis import scan_skills
from agent_scan.skill_scanning.reporting import render


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skills", type=int, default=100)
    parser.add_argument("--bytes-per-skill", type=int, default=104_858)
    parser.add_argument("--repeats", type=int, default=10)
    args = parser.parse_args()
    if min(args.skills, args.bytes_per_skill, args.repeats) < 1:
        parser.error("Counts must be positive")
    content = ("Read selected files and ask for approval.\n" * (args.bytes_per_skill // 40 + 1))[: args.bytes_per_skill]
    corpus = hashlib.sha256()
    timings: dict[str, list[float]] = {"legacy_analysis_only": [], "passive_collect_analyze": [], "passive_json": []}
    inspected = []
    with tempfile.TemporaryDirectory(prefix="oas-benchmark-") as directory:
        root = Path(directory)
        for index in range(args.skills):
            name = f"skill-{index:05d}"
            path = root / name
            path.mkdir()
            (path / "SKILL.md").write_text(content, encoding="utf-8")
            corpus.update(f"{name}/SKILL.md\0".encode())
            corpus.update(content.encode())
            inspected.append(
                InspectedSkill(
                    name=name,
                    installation_path=name,
                    files=[SkillFile(path="SKILL.md", content=content)],
                )
            )
        legacy_input = [InspectedPath(path="benchmark", skills=inspected)]
        # Warm imports, filesystem caches, and the existing redactor before timing.
        analyze_locally(legacy_input)
        report = scan_skills(root)
        if not report.execution_successful or report.coverage.status != "complete":
            raise SystemExit("Benchmark requires complete passive-profile support and sufficient default limits")
        render(report, "json")
        for _ in range(args.repeats):
            started = time.perf_counter()
            analyze_locally(legacy_input)
            timings["legacy_analysis_only"].append(time.perf_counter() - started)
            started = time.perf_counter()
            report = scan_skills(root)
            timings["passive_collect_analyze"].append(time.perf_counter() - started)
            started = time.perf_counter()
            render(report, "json")
            timings["passive_json"].append(time.perf_counter() - started)
        peak_rss_bytes = None
        try:
            import resource

            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            peak_rss_bytes = rss if platform.system() == "Darwin" else rss * 1024
        except ImportError:
            pass
        print(
            json.dumps(
                {
                    "scanner_version": __version__,
                    "python": platform.python_version(),
                    "platform": platform.platform(),
                    "corpus_sha256": corpus.hexdigest(),
                    "skills": args.skills,
                    "bytes": args.skills * len(content.encode()),
                    "repeats": args.repeats,
                    "peak_process_rss_bytes": peak_rss_bytes,
                    "timings_seconds": {
                        name: {
                            "median": statistics.median(values),
                            "p95": sorted(values)[math.ceil(len(values) * 0.95) - 1],
                        }
                        for name, values in timings.items()
                    },
                    "notes": [
                        "Synthetic original benign corpus, not a detector-accuracy benchmark.",
                        "Warm process only; cold CLI startup not measured.",
                        "Legacy excludes collection; profiles perform different work. Do not interpret their ratio as regression.",
                        "Peak RSS is the entire benchmark process, including both profiles and corpus preparation.",
                    ],
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
