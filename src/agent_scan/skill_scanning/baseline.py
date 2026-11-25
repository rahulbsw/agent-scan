from __future__ import annotations

import json
import os
import stat
from datetime import date, datetime, timezone
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from pathlib import Path

    from agent_scan.skill_scanning.models import Report

_MAX_BYTES = 1_048_576


class Acceptance(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    reason: str = Field(min_length=1, max_length=1024)
    owner: str = Field(min_length=1, max_length=256)
    expires: date


class Baseline(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["oas.baseline/v1"] = "oas.baseline/v1"
    profile: Literal["passive-text-v1"] = "passive-text-v1"
    acceptances: list[Acceptance] = Field(max_length=10_000)


def load_baseline(path: Path) -> Baseline:
    fd = os.open(path.expanduser(), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Baseline must be a regular file")
        data = stream.read(_MAX_BYTES + 1)
    if len(data) > _MAX_BYTES:
        raise ValueError("Baseline exceeds byte limit")
    baseline = Baseline.model_validate_json(data)
    fingerprints = [item.fingerprint for item in baseline.acceptances]
    if len(set(fingerprints)) != len(fingerprints):
        raise ValueError("Baseline contains duplicate fingerprints")
    if any(not item.reason.strip() or not item.owner.strip() for item in baseline.acceptances):
        raise ValueError("Baseline reason and owner must not be blank")
    return baseline


def apply_baseline(report: Report, baseline: Baseline, *, today: date | None = None) -> None:
    today = today or datetime.now(timezone.utc).date()
    accepted = {item.fingerprint: item for item in baseline.acceptances if item.expires >= today}
    for finding in report.findings:
        if finding.fingerprint in accepted:
            item = accepted[finding.fingerprint]
            finding.suppression = {"reason": item.reason, "owner": item.owner, "expires": item.expires.isoformat()}


def write_baseline(report: Report, path: Path, *, reason: str, owner: str, expires: date) -> None:
    if not report.execution_successful or report.coverage.status != "complete":
        raise ValueError("Cannot accept findings from an incomplete or failed scan")
    if expires < datetime.now(timezone.utc).date():
        raise ValueError("Baseline expiry must not be in the past")
    baseline = Baseline(
        acceptances=[
            Acceptance(fingerprint=finding.fingerprint, reason=reason, owner=owner, expires=expires)
            for finding in report.findings
        ]
    )
    # Validate metadata even when there are no findings.
    Acceptance(fingerprint="0" * 64, reason=reason, owner=owner, expires=expires)
    if not reason.strip() or not owner.strip():
        raise ValueError("Baseline reason and owner must not be blank")
    data = json.dumps(baseline.model_dump(mode="json"), ensure_ascii=True, indent=2).encode() + b"\n"
    if len(data) > _MAX_BYTES:
        raise ValueError("Baseline exceeds byte limit")
    # New files only; never truncate a previous review or follow an output symlink.
    fd = os.open(path.expanduser(), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
