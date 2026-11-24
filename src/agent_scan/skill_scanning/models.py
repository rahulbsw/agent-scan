from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, Field

from agent_scan.rules import Confidence, Severity  # noqa: TC001 - Pydantic resolves annotations at runtime.


@dataclass(frozen=True)
class Limits:
    max_entries: int = 10_000
    max_depth: int = 32
    max_file_bytes: int = 1_048_576
    max_total_bytes: int = 33_554_432
    max_findings: int = 10_000
    max_seconds: float = 30.0

    def __post_init__(self):
        import math

        for name, value in self.__dict__.items():
            valid_type = type(value) in (int, float) if name == "max_seconds" else type(value) is int
            if not valid_type or value <= 0 or (isinstance(value, float) and not math.isfinite(value)):
                raise ValueError("Scan limits must be positive and finite")


class Limitation(BaseModel):
    path: str
    reason: str


class Coverage(BaseModel):
    status: Literal["complete", "partial", "failed"] = "complete"
    entries_seen: int = 0
    files_read: int = 0
    bytes_read: int = 0
    limitations: list[Limitation] = Field(default_factory=list)


class Artifact(BaseModel):
    path: str
    sha256: str
    size_bytes: int
    analysis: Literal["text", "unsupported"]


class Finding(BaseModel):
    rule_id: str
    rule_revision: str = "1"
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    experimental: bool = True
    path: str
    line: int
    column: int
    message: str
    remediation: str
    references: list[str]
    false_positive_rationale: str
    fingerprint: str
    suppression: dict[str, str] | None = None


class Report(BaseModel):
    schema_version: Literal["oas.skills/v1"] = "oas.skills/v1"
    profile: Literal["passive-text-v1"] = "passive-text-v1"
    scanner_version: str
    execution_successful: bool = True
    coverage: Coverage = Field(default_factory=Coverage)
    artifacts: list[Artifact] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Experimental text rules only; no code execution or behavioral verification.",
            "No dependency resolution, advisory lookup, archive expansion, or semantic analysis.",
            "Complete means the passive-text-v1 profile completed, not that the target is safe.",
        ]
    )
