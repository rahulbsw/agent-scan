from __future__ import annotations

import re
import unicodedata
from typing import TYPE_CHECKING, Any

from mcp.types import Tool

from agent_scan.models import Entity, Issue, ScalarToolLabels, ScanPathResult, ServerScanResult, SkillServer

if TYPE_CHECKING:
    from collections.abc import Iterable

_SUSPICIOUS_WORDS = {
    "important",
    "crucial",
    "critical",
    "urgent",
    "ignore",
    "disregard",
    "override",
    "bypass",
}
_SUSPICIOUS_PHRASES = (
    "previous instructions",
    "system prompt",
    "developer message",
    "hidden instruction",
)

_DESTRUCTIVE_RE = re.compile(
    r"\b(delete|remove|rm|erase|destroy|overwrite|modify|write|execute|exec|shell|command|run|sudo|chmod|chown)\b",
    re.IGNORECASE,
)
_SHARED_DESTRUCTIVE_RE = re.compile(
    r"\b(production|deploy|terraform|kubernetes|kubectl|aws|gcp|azure|github|jira|database|payment|stripe|browser)\b",
    re.IGNORECASE,
)
_PRIVATE_DATA_RE = re.compile(
    r"\b(secret|credential|token|api[_ -]?key|password|vault|email|gmail|slack|private|financial|bank)\b",
    re.IGNORECASE,
)
_WORKSPACE_DATA_RE = re.compile(r"\b(workspace|repository|repo|source code|local file|project file)\b", re.IGNORECASE)
_UNTRUSTED_CONTENT_RE = re.compile(
    r"\b(url|web|website|internet|browser|fetch|download|social|comment|issue|pull request|user content|rss)\b",
    re.IGNORECASE,
)
_PUBLIC_SINK_RE = re.compile(r"\b(upload|post|send|publish|http|https|webhook|exfiltrate)\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s)>\]\"']+", re.IGNORECASE)
_EXECUTABLE_URL_RE = re.compile(r"https?://[^\s)>\]\"']+\.(?:sh|bash|py|js|ts|ps1|zip|tar|tgz|gz)", re.IGNORECASE)
_REMOTE_EXEC_RE = re.compile(r"\b(curl|wget|download|source|bash|sh|python|node|install|execute|run)\b", re.IGNORECASE)
_REDACTED_SECRET_RE = re.compile(r"\*\*REDACTED(?:_SECRET_[A-Z0-9_]+)?\*\*")


def analyze_locally(scan_path_results: list[ScanPathResult]) -> list[ScanPathResult]:
    """Apply high-confidence local checks to inspected MCP servers and skills."""
    for result in scan_path_results:
        result.issues = list(result.issues)
        result.labels = []
        for server_index, server in enumerate(result.servers or []):
            server_labels: list[ScalarToolLabels] = []
            for entity_index, entity in enumerate(server.entities):
                text = _entity_text(entity)
                label = _label_text(text)
                server_labels.append(label)
                result.issues.extend(_issues_for_entity(server, entity, text, label, server_index, entity_index))
            result.labels.append(server_labels)
    return scan_path_results


def _issues_for_entity(
    server: ServerScanResult,
    entity: Entity,
    text: str,
    label: ScalarToolLabels,
    server_index: int,
    entity_index: int,
) -> list[Issue]:
    reference = (server_index, entity_index)
    issues: list[Issue] = []
    hidden = _hidden_unicode_names(text)
    is_skill = isinstance(server.server, SkillServer)

    if hidden:
        issues.append(
            Issue(
                code="W021",
                message="Hidden or invisible Unicode characters detected in component text.",
                reference=reference,
                extra_data={"severity": "medium", "characters": hidden},
            )
        )

    if is_skill and _REDACTED_SECRET_RE.search(text):
        issues.append(
            Issue(
                code="W008",
                message="Sensitive credentials appear to be embedded in this skill.",
                reference=reference,
                extra_data={"severity": "high"},
            )
        )

    if is_skill and _has_external_dependency(text):
        issues.append(
            Issue(
                code="W012",
                message="Skill content depends on code or instructions fetched from an external URL.",
                reference=reference,
                extra_data={"severity": "high"},
            )
        )

    if not is_skill and isinstance(entity, Tool):
        suspicious_words = _suspicious_words(text)
        if suspicious_words:
            issues.append(
                Issue(
                    code="W001",
                    message="Suspicious words in tool description.",
                    reference=reference,
                    extra_data={"severity": "low", "words": suspicious_words},
                )
            )

    if label.private_data:
        issues.append(
            Issue(
                code="W017" if _PRIVATE_DATA_RE.search(text) else "W018",
                message="Sensitive or workspace data exposure detected.",
                reference=reference,
                extra_data={"severity": "medium" if _PRIVATE_DATA_RE.search(text) else "low"},
            )
        )

    if label.untrusted_content:
        issues.append(
            Issue(
                code="W015",
                message="Untrusted content exposure detected.",
                reference=reference,
                extra_data={"severity": "medium"},
            )
        )

    if label.destructive:
        shared = bool(_SHARED_DESTRUCTIVE_RE.search(text))
        issues.append(
            Issue(
                code="W019" if shared else "W020",
                message="Destructive capability detected.",
                reference=reference,
                extra_data={"severity": "medium" if shared else "low"},
            )
        )

    return _dedupe_issues(issues)


def _label_text(text: str) -> ScalarToolLabels:
    return ScalarToolLabels(
        is_public_sink=1 if _PUBLIC_SINK_RE.search(text) else 0,
        destructive=1 if _DESTRUCTIVE_RE.search(text) else 0,
        untrusted_content=1 if _UNTRUSTED_CONTENT_RE.search(text) or _URL_RE.search(text) else 0,
        private_data=1 if _PRIVATE_DATA_RE.search(text) or _WORKSPACE_DATA_RE.search(text) else 0,
    )


def _entity_text(entity: Entity) -> str:
    parts = [getattr(entity, "name", "")]
    description = getattr(entity, "description", None)
    if description:
        parts.append(description)
    input_schema: Any = getattr(entity, "inputSchema", None)
    if input_schema:
        parts.append(str(input_schema))
    return "\n".join(parts)


def _hidden_unicode_names(text: str) -> list[str]:
    hidden = []
    for char in text:
        if char in "\n\r\t":
            continue
        if unicodedata.category(char) in {"Cf", "Cc"}:
            hidden.append(unicodedata.name(char, f"U+{ord(char):04X}"))
    return sorted(set(hidden))


def _suspicious_words(text: str) -> list[str]:
    lowered = text.lower()
    words = {word for word in _SUSPICIOUS_WORDS if re.search(rf"\b{re.escape(word)}\b", lowered)}
    for phrase in _SUSPICIOUS_PHRASES:
        if phrase in lowered:
            words.add(phrase)
    return sorted(words)


def _has_external_dependency(text: str) -> bool:
    return bool(_EXECUTABLE_URL_RE.search(text) or (_URL_RE.search(text) and _REMOTE_EXEC_RE.search(text)))


def _dedupe_issues(issues: Iterable[Issue]) -> list[Issue]:
    seen = set()
    deduped = []
    for issue in issues:
        key = (issue.code, issue.reference)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(issue)
    return deduped
