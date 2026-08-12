from __future__ import annotations

import re
import unicodedata
from typing import TYPE_CHECKING, Any

from mcp.types import Tool

from agent_scan.models import (
    Entity,
    Issue,
    ScalarToolLabels,
    ScanPathResult,
    ServerScanResult,
    SkillServer,
    StdioServer,
)
from agent_scan.rules import issue_extra

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
_SHELL_PIPE_EXEC_RE = re.compile(
    r"\b(curl|wget)\b[^|;&]*(?:\||;|&&)\s*(?:sudo\s+)?(?:bash|sh|zsh|python|node)\b", re.IGNORECASE
)
_ENCODED_PAYLOAD_RE = re.compile(r"\b(base64\s+-d|frombase64string|certutil\s+-decode)\b", re.IGNORECASE)
_REMOTE_SCRIPT_RE = re.compile(r"https?://[^\s)>\]\"']+\.(?:sh|bash|ps1|py|js)(?:\?[^\s)>\]\"']*)?", re.IGNORECASE)
_SHELL_COMMANDS = {"bash", "sh", "zsh", "fish", "pwsh", "powershell", "cmd"}
_PACKAGE_RUNNERS = {"npx", "uvx"}


def analyze_locally(scan_path_results: list[ScanPathResult]) -> list[ScanPathResult]:
    """Apply high-confidence local checks to inspected MCP servers and skills."""
    for result in scan_path_results:
        result.issues = list(result.issues)
        result.labels = []
        servers = result.servers or []
        server_names = [server.name for server in servers]
        for server_index, server in enumerate(servers):
            server_labels: list[ScalarToolLabels] = []
            result.issues.extend(_issues_for_server(server, server_index))
            other_server_names = _other_server_names(server_names, server_index)
            for entity_index, entity in enumerate(server.entities):
                text = _entity_text(entity)
                label = _label_text(text)
                server_labels.append(label)
                result.issues.extend(
                    _issues_for_entity(
                        server,
                        entity,
                        text,
                        label,
                        server_index,
                        entity_index,
                        other_server_names=other_server_names,
                    )
                )
            result.labels.append(server_labels)
    return scan_path_results


def _issues_for_server(server: ServerScanResult, server_index: int) -> list[Issue]:
    if not isinstance(server.server, StdioServer):
        return []
    evidence = _suspicious_startup_evidence(server.server)
    if evidence is None:
        return []
    return [
        Issue(
            code="W022",
            message="Suspicious MCP startup command detected.",
            reference=(server_index, None),
            extra_data=issue_extra("W022", severity=evidence["severity"], evidence=_without_severity(evidence)),
        )
    ]


def _issues_for_entity(
    server: ServerScanResult,
    entity: Entity,
    text: str,
    label: ScalarToolLabels,
    server_index: int,
    entity_index: int,
    *,
    other_server_names: list[str],
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
                extra_data=issue_extra("W021", evidence={"characters": hidden}),
            )
        )

    if is_skill and _REDACTED_SECRET_RE.search(text):
        issues.append(
            Issue(
                code="W008",
                message="Sensitive credentials appear to be embedded in this skill.",
                reference=reference,
                extra_data=issue_extra("W008"),
            )
        )

    if is_skill and _has_external_dependency(text):
        issues.append(
            Issue(
                code="W012",
                message="Skill content depends on code or instructions fetched from an external URL.",
                reference=reference,
                extra_data=issue_extra("W012"),
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
                    extra_data=issue_extra("W001", evidence={"words": suspicious_words}),
                )
            )

    cross_server_references = _cross_server_references(text, other_server_names)
    if not is_skill and cross_server_references:
        issues.append(
            Issue(
                code="W023",
                message="Component text appears to influence another MCP server.",
                reference=reference,
                extra_data=issue_extra("W023", evidence={"referenced_servers": cross_server_references}),
            )
        )

    if label.private_data:
        issues.append(
            Issue(
                code="W017" if _PRIVATE_DATA_RE.search(text) else "W018",
                message="Sensitive or workspace data exposure detected.",
                reference=reference,
                extra_data=issue_extra("W017" if _PRIVATE_DATA_RE.search(text) else "W018"),
            )
        )

    if label.untrusted_content:
        issues.append(
            Issue(
                code="W015",
                message="Untrusted content exposure detected.",
                reference=reference,
                extra_data=issue_extra("W015"),
            )
        )

    if label.destructive:
        shared = bool(_SHARED_DESTRUCTIVE_RE.search(text))
        issues.append(
            Issue(
                code="W019" if shared else "W020",
                message="Destructive capability detected.",
                reference=reference,
                extra_data=issue_extra("W019" if shared else "W020"),
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


def _other_server_names(server_names: list[str | None], current_index: int) -> list[str]:
    return sorted(
        {name for index, name in enumerate(server_names) if index != current_index and name and len(name.strip()) >= 4}
    )


def _cross_server_references(text: str, other_server_names: list[str]) -> list[str]:
    references = set()
    for name in other_server_names:
        escaped = re.escape(name)
        name_first = rf"\b{escaped}\b.{{0,40}}\b(?:server|tool|mcp)\b"
        action_first = rf"\b(?:use|call|invoke|delegate to|ask)\b.{{0,60}}\b{escaped}\b"
        if re.search(name_first, text, re.IGNORECASE | re.DOTALL) or re.search(
            action_first, text, re.IGNORECASE | re.DOTALL
        ):
            references.add(name)
    return sorted(references)


def _has_external_dependency(text: str) -> bool:
    return bool(_EXECUTABLE_URL_RE.search(text) or (_URL_RE.search(text) and _REMOTE_EXEC_RE.search(text)))


def _suspicious_startup_evidence(server: StdioServer) -> dict[str, Any] | None:
    command = server.command.lower()
    command_text = _startup_command_text(server)
    reasons: list[str] = []
    severity = "medium"

    if _SHELL_PIPE_EXEC_RE.search(command_text):
        reasons.append("downloaded-content-piped-to-interpreter")
        severity = "high"
    if _ENCODED_PAYLOAD_RE.search(command_text):
        reasons.append("encoded-payload-decoding")
        severity = "high"
    if _REMOTE_SCRIPT_RE.search(command_text) and command in _SHELL_COMMANDS:
        reasons.append("shell-launches-remote-script")
        severity = "high"
    if command in _PACKAGE_RUNNERS and _first_package_argument(server.args) is not None:
        package = _first_package_argument(server.args)
        if package and _is_unpinned_package(package):
            reasons.append(f"unpinned-{command}-package")

    if not reasons:
        return None
    return {
        "severity": severity,
        "command": command,
        "reasons": sorted(set(reasons)),
    }


def _without_severity(evidence: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in evidence.items() if key != "severity"}


def _startup_command_text(server: StdioServer) -> str:
    return " ".join([server.command, *(server.args or [])])


def _first_package_argument(args: list[str]) -> str | None:
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in {"-c", "--cache", "--cwd", "--directory", "--from", "--index-url", "--python", "--with"}:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None


def _is_unpinned_package(package: str) -> bool:
    if "://" in package or package.startswith((".", "/", "~")):
        return False
    if "@" not in package:
        return True
    if package.startswith("@"):
        return package.count("@") == 1
    return package.endswith("@latest")


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
