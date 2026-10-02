from __future__ import annotations

import re
import unicodedata
from typing import TYPE_CHECKING, Any

from mcp.types import Prompt, Resource, ResourceTemplate, Tool

from agent_scan.models import (
    InspectedPath,
    InspectedServer,
    InspectedSkill,
    McpEntitySummary,
    McpServerRiskIndexes,
    McpServerRiskResponse,
    Region,
    RiskScore,
    ScanPathResponse,
    ScanResponse,
    SkillFileSummary,
    SkillRiskIndexes,
    SkillRiskResponse,
    SkillRiskScore,
    StdioServer,
    UnverifiableURLSkillRiskScore,
)

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


def analyze_locally(inspected_paths: list[InspectedPath]) -> ScanResponse:
    """Apply deterministic local checks and return the v2026 scan response shape."""
    return ScanResponse(scan_path_responses=[_analyze_path(path) for path in inspected_paths])


def _analyze_path(path: InspectedPath) -> ScanPathResponse:
    server_names = [server.name for server in path.servers]
    return ScanPathResponse(
        client=path.client,
        path=path.path,
        server_risks=[
            _analyze_server(server, _other_server_names(server_names, index))
            for index, server in enumerate(path.servers)
        ],
        skill_risks=[_analyze_skill(skill) for skill in path.skills],
        error=path.error.model_copy(deep=True) if path.error else None,
    )


def _analyze_server(server: InspectedServer, other_server_names: list[str]) -> McpServerRiskResponse:
    risk_indexes = McpServerRiskIndexes()
    affected_prompt_tools: list[int] = []
    prompt_evidence: list[str] = []
    untrusted_evidence: list[str] = []
    private_evidence: list[str] = []
    destructive_evidence: list[str] = []

    if isinstance(server.server, StdioServer):
        startup_evidence = _suspicious_startup_evidence(server.server)
        if startup_evidence is not None:
            destructive_evidence.append(
                "Suspicious startup command: " + ", ".join(startup_evidence["reasons"])
            )

    entities = server.signature.entities if server.signature is not None else []
    for index, entity in enumerate(entities):
        text = _entity_text(entity)
        if isinstance(entity, Tool):
            suspicious_words = _suspicious_words(text)
            if suspicious_words:
                affected_prompt_tools.append(index)
                prompt_evidence.append(f"{entity.name}: {', '.join(suspicious_words)}")

        cross_server_references = _cross_server_references(text, other_server_names)
        if cross_server_references:
            affected_prompt_tools.append(index)
            prompt_evidence.append(f"{entity.name}: references {', '.join(cross_server_references)}")

        if _UNTRUSTED_CONTENT_RE.search(text) or _URL_RE.search(text):
            untrusted_evidence.append(getattr(entity, "name", "component"))
        if _PRIVATE_DATA_RE.search(text) or _WORKSPACE_DATA_RE.search(text):
            private_evidence.append(getattr(entity, "name", "component"))
        if _DESTRUCTIVE_RE.search(text):
            shared = "shared " if _SHARED_DESTRUCTIVE_RE.search(text) else ""
            destructive_evidence.append(f"{getattr(entity, 'name', 'component')}: {shared}destructive capability")

    if prompt_evidence:
        risk_indexes.prompt_injection_tool_desc = RiskScore(
            score=650,
            evidence="; ".join(_dedupe(prompt_evidence)),
            affected_tools=sorted(set(affected_prompt_tools)) or None,
        )
    if untrusted_evidence:
        risk_indexes.untrusted_content = RiskScore(
            score=450,
            evidence="References external or untrusted content: " + ", ".join(_dedupe(untrusted_evidence)),
        )
    if private_evidence:
        risk_indexes.private_data = RiskScore(
            score=450,
            evidence="References sensitive or workspace data: " + ", ".join(_dedupe(private_evidence)),
        )
    if destructive_evidence:
        risk_indexes.destructive_capabilities = RiskScore(
            score=650,
            evidence="; ".join(_dedupe(destructive_evidence)),
        )

    return McpServerRiskResponse(
        name=server.name,
        entities=[_entity_summary(entity) for entity in entities],
        risk_indexes=risk_indexes,
        error=server.error.model_copy(deep=True) if server.error else None,
    )


def _analyze_skill(skill: InspectedSkill) -> SkillRiskResponse:
    risk_indexes = SkillRiskIndexes()
    prompt_evidence: list[str] = []
    external_urls: list[str] = []
    secret_locations: list[Region] = []
    malicious_evidence: list[str] = []

    for skill_file in skill.files:
        text = skill_file.content
        hidden = _hidden_unicode_names(text)
        if hidden:
            prompt_evidence.append(f"{skill_file.path}: hidden characters {', '.join(hidden)}")
        if _suspicious_words(text):
            prompt_evidence.append(f"{skill_file.path}: suspicious instruction language")
        if _REDACTED_SECRET_RE.search(text):
            secret_locations.append(_region(skill_file.path))
        if _has_external_dependency(text):
            external_urls.extend(_URL_RE.findall(text))
        if _ENCODED_PAYLOAD_RE.search(text) or _SHELL_PIPE_EXEC_RE.search(text):
            malicious_evidence.append(f"{skill_file.path}: suspicious shell or encoded payload pattern")

    if prompt_evidence:
        risk_indexes.prompt_injection_skill_instructions = SkillRiskScore(
            score=600,
            evidence="; ".join(_dedupe(prompt_evidence)),
        )
    if secret_locations:
        risk_indexes.secret_detection = SkillRiskScore(
            score=750,
            evidence="Redacted secret markers found in skill content.",
            locations=secret_locations,
        )
    if external_urls:
        risk_indexes.unverifiable_dependencies = UnverifiableURLSkillRiskScore(
            score=700,
            evidence="Skill content depends on code or instructions fetched from external URLs.",
            unverifiable_urls=sorted(set(external_urls)),
        )
    if malicious_evidence:
        risk_indexes.malicious_code = SkillRiskScore(score=750, evidence="; ".join(_dedupe(malicious_evidence)))

    return SkillRiskResponse(
        name=skill.name,
        files=[_skill_file_summary(file.path) for file in skill.files],
        risk_indexes=risk_indexes,
        error=skill.error.model_copy(deep=True) if skill.error else None,
    )


def _entity_summary(entity: Tool | Prompt | Resource | ResourceTemplate) -> McpEntitySummary:
    if isinstance(entity, Tool):
        entity_type = "tool"
    elif isinstance(entity, Prompt):
        entity_type = "prompt"
    elif isinstance(entity, Resource):
        entity_type = "resource"
    elif isinstance(entity, ResourceTemplate):
        entity_type = "resource_template"
    else:
        raise ValueError(f"Unknown entity type: {type(entity)}")
    return McpEntitySummary(name=entity.name, type=entity_type)


def _skill_file_summary(path: str) -> SkillFileSummary:
    lowered = path.lower()
    if lowered.endswith(".md"):
        file_type = "instruction"
    elif lowered.rsplit(".", 1)[-1] in ("py", "js", "ts", "sh"):
        file_type = "script"
    else:
        file_type = "asset"
    return SkillFileSummary(name=path, type=file_type)


def _region(path: str) -> Region:
    return Region(start={"path": path})


def _entity_text(entity: Tool | Prompt | Resource | ResourceTemplate) -> str:
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


def _dedupe(values: Iterable[str]) -> list[str]:
    seen = set()
    deduped = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped
