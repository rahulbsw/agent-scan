from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low"]
Confidence = Literal["high", "medium", "low"]
ComponentType = Literal["mcp", "skill", "all"]


@dataclass(frozen=True)
class RuleDefinition:
    code: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    component_types: tuple[ComponentType, ...]
    source_references: tuple[str, ...]
    false_positive_rationale: str


RULES: dict[str, RuleDefinition] = {
    "W001": RuleDefinition(
        code="W001",
        title="Suspicious words in tool description",
        category="prompt-injection",
        severity="low",
        confidence="medium",
        component_types=("mcp",),
        source_references=(
            "OWASP LLM01:2025 Prompt Injection",
            "OWASP MCP Security Cheat Sheet - Tool Description and Schema Integrity",
        ),
        false_positive_rationale="Legitimate tools can use urgent language; review with surrounding evidence.",
    ),
    "W008": RuleDefinition(
        code="W008",
        title="Hardcoded or embedded secret marker in skill",
        category="sensitive-information",
        severity="high",
        confidence="high",
        component_types=("skill",),
        source_references=(
            "OWASP LLM02:2025 Sensitive Information Disclosure",
            "NIST SSDF PW.4",
        ),
        false_positive_rationale="Synthetic fixtures can intentionally include redacted markers.",
    ),
    "W012": RuleDefinition(
        code="W012",
        title="Unverifiable external dependency",
        category="supply-chain",
        severity="high",
        confidence="high",
        component_types=("skill",),
        source_references=(
            "OWASP LLM03:2025 Supply Chain",
            "OWASP MCP Security Cheat Sheet - Supply Chain Security",
        ),
        false_positive_rationale="Trusted documentation links are acceptable when they do not control runtime behavior.",
    ),
    "W015": RuleDefinition(
        code="W015",
        title="Untrusted content exposure",
        category="indirect-prompt-injection",
        severity="medium",
        confidence="medium",
        component_types=("mcp", "skill"),
        source_references=(
            "OWASP LLM01:2025 Prompt Injection",
            "MCP specification - Data Privacy and Tool Safety",
        ),
        false_positive_rationale="Some public-content tools are expected; pair this signal with data access and sink labels.",
    ),
    "W017": RuleDefinition(
        code="W017",
        title="Sensitive data exposure",
        category="sensitive-information",
        severity="medium",
        confidence="medium",
        component_types=("mcp", "skill"),
        source_references=(
            "OWASP LLM02:2025 Sensitive Information Disclosure",
            "NIST AI RMF Generative AI Profile",
        ),
        false_positive_rationale="The tool may be intentionally scoped to read sensitive data with proper controls.",
    ),
    "W018": RuleDefinition(
        code="W018",
        title="Workspace data exposure",
        category="sensitive-information",
        severity="low",
        confidence="medium",
        component_types=("mcp", "skill"),
        source_references=(
            "OWASP LLM02:2025 Sensitive Information Disclosure",
            "MCP specification - Data Privacy",
        ),
        false_positive_rationale="Workspace readers are common in coding agents; validate least privilege.",
    ),
    "W019": RuleDefinition(
        code="W019",
        title="Shared destructive capability",
        category="excessive-agency",
        severity="medium",
        confidence="medium",
        component_types=("mcp", "skill"),
        source_references=(
            "OWASP MCP Security Cheat Sheet - Human-in-the-Loop for Sensitive Actions",
            "MCP specification - Tool Safety",
        ),
        false_positive_rationale="Some administrative tools are legitimate when approval and audit controls exist.",
    ),
    "W020": RuleDefinition(
        code="W020",
        title="Local destructive capability",
        category="excessive-agency",
        severity="low",
        confidence="medium",
        component_types=("mcp", "skill"),
        source_references=(
            "OWASP MCP Security Cheat Sheet - Sandbox and Isolate MCP Servers",
            "MCP security best practices - Local MCP Server Compromise",
        ),
        false_positive_rationale="Local file modification may be expected for developer tools.",
    ),
    "W021": RuleDefinition(
        code="W021",
        title="Hidden Unicode characters",
        category="obfuscation",
        severity="medium",
        confidence="high",
        component_types=("mcp", "skill"),
        source_references=(
            "OWASP LLM01:2025 Prompt Injection",
            "OWASP MCP Security Cheat Sheet - Input and Output Validation",
        ),
        false_positive_rationale="Some languages and copied text can contain invisible formatting unintentionally.",
    ),
    "W022": RuleDefinition(
        code="W022",
        title="Suspicious MCP startup command",
        category="supply-chain",
        severity="high",
        confidence="high",
        component_types=("mcp",),
        source_references=(
            "MCP security best practices - Local MCP Server Compromise",
            "OWASP MCP Security Cheat Sheet - Consent and Installation Security",
            "OWASP LLM03:2025 Supply Chain",
        ),
        false_positive_rationale="Installer-style commands can be legitimate during setup but should not be hidden in MCP config.",
    ),
    "W023": RuleDefinition(
        code="W023",
        title="Cross-server influence instruction",
        category="tool-poisoning",
        severity="medium",
        confidence="high",
        component_types=("mcp",),
        source_references=(
            "OWASP MCP Security Cheat Sheet - Tool Poisoning and Tool Shadowing",
            "MCP security best practices - Tool Poisoning",
            "OWASP LLM01:2025 Prompt Injection",
        ),
        false_positive_rationale="Some orchestrator tools legitimately route between servers; verify that routing is explicit and user-approved.",
    ),
}


def issue_extra(
    code: str, *, severity: Severity | None = None, evidence: dict[str, Any] | None = None
) -> dict[str, Any]:
    rule = RULES[code]
    return {
        "severity": severity or rule.severity,
        "confidence": rule.confidence,
        "rule_title": rule.title,
        "category": rule.category,
        "evidence": evidence or {},
        "source_references": list(rule.source_references),
        "false_positive_rationale": rule.false_positive_rationale,
    }
