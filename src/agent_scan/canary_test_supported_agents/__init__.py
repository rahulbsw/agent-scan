"""Live-test ("canary") specs co-located with the discoverers.

For each ``AgentDiscoverer`` there is an :class:`~agent_scan.canary_test_supported_agents.base.AgentCanary` that declares one
:class:`~agent_scan.canary_test_supported_agents.base.Scope` per scope-producing ``_discover_*`` method — how to drive the real
agent binary to write that scope and what ``inspect`` must then detect. The specs are declarative and
runner-agnostic; an external executor (the agent-scan-backoffice canary) imports :data:`CANARIES` and
runs the commands against the real binary in an isolated home. Because the canary lives in the same repo
as the discoverers, it cannot drift from them — ``tests/unit/test_canary_covers_scopes.py`` enforces that
every scope-producing method has a canary scope.
"""

from agent_scan.canary_test_supported_agents.base import (
    AgentCanary,
    CanaryContext,
    ExpectedItem,
    FixtureFile,
    FixtureScope,
    Gap,
    LifecycleStep,
    McpScope,
    PluginScope,
    Scope,
    SeedCommand,
)
from agent_scan.canary_test_supported_agents.claude_code import ClaudeCodeCanary

# Registry of the available canaries, keyed by the discoverer name (matches agents.DISCOVERERS keys).
# Only discoverers with a built canary appear here; the others are added as their canaries land.
CANARIES: dict[str, AgentCanary] = {c.name: c for c in (ClaudeCodeCanary(),)}

__all__ = [
    "CANARIES",
    "AgentCanary",
    "CanaryContext",
    "ClaudeCodeCanary",
    "ExpectedItem",
    "FixtureFile",
    "FixtureScope",
    "Gap",
    "LifecycleStep",
    "McpScope",
    "PluginScope",
    "Scope",
    "SeedCommand",
]
