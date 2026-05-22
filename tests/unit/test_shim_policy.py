"""End-to-end tests for the shim lifecycle policy in ``run_scan``.

The runtime_config flag ``enable-local-stdio-proxy`` controls whether the
stdio shim is installed (flag present) or explicitly uninstalled (flag
absent).  These tests call ``run_scan`` with real config files on disk and
verify that shims are correctly installed / uninstalled before the scan
inspects the configs.
"""

from __future__ import annotations

import json
from argparse import Namespace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

if TYPE_CHECKING:
    from pathlib import Path

import pytest

from agent_scan.cli import run_scan
from agent_scan.inspect import inspect_client
from agent_scan.models import ClientToInspect, RemoteServer, ScanPathResult, ServerSignature, StdioServer
from agent_scan.runtime_config import RuntimeConfig, get_runtime_config, set_runtime_config
from agent_scan.shim_installer import (
    RUNTIME_CONFIG_SHIM_FLAG,
    SHIM_MARKER,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(tmp_path: Path, config: dict, name: str = "mcp.json") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return p


def _read_config(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _scan_args(files: list[str], **overrides) -> Namespace:
    """Minimal Namespace for ``run_scan`` with sensible defaults."""
    base = {
        "command": "scan",
        "control_servers": [],
        "analysis_url": "https://example.com/analysis",
        "verification_H": None,
        "skip_ssl_verify": False,
        "verbose": False,
        "scan_all_users": False,
        "server_timeout": 10,
        "files": files,
        "mcp_oauth_tokens_path": None,
        "skills": False,
        "dangerously_run_mcp_servers": True,
        "suppress_mcpserver_io": True,
        "use_shim_cache": False,
    }
    base.update(overrides)
    return Namespace(**base)


def _fake_clients(cfg_path: str) -> list[ClientToInspect]:
    """A single client pointing at the given config path."""
    return [
        ClientToInspect(
            name="test-client",
            client_path="/fake/client",
            mcp_configs={
                cfg_path: [
                    ("srv", StdioServer(command="uv", args=["run", "server.py"])),
                ],
            },
            skills_dirs={},
        ),
    ]


def _mock_scan_pipeline():
    """Patches that prevent any real HTTP or server startup from ``run_scan``."""
    path_result = ScanPathResult(path="/fake/mcp.json", servers=[])
    return (
        patch(
            "agent_scan.pipelines.inspect_pipeline",
            new=AsyncMock(return_value=([path_result], ["testuser"])),
        ),
        patch("agent_scan.pipelines.analyze_machine", new=AsyncMock(side_effect=lambda p, **kw: p)),
        patch("agent_scan.pipelines.upload", new=AsyncMock()),
    )


def _shim_path_fixture(tmp_path: Path) -> Path:
    fake_shim = tmp_path / "snyk_mcp_stdio_local_proxy.sh"
    fake_shim.write_text('#!/bin/sh\nexec "$@"')
    return fake_shim


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestShimPolicyInRunScan:
    async def test_flag_true_installs_shims_into_config(self, tmp_path):
        """When the bootstrap returns enable-local-stdio-proxy=true, run_scan
        installs the shim into the config file before the scan runs."""
        set_runtime_config(RuntimeConfig(config={RUNTIME_CONFIG_SHIM_FLAG: True}, source="bootstrap"))

        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run", "server.py"]}}}
        cfg_path = _write_config(tmp_path, config)

        fake_shim = _shim_path_fixture(tmp_path)
        args = _scan_args(files=[str(cfg_path)])

        p1, p2, p3 = _mock_scan_pipeline()
        with (
            p1,
            p2,
            p3,
            patch("agent_scan.shim_installer._get_shim_path", return_value=fake_shim),
            patch(
                "agent_scan.shim_installer._get_stdio_server_names",
                new_callable=AsyncMock,
                return_value={"srv"},
            ),
        ):
            await run_scan(args, mode="scan")

        result = _read_config(cfg_path)
        assert SHIM_MARKER in result["mcpServers"]["srv"]["command"]
        assert result["mcpServers"]["srv"]["args"][0] == "uv"

    async def test_flag_false_uninstalls_shims_from_config(self, tmp_path):
        """When the bootstrap returns enable-local-stdio-proxy=false, run_scan
        removes any existing shim from the config file."""
        set_runtime_config(RuntimeConfig(config={RUNTIME_CONFIG_SHIM_FLAG: False}, source="bootstrap"))

        config = {
            "mcpServers": {
                "srv": {
                    "command": f"/old/path/{SHIM_MARKER}.sh",
                    "args": ["uv", "run", "server.py"],
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        args = _scan_args(files=[str(cfg_path)])

        p1, p2, p3 = _mock_scan_pipeline()
        with p1, p2, p3:
            await run_scan(args, mode="scan")

        result = _read_config(cfg_path)
        assert result["mcpServers"]["srv"]["command"] == "uv"
        assert result["mcpServers"]["srv"]["args"] == ["run", "server.py"]

    async def test_flag_absent_uninstalls_shims(self, tmp_path):
        """When the bootstrap response has no shim flag at all, existing shims
        are cleaned up (safe default)."""
        set_runtime_config(RuntimeConfig(config={}, source="bootstrap"))

        config = {
            "mcpServers": {
                "srv": {
                    "command": f"/old/path/{SHIM_MARKER}.sh",
                    "args": ["uv", "run", "server.py"],
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        args = _scan_args(files=[str(cfg_path)])

        p1, p2, p3 = _mock_scan_pipeline()
        with p1, p2, p3:
            await run_scan(args, mode="scan")

        result = _read_config(cfg_path)
        assert result["mcpServers"]["srv"]["command"] == "uv"

    async def test_bootstrap_failure_still_uninstalls_shims(self, tmp_path):
        """When bootstrap failed (source=default, empty config), stale shims
        are still cleaned up."""
        # This is the state after bootstrap_runtime_config catches an exception
        set_runtime_config(RuntimeConfig())
        assert get_runtime_config().source == "default"

        config = {
            "mcpServers": {
                "srv": {
                    "command": f"/old/path/{SHIM_MARKER}.sh",
                    "args": ["uv", "run", "server.py"],
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        args = _scan_args(files=[str(cfg_path)])

        p1, p2, p3 = _mock_scan_pipeline()
        with p1, p2, p3:
            await run_scan(args, mode="scan")

        result = _read_config(cfg_path)
        assert result["mcpServers"]["srv"]["command"] == "uv"
        assert result["mcpServers"]["srv"]["args"] == ["run", "server.py"]

    async def test_flag_true_enables_shim_cache(self, tmp_path):
        """When the flag is set, use_shim_cache is forced to True regardless
        of the CLI flag."""
        set_runtime_config(RuntimeConfig(config={RUNTIME_CONFIG_SHIM_FLAG: True}, source="bootstrap"))

        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run", "server.py"]}}}
        cfg_path = _write_config(tmp_path, config)

        fake_shim = _shim_path_fixture(tmp_path)
        args = _scan_args(files=[str(cfg_path)], use_shim_cache=False)

        captured_inspect_args = {}

        async def capture_inspect(inspect_args, **kwargs):
            captured_inspect_args.update(inspect_args.model_dump())
            return [ScanPathResult(path=str(cfg_path), servers=[])], ["testuser"]

        with (
            patch("agent_scan.pipelines.inspect_pipeline", new=AsyncMock(side_effect=capture_inspect)),
            patch("agent_scan.pipelines.analyze_machine", new=AsyncMock(side_effect=lambda p, **kw: p)),
            patch("agent_scan.pipelines.upload", new=AsyncMock()),
            patch("agent_scan.shim_installer._get_shim_path", return_value=fake_shim),
            patch(
                "agent_scan.shim_installer._get_stdio_server_names",
                new_callable=AsyncMock,
                return_value={"srv"},
            ),
        ):
            await run_scan(args, mode="scan")

        assert captured_inspect_args["use_shim_cache"] is True

    async def test_unshimmed_config_stays_clean_when_flag_absent(self, tmp_path):
        """When configs have no shim and the flag is absent, configs are not
        modified (no unnecessary writes)."""
        set_runtime_config(RuntimeConfig(config={}, source="bootstrap"))

        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run", "server.py"]}}}
        cfg_path = _write_config(tmp_path, config)
        mtime_before = cfg_path.stat().st_mtime

        args = _scan_args(files=[str(cfg_path)])

        p1, p2, p3 = _mock_scan_pipeline()
        with p1, p2, p3:
            await run_scan(args, mode="scan")

        result = _read_config(cfg_path)
        assert result["mcpServers"]["srv"]["command"] == "uv"
        assert cfg_path.stat().st_mtime == mtime_before

    async def test_multiple_configs_all_shimmed(self, tmp_path):
        """Shim policy applies to all discovered config files, not just the first."""
        set_runtime_config(RuntimeConfig(config={RUNTIME_CONFIG_SHIM_FLAG: True}, source="bootstrap"))

        config1 = {"mcpServers": {"a": {"command": "cmd_a", "args": ["--flag"]}}}
        config2 = {"mcpServers": {"b": {"command": "cmd_b", "args": []}}}
        path1 = _write_config(tmp_path, config1, "config1.json")
        path2 = _write_config(tmp_path, config2, "config2.json")

        fake_shim = _shim_path_fixture(tmp_path)
        args = _scan_args(files=[str(path1), str(path2)])

        p1, p2, p3 = _mock_scan_pipeline()
        with (
            p1,
            p2,
            p3,
            patch("agent_scan.shim_installer._get_shim_path", return_value=fake_shim),
            patch(
                "agent_scan.shim_installer._get_stdio_server_names",
                new_callable=AsyncMock,
                return_value={"a", "b"},
            ),
        ):
            await run_scan(args, mode="scan")

        assert SHIM_MARKER in _read_config(path1)["mcpServers"]["a"]["command"]
        assert SHIM_MARKER in _read_config(path2)["mcpServers"]["b"]["command"]

    async def test_multiple_configs_all_unshimmed(self, tmp_path):
        """When flag is absent, all configs get their shims removed."""
        set_runtime_config(RuntimeConfig(config={}, source="bootstrap"))

        config1 = {"mcpServers": {"a": {"command": f"/old/{SHIM_MARKER}.sh", "args": ["cmd_a", "--flag"]}}}
        config2 = {"mcpServers": {"b": {"command": f"/old/{SHIM_MARKER}.sh", "args": ["cmd_b"]}}}
        path1 = _write_config(tmp_path, config1, "config1.json")
        path2 = _write_config(tmp_path, config2, "config2.json")

        args = _scan_args(files=[str(path1), str(path2)])

        p1, p2, p3 = _mock_scan_pipeline()
        with p1, p2, p3:
            await run_scan(args, mode="scan")

        assert _read_config(path1)["mcpServers"]["a"]["command"] == "cmd_a"
        assert _read_config(path2)["mcpServers"]["b"]["command"] == "cmd_b"


@pytest.mark.asyncio
class TestShimCacheSkipsStdioButNotRemote:
    """Verify that the shim cache flag is what controls whether stdio servers
    get a real handshake or are served from cache.  Remote servers always get
    a real handshake regardless of the flag."""

    @staticmethod
    def _build_fixtures():
        from mcp.types import Implementation, InitializeResult, ServerCapabilities, Tool

        cached_signature = ServerSignature(
            metadata=InitializeResult(
                protocolVersion="2024-11-05",
                capabilities=ServerCapabilities(),
                serverInfo=Implementation(name="cached-srv", version="1.0"),
            ),
            tools=[Tool(name="cached_tool", inputSchema={"type": "object"})],
        )

        live_stdio_signature = ServerSignature(
            metadata=InitializeResult(
                protocolVersion="2024-11-05",
                capabilities=ServerCapabilities(),
                serverInfo=Implementation(name="live-stdio-srv", version="1.0"),
            ),
            tools=[Tool(name="live_stdio_tool", inputSchema={"type": "object"})],
        )

        remote_signature = ServerSignature(
            metadata=InitializeResult(
                protocolVersion="2024-11-05",
                capabilities=ServerCapabilities(),
                serverInfo=Implementation(name="remote-srv", version="2.0"),
            ),
            tools=[Tool(name="remote_tool", inputSchema={"type": "object"})],
        )

        remote_server = RemoteServer(url="http://localhost:9999/mcp")
        stdio_server = StdioServer(command="uv", args=["run", "server.py"])

        client = ClientToInspect(
            name="test-client",
            client_path="/fake/client",
            mcp_configs={
                "/fake/mcp.json": [
                    ("stdio-srv", stdio_server),
                    ("remote-srv", remote_server),
                ],
            },
            skills_dirs={},
        )

        return client, stdio_server, remote_server, cached_signature, live_stdio_signature, remote_signature

    async def test_shim_enabled_skips_stdio_handshake(self):
        """With use_shim_cache=True, the stdio server is served from cache
        and check_server is only called for the remote server."""
        client, _, remote_server, cached_sig, _, remote_sig = self._build_fixtures()

        check_server_mock = AsyncMock(return_value=(remote_sig, remote_server))

        with (
            patch("agent_scan.inspect.get_signature_for_server", return_value=cached_sig),
            patch("agent_scan.inspect.check_server", new=check_server_mock),
        ):
            result = await inspect_client(
                client,
                timeout=10,
                tokens=[],
                scan_skills=False,
                use_shim_cache=True,
            )

        inspected = result.extensions["/fake/mcp.json"]
        assert isinstance(inspected, list)
        by_name = {ext.name: ext for ext in inspected}

        # stdio served from cache
        stdio_ext = by_name["stdio-srv"]
        assert isinstance(stdio_ext.signature_or_error, ServerSignature)
        assert stdio_ext.signature_or_error.tools[0].name == "cached_tool"

        # remote got a real handshake
        remote_ext = by_name["remote-srv"]
        assert isinstance(remote_ext.signature_or_error, ServerSignature)
        assert remote_ext.signature_or_error.tools[0].name == "remote_tool"

        # check_server called exactly once — for the remote server only
        assert check_server_mock.call_count == 1
        assert isinstance(check_server_mock.call_args[0][0], RemoteServer)

    async def test_shim_disabled_handshakes_both(self):
        """With use_shim_cache=False, check_server is called for BOTH the
        stdio and the remote server — the cache is never consulted."""
        client, _, remote_server, cached_sig, live_stdio_sig, remote_sig = self._build_fixtures()

        def check_server_side_effect(config, *args, **kwargs):
            if isinstance(config, StdioServer):
                return (live_stdio_sig, config)
            return (remote_sig, remote_server)

        check_server_mock = AsyncMock(side_effect=check_server_side_effect)
        get_sig_mock = AsyncMock(return_value=cached_sig)

        with (
            patch("agent_scan.inspect.get_signature_for_server", new=get_sig_mock),
            patch("agent_scan.inspect.check_server", new=check_server_mock),
        ):
            result = await inspect_client(
                client,
                timeout=10,
                tokens=[],
                scan_skills=False,
                use_shim_cache=False,
            )

        inspected = result.extensions["/fake/mcp.json"]
        assert isinstance(inspected, list)
        by_name = {ext.name: ext for ext in inspected}

        # stdio got a real handshake — NOT the cached version
        stdio_ext = by_name["stdio-srv"]
        assert isinstance(stdio_ext.signature_or_error, ServerSignature)
        assert stdio_ext.signature_or_error.tools[0].name == "live_stdio_tool"

        # remote also got a real handshake
        remote_ext = by_name["remote-srv"]
        assert isinstance(remote_ext.signature_or_error, ServerSignature)
        assert remote_ext.signature_or_error.tools[0].name == "remote_tool"

        # check_server called for both servers
        assert check_server_mock.call_count == 2

        # cache was never consulted
        get_sig_mock.assert_not_called()


@pytest.mark.asyncio
class TestFullShimPolicyE2E:
    """Full end-to-end: runtime config flag → shim installed on disk →
    stdio served from cache → remote gets real handshake → scan results
    contain both servers."""

    async def test_flag_shims_config_and_caches_stdio_while_remote_handshakes(self, tmp_path):
        from mcp.types import Implementation, InitializeResult, ServerCapabilities, Tool

        cached_signature = ServerSignature(
            metadata=InitializeResult(
                protocolVersion="2024-11-05",
                capabilities=ServerCapabilities(),
                serverInfo=Implementation(name="cached-stdio", version="1.0"),
            ),
            tools=[Tool(name="cached_tool", inputSchema={"type": "object"})],
        )

        remote_signature = ServerSignature(
            metadata=InitializeResult(
                protocolVersion="2024-11-05",
                capabilities=ServerCapabilities(),
                serverInfo=Implementation(name="remote-srv", version="2.0"),
            ),
            tools=[Tool(name="remote_tool", inputSchema={"type": "object"})],
        )

        # Config on disk with both stdio and remote servers
        config = {
            "mcpServers": {
                "my-stdio": {"command": "uv", "args": ["run", "server.py"]},
                "my-remote": {"url": "http://localhost:9999/mcp"},
            }
        }
        cfg_path = _write_config(tmp_path, config)
        fake_shim = _shim_path_fixture(tmp_path)

        set_runtime_config(RuntimeConfig(config={RUNTIME_CONFIG_SHIM_FLAG: True}, source="bootstrap"))

        args = _scan_args(files=[str(cfg_path)])

        remote_server_obj = RemoteServer(url="http://localhost:9999/mcp")
        check_server_mock = AsyncMock(return_value=(remote_signature, remote_server_obj))

        with (
            # Shim installation mocks
            patch("agent_scan.shim_installer._get_shim_path", return_value=fake_shim),
            patch(
                "agent_scan.shim_installer._get_stdio_server_names",
                new_callable=AsyncMock,
                return_value={"my-stdio"},
            ),
            # Inspection mocks — let the real inspect_client / inspect_extension
            # run, but mock check_server to avoid real server startup
            patch("agent_scan.inspect.check_server", new=check_server_mock),
            patch("agent_scan.inspect.get_signature_for_server", return_value=cached_signature),
            # Prevent real HTTP for analyze + push
            patch("agent_scan.pipelines.analyze_machine", new=AsyncMock(side_effect=lambda p, **kw: p)),
            patch("agent_scan.pipelines.upload", new=AsyncMock()),
        ):
            results = await run_scan(args, mode="scan")

        # 1. Config file on disk was shimmed
        on_disk = _read_config(cfg_path)
        assert SHIM_MARKER in on_disk["mcpServers"]["my-stdio"]["command"]
        assert on_disk["mcpServers"]["my-stdio"]["args"][0] == "uv"
        # Remote server untouched on disk
        assert on_disk["mcpServers"]["my-remote"]["url"] == "http://localhost:9999/mcp"

        # 2. check_server was called exactly once — for the remote server only
        assert check_server_mock.call_count == 1
        assert isinstance(check_server_mock.call_args[0][0], RemoteServer)

        # 3. Scan results contain both servers with correct signatures
        assert len(results) == 1
        servers = results[0].servers
        by_name = {s.name: s for s in servers}

        assert "my-stdio" in by_name
        assert by_name["my-stdio"].signature is not None
        assert by_name["my-stdio"].signature.tools[0].name == "cached_tool"

        assert "my-remote" in by_name
        assert by_name["my-remote"].signature is not None
        assert by_name["my-remote"].signature.tools[0].name == "remote_tool"

    async def test_flag_absent_unshims_and_handshakes_all(self, tmp_path):
        """Counterpart: no flag → shim removed from disk → both servers
        get a real check_server call."""
        from mcp.types import Implementation, InitializeResult, ServerCapabilities, Tool

        stdio_signature = ServerSignature(
            metadata=InitializeResult(
                protocolVersion="2024-11-05",
                capabilities=ServerCapabilities(),
                serverInfo=Implementation(name="live-stdio", version="1.0"),
            ),
            tools=[Tool(name="live_stdio_tool", inputSchema={"type": "object"})],
        )

        remote_signature = ServerSignature(
            metadata=InitializeResult(
                protocolVersion="2024-11-05",
                capabilities=ServerCapabilities(),
                serverInfo=Implementation(name="remote-srv", version="2.0"),
            ),
            tools=[Tool(name="remote_tool", inputSchema={"type": "object"})],
        )

        # Config on disk: stdio server is currently shimmed (leftover from a previous run)
        config = {
            "mcpServers": {
                "my-stdio": {
                    "command": f"/old/path/{SHIM_MARKER}.sh",
                    "args": ["uv", "run", "server.py"],
                },
                "my-remote": {"url": "http://localhost:9999/mcp"},
            }
        }
        cfg_path = _write_config(tmp_path, config)

        # No flag → shims should be removed
        set_runtime_config(RuntimeConfig(config={}, source="bootstrap"))

        args = _scan_args(files=[str(cfg_path)])

        remote_server_obj = RemoteServer(url="http://localhost:9999/mcp")

        def check_server_side_effect(config, *a, **kw):
            if isinstance(config, StdioServer):
                return (stdio_signature, config)
            return (remote_signature, remote_server_obj)

        check_server_mock = AsyncMock(side_effect=check_server_side_effect)
        get_sig_mock = AsyncMock()

        with (
            patch("agent_scan.inspect.check_server", new=check_server_mock),
            patch("agent_scan.inspect.get_signature_for_server", new=get_sig_mock),
            patch("agent_scan.pipelines.analyze_machine", new=AsyncMock(side_effect=lambda p, **kw: p)),
            patch("agent_scan.pipelines.upload", new=AsyncMock()),
        ):
            results = await run_scan(args, mode="scan")

        # 1. Config file on disk was unshimmed
        on_disk = _read_config(cfg_path)
        assert on_disk["mcpServers"]["my-stdio"]["command"] == "uv"
        assert on_disk["mcpServers"]["my-stdio"]["args"] == ["run", "server.py"]

        # 2. check_server called for both servers
        assert check_server_mock.call_count == 2

        # 3. Cache was never consulted
        get_sig_mock.assert_not_called()

        # 4. Scan results contain both servers with live signatures
        servers = results[0].servers
        by_name = {s.name: s for s in servers}

        assert by_name["my-stdio"].signature is not None
        assert by_name["my-stdio"].signature.tools[0].name == "live_stdio_tool"

        assert by_name["my-remote"].signature is not None
        assert by_name["my-remote"].signature.tools[0].name == "remote_tool"

    async def test_flag_true_but_shim_script_missing_repairs_and_scans_normally(self, tmp_path):
        """Flag is on, but the shim script doesn't exist on disk (e.g.
        package reinstalled to a different path).  The stale shim in the
        config should be repaired and the scan should fall through to a
        normal check_server handshake for all servers."""
        from mcp.types import Implementation, InitializeResult, ServerCapabilities, Tool

        stdio_signature = ServerSignature(
            metadata=InitializeResult(
                protocolVersion="2024-11-05",
                capabilities=ServerCapabilities(),
                serverInfo=Implementation(name="live-stdio", version="1.0"),
            ),
            tools=[Tool(name="live_stdio_tool", inputSchema={"type": "object"})],
        )

        remote_signature = ServerSignature(
            metadata=InitializeResult(
                protocolVersion="2024-11-05",
                capabilities=ServerCapabilities(),
                serverInfo=Implementation(name="remote-srv", version="2.0"),
            ),
            tools=[Tool(name="remote_tool", inputSchema={"type": "object"})],
        )

        # Config on disk: stdio was shimmed in a previous run, but the shim
        # script has since been deleted (stale path).
        config = {
            "mcpServers": {
                "my-stdio": {
                    "command": f"/gone/{SHIM_MARKER}.sh",
                    "args": ["uv", "run", "server.py"],
                },
                "my-remote": {"url": "http://localhost:9999/mcp"},
            }
        }
        cfg_path = _write_config(tmp_path, config)

        # Flag is on, but point _get_shim_path to a nonexistent file
        missing_shim = tmp_path / "nonexistent" / "snyk_mcp_stdio_local_proxy.sh"

        set_runtime_config(RuntimeConfig(config={RUNTIME_CONFIG_SHIM_FLAG: True}, source="bootstrap"))

        args = _scan_args(files=[str(cfg_path)])

        remote_server_obj = RemoteServer(url="http://localhost:9999/mcp")

        def check_server_side_effect(server_config, *a, **kw):
            if isinstance(server_config, StdioServer):
                return (stdio_signature, server_config)
            return (remote_signature, remote_server_obj)

        check_server_mock = AsyncMock(side_effect=check_server_side_effect)

        with (
            patch("agent_scan.shim_installer._get_shim_path", return_value=missing_shim),
            patch(
                "agent_scan.shim_installer._get_stdio_server_names",
                new_callable=AsyncMock,
                return_value={"my-stdio"},
            ),
            patch("agent_scan.inspect.check_server", new=check_server_mock),
            patch("agent_scan.inspect.get_signature_for_server", return_value=None),
            patch("agent_scan.pipelines.analyze_machine", new=AsyncMock(side_effect=lambda p, **kw: p)),
            patch("agent_scan.pipelines.upload", new=AsyncMock()),
        ):
            results = await run_scan(args, mode="scan")

        # 1. Config was repaired: stale shim removed, original command restored
        on_disk = _read_config(cfg_path)
        assert on_disk["mcpServers"]["my-stdio"]["command"] == "uv"
        assert on_disk["mcpServers"]["my-stdio"]["args"] == ["run", "server.py"]
        assert SHIM_MARKER not in on_disk["mcpServers"]["my-stdio"]["command"]

        # 2. Both servers got a real check_server call (no cache available)
        assert check_server_mock.call_count == 2

        # 3. Scan results contain both servers with live signatures
        servers = results[0].servers
        by_name = {s.name: s for s in servers}

        assert by_name["my-stdio"].signature is not None
        assert by_name["my-stdio"].signature.tools[0].name == "live_stdio_tool"

        assert by_name["my-remote"].signature is not None
        assert by_name["my-remote"].signature.tools[0].name == "remote_tool"
