"""Tests for shim installation / uninstallation into MCP client configs."""

from __future__ import annotations

import hashlib
import json
import sys
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

if TYPE_CHECKING:
    from pathlib import Path

import pytest

from agent_scan import shim_installer
from agent_scan.models import StdioServer
from agent_scan.shim_installer import (
    SHIM_MARKER,
    _get_shim_path,
    _is_shimmed_raw,
    _read_shim_source_bytes,
    _resolve_servers,
    compute_server_hash,
    install_shim_into_config,
    repair_broken_shim,
    uninstall_shim_from_config,
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


# ---------------------------------------------------------------------------
# _resolve_servers
# ---------------------------------------------------------------------------


class TestResolveServers:
    def test_mcpservers_key(self):
        config = {"mcpServers": {"a": {"command": "x"}}}
        assert _resolve_servers(config) == {"a": {"command": "x"}}

    def test_servers_key(self):
        config = {"servers": {"b": {"command": "y"}}}
        assert _resolve_servers(config) == {"b": {"command": "y"}}

    def test_mcp_servers_nested(self):
        config = {"mcp": {"servers": {"c": {"command": "z"}}}}
        assert _resolve_servers(config) == {"c": {"command": "z"}}

    def test_projects_key(self):
        config = {"projects": {"proj1": {"mcpServers": {"d": {"command": "w"}}}}}
        assert _resolve_servers(config) == {"d": {"command": "w"}}

    def test_empty_config(self):
        assert _resolve_servers({}) is None

    def test_empty_servers(self):
        assert _resolve_servers({"mcpServers": {}}) is None

    def test_prefers_first_match(self):
        config = {
            "mcpServers": {"a": {"command": "first"}},
            "servers": {"b": {"command": "second"}},
        }
        assert _resolve_servers(config) == {"a": {"command": "first"}}


# ---------------------------------------------------------------------------
# _is_shimmed_raw
# ---------------------------------------------------------------------------


class TestIsShimmedRaw:
    def test_not_shimmed(self):
        assert not _is_shimmed_raw({"command": "uv", "args": ["run"]})

    def test_shimmed(self):
        assert _is_shimmed_raw({"command": f"/path/to/{SHIM_MARKER}.sh", "args": ["uv", "run"]})

    def test_no_command(self):
        assert not _is_shimmed_raw({"args": ["run"]})


# ---------------------------------------------------------------------------
# compute_server_hash
# ---------------------------------------------------------------------------


class TestComputeServerHash:
    def test_deterministic(self):
        s = StdioServer(command="uv", args=["run", "server.py"])
        assert compute_server_hash(s) == compute_server_hash(s)

    def test_different_args(self):
        s1 = StdioServer(command="uv", args=["run", "a.py"])
        s2 = StdioServer(command="uv", args=["run", "b.py"])
        assert compute_server_hash(s1) != compute_server_hash(s2)

    def test_length(self):
        s = StdioServer(command="uv", args=[])
        assert len(compute_server_hash(s)) == 12


# ---------------------------------------------------------------------------
# install_shim_into_config
# ---------------------------------------------------------------------------


@pytest.fixture
def shim_path(tmp_path):
    """Create a fake shim script so path-existence checks pass."""
    fake_shim = tmp_path / "snyk_mcp_stdio_local_proxy.sh"
    fake_shim.write_text('#!/bin/sh\nexec "$@"')
    return fake_shim


def _patch_shim(shim_path: Path):
    return patch("agent_scan.shim_installer._get_shim_path", return_value=shim_path)


def _patch_stdio_names(names: set[str]):
    return patch("agent_scan.shim_installer._get_stdio_server_names", new_callable=AsyncMock, return_value=names)


class TestInstallShim:
    @pytest.mark.asyncio
    async def test_install_mcpservers_format(self, tmp_path, shim_path):
        config = {
            "mcpServers": {
                "weather": {"command": "uv", "args": ["run", "weather.py"]},
                "remote": {"url": "https://example.com/mcp"},
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"weather"}):
            shimmed = await install_shim_into_config(str(cfg_path))

        assert shimmed == ["weather"]
        result = _read_config(cfg_path)
        weather = result["mcpServers"]["weather"]
        assert SHIM_MARKER in weather["command"]
        assert weather["args"][0] == "uv"
        assert weather["args"][1:] == ["run", "weather.py"]
        # remote server should be untouched
        assert result["mcpServers"]["remote"] == {"url": "https://example.com/mcp"}

    @pytest.mark.asyncio
    async def test_install_vscode_mcp_servers_format(self, tmp_path, shim_path):
        config = {"mcp": {"servers": {"myserver": {"command": "node", "args": ["index.js"]}}}}
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"myserver"}):
            shimmed = await install_shim_into_config(str(cfg_path))

        assert shimmed == ["myserver"]
        result = _read_config(cfg_path)
        server = result["mcp"]["servers"]["myserver"]
        assert SHIM_MARKER in server["command"]
        assert server["args"][0] == "node"

    @pytest.mark.asyncio
    async def test_install_servers_format(self, tmp_path, shim_path):
        config = {"servers": {"s1": {"command": "python", "args": ["-m", "srv"]}}}
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"s1"}):
            shimmed = await install_shim_into_config(str(cfg_path))

        assert shimmed == ["s1"]
        result = _read_config(cfg_path)
        assert SHIM_MARKER in result["servers"]["s1"]["command"]

    @pytest.mark.asyncio
    async def test_skips_already_shimmed_with_current_path(self, tmp_path, shim_path):
        config = {
            "mcpServers": {
                "already": {"command": str(shim_path.resolve()), "args": ["uv", "run"]},
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"already"}):
            shimmed = await install_shim_into_config(str(cfg_path))

        assert shimmed == []

    @pytest.mark.asyncio
    async def test_skips_non_stdio_servers(self, tmp_path, shim_path):
        config = {
            "mcpServers": {
                "stdio_one": {"command": "uv", "args": []},
                "not_stdio": {"command": "other", "args": []},
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"stdio_one"}):
            shimmed = await install_shim_into_config(str(cfg_path))

        assert shimmed == ["stdio_one"]
        result = _read_config(cfg_path)
        assert SHIM_MARKER not in result["mcpServers"]["not_stdio"]["command"]

    @pytest.mark.asyncio
    async def test_missing_config_file(self, shim_path):
        with _patch_shim(shim_path):
            shimmed = await install_shim_into_config("/nonexistent/path.json")
        assert shimmed == []

    @pytest.mark.asyncio
    async def test_no_stdio_servers_returns_empty(self, tmp_path, shim_path):
        config = {"mcpServers": {"remote": {"url": "https://example.com"}}}
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names(set()):
            shimmed = await install_shim_into_config(str(cfg_path))

        assert shimmed == []

    @pytest.mark.asyncio
    async def test_preserves_env_and_other_keys(self, tmp_path, shim_path):
        config = {
            "mcpServers": {
                "srv": {
                    "command": "uv",
                    "args": ["run"],
                    "env": {"API_KEY": "secret"},
                    "custom_field": 42,
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"srv"}):
            await install_shim_into_config(str(cfg_path))

        result = _read_config(cfg_path)
        srv = result["mcpServers"]["srv"]
        assert srv["env"] == {"API_KEY": "secret"}
        assert srv["custom_field"] == 42

    @pytest.mark.asyncio
    async def test_install_multiple_servers(self, tmp_path, shim_path):
        config = {
            "mcpServers": {
                "a": {"command": "cmd_a", "args": ["--flag"]},
                "b": {"command": "cmd_b", "args": []},
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"a", "b"}):
            shimmed = await install_shim_into_config(str(cfg_path))

        assert set(shimmed) == {"a", "b"}
        result = _read_config(cfg_path)
        for name in ("a", "b"):
            assert SHIM_MARKER in result["mcpServers"][name]["command"]

    @pytest.mark.asyncio
    async def test_shim_marker_changed_updates_shimmed_servers(self, tmp_path, shim_path):
        """If the shim marker has changed, we should update the shimmed servers to use the new marker."""
        config = {
            "mcpServers": {
                "weather": {
                    "command": f"/path/to/{SHIM_MARKER}.sh",
                    "args": ["uv", "run", "weather.py"],
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"weather"}):
            shimmed = await install_shim_into_config(str(cfg_path))

        assert shimmed == ["weather"]
        result = _read_config(cfg_path)
        assert SHIM_MARKER in result["mcpServers"]["weather"]["command"]
        assert result["mcpServers"]["weather"]["args"] == ["uv", "run", "weather.py"]


# ---------------------------------------------------------------------------
# uninstall_shim_from_config
# ---------------------------------------------------------------------------


class TestUninstallShim:
    @pytest.mark.asyncio
    async def test_uninstall_restores_command(self, tmp_path):
        config = {
            "mcpServers": {
                "weather": {
                    "command": f"/path/to/{SHIM_MARKER}.sh",
                    "args": ["uv", "run", "weather.py"],
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        unshimmed = await uninstall_shim_from_config(str(cfg_path))

        assert unshimmed == ["weather"]
        result = _read_config(cfg_path)
        weather = result["mcpServers"]["weather"]
        assert weather["command"] == "uv"
        assert weather["args"] == ["run", "weather.py"]

    @pytest.mark.asyncio
    async def test_uninstall_not_shimmed_is_noop(self, tmp_path):
        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run"]}}}
        cfg_path = _write_config(tmp_path, config)

        unshimmed = await uninstall_shim_from_config(str(cfg_path))

        assert unshimmed == []
        # File should not be rewritten
        result = _read_config(cfg_path)
        assert result["mcpServers"]["srv"]["command"] == "uv"

    @pytest.mark.asyncio
    async def test_uninstall_missing_file(self):
        unshimmed = await uninstall_shim_from_config("/nonexistent/path.json")
        assert unshimmed == []

    @pytest.mark.asyncio
    async def test_uninstall_preserves_other_servers(self, tmp_path):
        config = {
            "mcpServers": {
                "shimmed": {
                    "command": f"/path/{SHIM_MARKER}.sh",
                    "args": ["original_cmd", "--flag"],
                },
                "untouched": {
                    "command": "other",
                    "args": ["--arg"],
                },
            }
        }
        cfg_path = _write_config(tmp_path, config)

        unshimmed = await uninstall_shim_from_config(str(cfg_path))

        assert unshimmed == ["shimmed"]
        result = _read_config(cfg_path)
        assert result["mcpServers"]["untouched"] == {"command": "other", "args": ["--arg"]}

    @pytest.mark.asyncio
    async def test_uninstall_preserves_env(self, tmp_path):
        config = {
            "mcpServers": {
                "srv": {
                    "command": f"/path/{SHIM_MARKER}.sh",
                    "args": ["uv", "run"],
                    "env": {"KEY": "val"},
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        await uninstall_shim_from_config(str(cfg_path))

        result = _read_config(cfg_path)
        assert result["mcpServers"]["srv"]["env"] == {"KEY": "val"}

    @pytest.mark.asyncio
    async def test_uninstall_vscode_format(self, tmp_path):
        config = {
            "mcp": {
                "servers": {
                    "srv": {
                        "command": f"/path/{SHIM_MARKER}.sh",
                        "args": ["node", "index.js"],
                    }
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        unshimmed = await uninstall_shim_from_config(str(cfg_path))

        assert unshimmed == ["srv"]
        result = _read_config(cfg_path)
        assert result["mcp"]["servers"]["srv"]["command"] == "node"
        assert result["mcp"]["servers"]["srv"]["args"] == ["index.js"]

    @pytest.mark.asyncio
    async def test_uninstall_stale_shim_path(self, tmp_path, shim_path):
        """If the shim path has changed (e.g. package updated), uninstall should restore the original command."""
        old_shim = f"/old/path/to/{SHIM_MARKER}.sh"
        config = {
            "mcpServers": {
                "weather": {
                    "command": old_shim,
                    "args": ["uv", "run", "weather.py"],
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        unshimmed = await uninstall_shim_from_config(str(cfg_path))

        assert unshimmed == ["weather"]
        result = _read_config(cfg_path)
        weather = result["mcpServers"]["weather"]
        assert weather["command"] == "uv"
        assert weather["args"] == ["run", "weather.py"]
        assert SHIM_MARKER not in weather["command"]


# ---------------------------------------------------------------------------
# Round-trip: install then uninstall
# ---------------------------------------------------------------------------


class TestRoundTrip:
    @pytest.mark.asyncio
    async def test_install_then_uninstall_restores_original(self, tmp_path, shim_path):
        original = {
            "mcpServers": {
                "weather": {"command": "uv", "args": ["run", "weather.py"]},
                "remote": {"url": "https://example.com"},
            }
        }
        cfg_path = _write_config(tmp_path, original)

        with _patch_shim(shim_path), _patch_stdio_names({"weather"}):
            await install_shim_into_config(str(cfg_path))

        # Verify shimmed state
        mid = _read_config(cfg_path)
        assert SHIM_MARKER in mid["mcpServers"]["weather"]["command"]

        await uninstall_shim_from_config(str(cfg_path))

        result = _read_config(cfg_path)
        assert result["mcpServers"]["weather"]["command"] == "uv"
        assert result["mcpServers"]["weather"]["args"] == ["run", "weather.py"]
        assert result["mcpServers"]["remote"] == {"url": "https://example.com"}

    @pytest.mark.asyncio
    async def test_install_updates_stale_shim_path(self, tmp_path, shim_path):
        """If the shim path has changed (e.g. package updated), re-install should update the command."""
        old_shim = f"/old/path/to/{SHIM_MARKER}.sh"
        config = {
            "mcpServers": {
                "weather": {
                    "command": old_shim,
                    "args": ["uv", "run", "weather.py"],
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"weather"}):
            shimmed = await install_shim_into_config(str(cfg_path))

        assert shimmed == ["weather"]
        result = _read_config(cfg_path)
        weather = result["mcpServers"]["weather"]
        # Command should now point to the new shim path, not the old one
        assert weather["command"] == str(shim_path.resolve())
        assert weather["command"] != old_shim
        # Original args should be preserved (not double-wrapped)
        assert weather["args"] == ["uv", "run", "weather.py"]

    @pytest.mark.asyncio
    async def test_double_install_is_idempotent(self, tmp_path, shim_path):
        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run"]}}}
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"srv"}):
            first = await install_shim_into_config(str(cfg_path))
            second = await install_shim_into_config(str(cfg_path))

        assert first == ["srv"]
        assert second == []
        result = _read_config(cfg_path)
        # Should only be wrapped once
        assert result["mcpServers"]["srv"]["args"][0] == "uv"

    @pytest.mark.asyncio
    async def test_double_uninstall_is_idempotent(self, tmp_path, shim_path):
        config = {
            "mcpServers": {
                "srv": {
                    "command": f"/path/{SHIM_MARKER}.sh",
                    "args": ["uv", "run"],
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        first = await uninstall_shim_from_config(str(cfg_path))
        second = await uninstall_shim_from_config(str(cfg_path))

        assert first == ["srv"]
        assert second == []

    @pytest.mark.asyncio
    async def test_config_edited_between_install_and_uninstall(self, tmp_path, shim_path):
        """Edits to other parts of the config survive uninstall (no backup overwrite)."""
        config = {
            "mcpServers": {
                "weather": {"command": "uv", "args": ["run"]},
                "other": {"url": "https://old.example.com"},
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"weather"}):
            await install_shim_into_config(str(cfg_path))

        # Simulate user editing the config while shim is installed
        mid = _read_config(cfg_path)
        mid["mcpServers"]["other"]["url"] = "https://new.example.com"
        mid["mcpServers"]["added"] = {"url": "https://added.example.com"}
        cfg_path.write_text(json.dumps(mid, indent=2), encoding="utf-8")

        await uninstall_shim_from_config(str(cfg_path))

        result = _read_config(cfg_path)
        assert result["mcpServers"]["weather"]["command"] == "uv"
        assert result["mcpServers"]["other"]["url"] == "https://new.example.com"
        assert result["mcpServers"]["added"]["url"] == "https://added.example.com"

    @pytest.mark.asyncio
    async def test_server_with_no_args(self, tmp_path, shim_path):
        config = {"mcpServers": {"bare": {"command": "my-server"}}}
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"bare"}):
            shimmed = await install_shim_into_config(str(cfg_path))

        assert shimmed == ["bare"]
        result = _read_config(cfg_path)
        assert result["mcpServers"]["bare"]["args"] == ["my-server"]

        await uninstall_shim_from_config(str(cfg_path))

        result = _read_config(cfg_path)
        assert result["mcpServers"]["bare"]["command"] == "my-server"
        assert result["mcpServers"]["bare"]["args"] == []


# ---------------------------------------------------------------------------
# Config mutations while shim is installed
# ---------------------------------------------------------------------------


class TestConfigMutations:
    @pytest.mark.asyncio
    async def test_user_adds_new_stdio_server(self, tmp_path, shim_path):
        """User adds a new stdio server while shim is installed. Re-install should shim it."""
        config = {"mcpServers": {"existing": {"command": "uv", "args": ["run"]}}}
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"existing"}):
            await install_shim_into_config(str(cfg_path))

        # User adds a new server
        mid = _read_config(cfg_path)
        mid["mcpServers"]["new_server"] = {"command": "node", "args": ["index.js"]}
        cfg_path.write_text(json.dumps(mid, indent=2), encoding="utf-8")

        with _patch_shim(shim_path), _patch_stdio_names({"existing", "new_server"}):
            shimmed = await install_shim_into_config(str(cfg_path))

        assert shimmed == ["new_server"]
        result = _read_config(cfg_path)
        assert SHIM_MARKER in result["mcpServers"]["new_server"]["command"]
        assert result["mcpServers"]["new_server"]["args"][0] == "node"
        # Existing should still be shimmed, not double-wrapped
        assert SHIM_MARKER in result["mcpServers"]["existing"]["command"]
        assert result["mcpServers"]["existing"]["args"][0] == "uv"

    @pytest.mark.asyncio
    async def test_user_removes_shimmed_server(self, tmp_path, shim_path):
        """User deletes a shimmed server from config. Uninstall handles remaining servers fine."""
        config = {
            "mcpServers": {
                "keep": {"command": "uv", "args": ["run", "a.py"]},
                "remove_me": {"command": "node", "args": ["b.js"]},
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"keep", "remove_me"}):
            await install_shim_into_config(str(cfg_path))

        # User removes one server
        mid = _read_config(cfg_path)
        del mid["mcpServers"]["remove_me"]
        cfg_path.write_text(json.dumps(mid, indent=2), encoding="utf-8")

        unshimmed = await uninstall_shim_from_config(str(cfg_path))

        assert unshimmed == ["keep"]
        result = _read_config(cfg_path)
        assert result["mcpServers"]["keep"]["command"] == "uv"
        assert "remove_me" not in result["mcpServers"]

    @pytest.mark.asyncio
    async def test_user_edits_shimmed_server_args(self, tmp_path, shim_path):
        """User edits the args of a shimmed server (appends a flag). Uninstall preserves the edit."""
        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run", "server.py"]}}}
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"srv"}):
            await install_shim_into_config(str(cfg_path))

        # User appends a flag to the shimmed server's args
        mid = _read_config(cfg_path)
        mid["mcpServers"]["srv"]["args"].append("--verbose")
        cfg_path.write_text(json.dumps(mid, indent=2), encoding="utf-8")

        await uninstall_shim_from_config(str(cfg_path))

        result = _read_config(cfg_path)
        assert result["mcpServers"]["srv"]["command"] == "uv"
        assert result["mcpServers"]["srv"]["args"] == ["run", "server.py", "--verbose"]

    @pytest.mark.asyncio
    async def test_user_manually_removes_shim(self, tmp_path, shim_path):
        """User manually restores the original command. Uninstall is a no-op, re-install re-shims."""
        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run"]}}}
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"srv"}):
            await install_shim_into_config(str(cfg_path))

        # User manually reverts the shim
        mid = _read_config(cfg_path)
        mid["mcpServers"]["srv"]["command"] = "uv"
        mid["mcpServers"]["srv"]["args"] = ["run"]
        cfg_path.write_text(json.dumps(mid, indent=2), encoding="utf-8")

        # Uninstall should be a no-op
        unshimmed = await uninstall_shim_from_config(str(cfg_path))
        assert unshimmed == []

        # Re-install should shim it again
        with _patch_shim(shim_path), _patch_stdio_names({"srv"}):
            shimmed = await install_shim_into_config(str(cfg_path))
        assert shimmed == ["srv"]

    @pytest.mark.asyncio
    async def test_user_replaces_shimmed_server_command(self, tmp_path, shim_path):
        """User changes the underlying command of a shimmed server (e.g. switches from uv to node)."""
        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run", "old.py"]}}}
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"srv"}):
            await install_shim_into_config(str(cfg_path))

        # User changes args[0] (the wrapped original command) and the rest
        mid = _read_config(cfg_path)
        mid["mcpServers"]["srv"]["args"] = ["node", "new.js"]
        cfg_path.write_text(json.dumps(mid, indent=2), encoding="utf-8")

        await uninstall_shim_from_config(str(cfg_path))

        result = _read_config(cfg_path)
        assert result["mcpServers"]["srv"]["command"] == "node"
        assert result["mcpServers"]["srv"]["args"] == ["new.js"]

    @pytest.mark.asyncio
    async def test_user_adds_env_to_shimmed_server(self, tmp_path, shim_path):
        """User adds env vars to a shimmed server. They survive uninstall."""
        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run"]}}}
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"srv"}):
            await install_shim_into_config(str(cfg_path))

        mid = _read_config(cfg_path)
        mid["mcpServers"]["srv"]["env"] = {"NEW_KEY": "new_val"}
        cfg_path.write_text(json.dumps(mid, indent=2), encoding="utf-8")

        await uninstall_shim_from_config(str(cfg_path))

        result = _read_config(cfg_path)
        assert result["mcpServers"]["srv"]["command"] == "uv"
        assert result["mcpServers"]["srv"]["env"] == {"NEW_KEY": "new_val"}

    @pytest.mark.asyncio
    async def test_user_removes_all_servers(self, tmp_path, shim_path):
        """User empties the servers dict. Uninstall returns empty list."""
        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run"]}}}
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"srv"}):
            await install_shim_into_config(str(cfg_path))

        mid = _read_config(cfg_path)
        mid["mcpServers"] = {}
        cfg_path.write_text(json.dumps(mid, indent=2), encoding="utf-8")

        unshimmed = await uninstall_shim_from_config(str(cfg_path))
        assert unshimmed == []


# ---------------------------------------------------------------------------
# repair_broken_shim
# ---------------------------------------------------------------------------


class TestRepairBrokenShim:
    @pytest.mark.asyncio
    async def test_repairs_when_shim_file_missing(self, tmp_path):
        """Shimmed config with missing shim file gets restored."""
        missing_shim = tmp_path / "gone" / "snyk_mcp_stdio_local_proxy.sh"
        config = {
            "mcpServers": {
                "weather": {
                    "command": f"/old/path/{SHIM_MARKER}.sh",
                    "args": ["uv", "run", "weather.py"],
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(missing_shim):
            repaired = await repair_broken_shim(str(cfg_path))

        assert repaired == ["weather"]
        result = _read_config(cfg_path)
        assert result["mcpServers"]["weather"]["command"] == "uv"
        assert result["mcpServers"]["weather"]["args"] == ["run", "weather.py"]

    @pytest.mark.asyncio
    async def test_noop_when_shim_file_exists(self, tmp_path, shim_path):
        """No repair needed when the shim file is present."""
        config = {
            "mcpServers": {
                "weather": {
                    "command": str(shim_path.resolve()),
                    "args": ["uv", "run", "weather.py"],
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path):
            repaired = await repair_broken_shim(str(cfg_path))

        assert repaired == []
        result = _read_config(cfg_path)
        assert SHIM_MARKER in result["mcpServers"]["weather"]["command"]

    @pytest.mark.asyncio
    async def test_noop_when_no_shimmed_servers(self, tmp_path):
        """No repair needed when config has no shimmed servers."""
        missing_shim = tmp_path / "gone" / "snyk_mcp_stdio_local_proxy.sh"
        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run"]}}}
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(missing_shim):
            repaired = await repair_broken_shim(str(cfg_path))

        assert repaired == []

    @pytest.mark.asyncio
    async def test_noop_when_config_missing(self, tmp_path):
        """No crash when config file doesn't exist."""
        missing_shim = tmp_path / "gone" / "snyk_mcp_stdio_local_proxy.sh"

        with _patch_shim(missing_shim):
            repaired = await repair_broken_shim("/nonexistent/path.json")

        assert repaired == []

    @pytest.mark.asyncio
    async def test_repairs_multiple_shimmed_servers(self, tmp_path):
        """All shimmed servers get restored when shim is missing."""
        missing_shim = tmp_path / "gone" / "snyk_mcp_stdio_local_proxy.sh"
        config = {
            "mcpServers": {
                "a": {"command": f"/old/{SHIM_MARKER}.sh", "args": ["cmd_a", "--flag"]},
                "b": {"command": f"/old/{SHIM_MARKER}.sh", "args": ["cmd_b"]},
                "not_shimmed": {"command": "uv", "args": ["run"]},
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(missing_shim):
            repaired = await repair_broken_shim(str(cfg_path))

        assert set(repaired) == {"a", "b"}
        result = _read_config(cfg_path)
        assert result["mcpServers"]["a"]["command"] == "cmd_a"
        assert result["mcpServers"]["a"]["args"] == ["--flag"]
        assert result["mcpServers"]["b"]["command"] == "cmd_b"
        assert result["mcpServers"]["b"]["args"] == []
        assert result["mcpServers"]["not_shimmed"]["command"] == "uv"

    @pytest.mark.asyncio
    async def test_preserves_env_on_repair(self, tmp_path):
        """Env vars and other keys survive repair."""
        missing_shim = tmp_path / "gone" / "snyk_mcp_stdio_local_proxy.sh"
        config = {
            "mcpServers": {
                "srv": {
                    "command": f"/old/{SHIM_MARKER}.sh",
                    "args": ["uv", "run"],
                    "env": {"API_KEY": "secret"},
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(missing_shim):
            await repair_broken_shim(str(cfg_path))

        result = _read_config(cfg_path)
        assert result["mcpServers"]["srv"]["command"] == "uv"
        assert result["mcpServers"]["srv"]["env"] == {"API_KEY": "secret"}


# ---------------------------------------------------------------------------
# _get_shim_path (content-addressed installer)
# ---------------------------------------------------------------------------


class TestGetShimPath:
    """The new content-addressed _get_shim_path() installer."""

    def test_idempotent(self, tmp_path, monkeypatch):
        """Two calls return the same path."""
        monkeypatch.setattr(shim_installer, "_get_shim_target_dir", lambda: tmp_path)
        path1 = _get_shim_path()
        path2 = _get_shim_path()
        assert path1 is not None
        assert path1 == path2

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-only file mode check")
    def test_file_mode_0o755_on_unix(self, tmp_path, monkeypatch):
        monkeypatch.setattr(shim_installer, "_get_shim_target_dir", lambda: tmp_path)
        path = _get_shim_path()
        assert path is not None
        mode = path.stat().st_mode & 0o777
        assert mode == 0o755

    def test_file_contents_match_bundled_source(self, tmp_path, monkeypatch):
        monkeypatch.setattr(shim_installer, "_get_shim_target_dir", lambda: tmp_path)
        path = _get_shim_path()
        assert path is not None
        assert path.read_bytes() == _read_shim_source_bytes()

    def test_path_filename_encodes_source_digest(self, tmp_path, monkeypatch):
        monkeypatch.setattr(shim_installer, "_get_shim_target_dir", lambda: tmp_path)
        source = _read_shim_source_bytes()
        digest = hashlib.sha256(source).hexdigest()[:12]
        path = _get_shim_path()
        assert path is not None
        assert digest in path.name

    def test_returns_none_when_target_exists_with_different_bytes(self, tmp_path, monkeypatch):
        """Foreign-owned tamper: target file exists but contents don't match bundled source."""
        monkeypatch.setattr(shim_installer, "_get_shim_target_dir", lambda: tmp_path)
        source = _read_shim_source_bytes()
        digest = hashlib.sha256(source).hexdigest()[:12]
        suffix = ".cmd" if sys.platform == "win32" else ".sh"
        tampered = tmp_path / f"snyk_mcp_stdio_local_proxy.{digest}{suffix}"
        tampered.write_bytes(b"#!/bin/sh\necho 'tampered'\n")
        assert _get_shim_path() is None

    def test_returns_none_when_not_executable(self, tmp_path, monkeypatch):
        """os.access(target, os.X_OK) is False (e.g. /tmp mounted noexec)."""
        monkeypatch.setattr(shim_installer, "_get_shim_target_dir", lambda: tmp_path)

        real_access = shim_installer.os.access

        def fake_access(p, mode):
            if mode == shim_installer.os.X_OK:
                return False
            return real_access(p, mode)

        monkeypatch.setattr(shim_installer.os, "access", fake_access)
        assert _get_shim_path() is None

    def test_returns_none_when_target_dir_missing(self, tmp_path, monkeypatch):
        """Target directory doesn't exist or isn't writable."""
        nonexistent = tmp_path / "does" / "not" / "exist"
        monkeypatch.setattr(shim_installer, "_get_shim_target_dir", lambda: nonexistent)
        assert _get_shim_path() is None

    def test_returns_existing_target_without_rewriting(self, tmp_path, monkeypatch):
        """If a matching file is already at the target, return it (idempotent read path)."""
        monkeypatch.setattr(shim_installer, "_get_shim_target_dir", lambda: tmp_path)
        source = _read_shim_source_bytes()
        digest = hashlib.sha256(source).hexdigest()[:12]
        suffix = ".cmd" if sys.platform == "win32" else ".sh"
        target = tmp_path / f"snyk_mcp_stdio_local_proxy.{digest}{suffix}"
        target.write_bytes(source)
        if sys.platform != "win32":
            target.chmod(0o755)
        mtime_before = target.stat().st_mtime
        path = _get_shim_path()
        assert path == target
        assert target.stat().st_mtime == mtime_before


# ---------------------------------------------------------------------------
# install_shim_into_config: cleanup-on-failure when _get_shim_path() is None
# ---------------------------------------------------------------------------


class TestInstallShimWhenShimUnavailable:
    """When _get_shim_path() returns None, install acts as a cleanup directive."""

    @pytest.mark.asyncio
    async def test_removes_existing_shim_when_get_shim_path_is_none(self, tmp_path):
        config = {
            "mcpServers": {
                "weather": {
                    "command": f"/somewhere/{SHIM_MARKER}.sh",
                    "args": ["uv", "run", "weather.py"],
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with patch("agent_scan.shim_installer._get_shim_path", return_value=None):
            result = await install_shim_into_config(str(cfg_path))

        assert result == ["weather"]
        on_disk = _read_config(cfg_path)
        assert SHIM_MARKER not in on_disk["mcpServers"]["weather"]["command"]
        assert on_disk["mcpServers"]["weather"]["command"] == "uv"
        assert on_disk["mcpServers"]["weather"]["args"] == ["run", "weather.py"]

    @pytest.mark.asyncio
    async def test_unshimmed_config_untouched_when_get_shim_path_is_none(self, tmp_path):
        """A config that has no shim wrapping is not modified."""
        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run", "server.py"]}}}
        cfg_path = _write_config(tmp_path, config)
        mtime_before = cfg_path.stat().st_mtime

        with patch("agent_scan.shim_installer._get_shim_path", return_value=None):
            result = await install_shim_into_config(str(cfg_path))

        assert result == []
        on_disk = _read_config(cfg_path)
        assert on_disk["mcpServers"]["srv"]["command"] == "uv"
        assert cfg_path.stat().st_mtime == mtime_before

    @pytest.mark.asyncio
    async def test_returns_none_when_target_has_foreign_bytes(self, tmp_path, monkeypatch):
        """End-to-end via real _get_shim_path: planted tamper → install cleans up."""
        monkeypatch.setattr(shim_installer, "_get_shim_target_dir", lambda: tmp_path)
        source = _read_shim_source_bytes()
        digest = hashlib.sha256(source).hexdigest()[:12]
        suffix = ".cmd" if sys.platform == "win32" else ".sh"
        tampered = tmp_path / f"snyk_mcp_stdio_local_proxy.{digest}{suffix}"
        tampered.write_bytes(b"not the bundled source")

        config = {
            "mcpServers": {
                "weather": {
                    "command": f"/somewhere/{SHIM_MARKER}.sh",
                    "args": ["uv", "run"],
                }
            }
        }
        cfg_path = _write_config(tmp_path, config, name="mcp.json")

        result = await install_shim_into_config(str(cfg_path))
        # The tampered file makes _get_shim_path() return None; the existing
        # shim wrapping in the config should be removed.
        assert result == ["weather"]
        on_disk = _read_config(cfg_path)
        assert on_disk["mcpServers"]["weather"]["command"] == "uv"
