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
    WRAPPER_SENTINEL,
    _get_shim_path,
    _is_shimmed_raw,
    _read_shim_source_bytes,
    _resolve_servers,
    _unwrap_shimmed,
    _wrap_command,
    compute_server_hash,
    install_shim_into_config,
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

    def test_shimmed_legacy_direct_exec(self):
        assert _is_shimmed_raw({"command": f"/path/to/{SHIM_MARKER}.sh", "args": ["uv", "run"]})

    def test_shimmed_conditional_unix(self):
        server = {
            "command": "/bin/sh",
            "args": [
                "-c",
                f'P=/tmp/{SHIM_MARKER}.HASH.sh; if [ -x "$P" ]; then exec "$P" "$@"; else exec "$@"; fi',
                WRAPPER_SENTINEL,
                "uv",
                "run",
            ],
        }
        assert _is_shimmed_raw(server)

    def test_shimmed_conditional_windows(self):
        server = {
            "command": "cmd",
            "args": [
                "/d",
                "/s",
                "/c",
                f'if exist "C:\\Users\\Public\\{SHIM_MARKER}.HASH.cmd" ("C:\\...{SHIM_MARKER}.HASH.cmd" %*) else (%*)',
                "uv",
                "run",
            ],
        }
        assert _is_shimmed_raw(server)

    def test_no_command(self):
        assert not _is_shimmed_raw({"args": ["run"]})


# ---------------------------------------------------------------------------
# _unwrap_shimmed / _wrap_command
# ---------------------------------------------------------------------------


class TestUnwrapShimmed:
    def test_unshimmed_returns_none(self):
        assert _unwrap_shimmed({"command": "uv", "args": ["run", "server.py"]}) is None

    def test_legacy_direct_exec(self):
        server = {
            "command": f"/tmp/{SHIM_MARKER}.HASH.sh",
            "args": ["uv", "run", "server.py"],
        }
        assert _unwrap_shimmed(server) == ("uv", ["run", "server.py"])

    def test_conditional_unix(self):
        shim_path = f"/tmp/{SHIM_MARKER}.HASH.sh"
        cmd, args = _wrap_command(shim_path, "uv", ["run", "server.py"])
        assert _unwrap_shimmed({"command": cmd, "args": args}) == ("uv", ["run", "server.py"])


class TestWrapCommand:
    def test_round_trip(self):
        shim_path = f"/tmp/{SHIM_MARKER}.HASH.sh"
        cmd, args = _wrap_command(shim_path, "uv", ["run", "server.py"])
        assert _unwrap_shimmed({"command": cmd, "args": args}) == ("uv", ["run", "server.py"])

    def test_marker_present_in_args(self):
        cmd, args = _wrap_command(f"/tmp/{SHIM_MARKER}.HASH.sh", "uv", [])
        assert any(SHIM_MARKER in a for a in args if isinstance(a, str))


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
        assert _is_shimmed_raw(weather)
        assert _unwrap_shimmed(weather) == ("uv", ["run", "weather.py"])
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
        assert _unwrap_shimmed(server) == ("node", ["index.js"])

    @pytest.mark.asyncio
    async def test_install_servers_format(self, tmp_path, shim_path):
        config = {"servers": {"s1": {"command": "python", "args": ["-m", "srv"]}}}
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"s1"}):
            shimmed = await install_shim_into_config(str(cfg_path))

        assert shimmed == ["s1"]
        result = _read_config(cfg_path)
        assert _unwrap_shimmed(result["servers"]["s1"]) == ("python", ["-m", "srv"])

    @pytest.mark.asyncio
    async def test_skips_already_shimmed_with_current_path(self, tmp_path, shim_path):
        """A config already in the conditional-wrapper form with the current
        shim path is left alone (no rewrite)."""
        wrapped_cmd, wrapped_args = _wrap_command(str(shim_path.resolve()), "uv", ["run"])
        config = {
            "mcpServers": {
                "already": {"command": wrapped_cmd, "args": wrapped_args},
            }
        }
        cfg_path = _write_config(tmp_path, config)
        mtime_before = cfg_path.stat().st_mtime

        with _patch_shim(shim_path), _patch_stdio_names({"already"}):
            shimmed = await install_shim_into_config(str(cfg_path))

        assert shimmed == []
        assert cfg_path.stat().st_mtime == mtime_before

    @pytest.mark.asyncio
    async def test_upgrades_legacy_direct_exec_to_conditional(self, tmp_path, shim_path):
        """A config in the legacy direct-exec form gets re-wrapped to the
        conditional form on install."""
        config = {
            "mcpServers": {
                "weather": {
                    "command": f"/old/path/{SHIM_MARKER}.sh",
                    "args": ["uv", "run", "weather.py"],
                },
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"weather"}):
            shimmed = await install_shim_into_config(str(cfg_path))

        assert shimmed == ["weather"]
        result = _read_config(cfg_path)
        weather = result["mcpServers"]["weather"]
        assert _unwrap_shimmed(weather) == ("uv", ["run", "weather.py"])
        # And it's no longer in the legacy form
        assert SHIM_MARKER not in weather["command"]

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
        assert not _is_shimmed_raw(result["mcpServers"]["not_stdio"])

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
        assert _unwrap_shimmed(result["mcpServers"]["a"]) == ("cmd_a", ["--flag"])
        assert _unwrap_shimmed(result["mcpServers"]["b"]) == ("cmd_b", [])

    @pytest.mark.asyncio
    async def test_shim_path_changed_re_wraps_with_new_path(self, tmp_path, shim_path):
        """If the shim path embedded in the conditional has changed (e.g. a
        package upgrade with a new content-addressed hash), re-installing
        re-wraps with the new shim path."""
        old_wrap_cmd, old_wrap_args = _wrap_command(f"/old/path/{SHIM_MARKER}.OLD.sh", "uv", ["run", "weather.py"])
        config = {
            "mcpServers": {
                "weather": {"command": old_wrap_cmd, "args": old_wrap_args},
            }
        }
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"weather"}):
            shimmed = await install_shim_into_config(str(cfg_path))

        assert shimmed == ["weather"]
        result = _read_config(cfg_path)
        weather = result["mcpServers"]["weather"]
        assert _unwrap_shimmed(weather) == ("uv", ["run", "weather.py"])
        # And the new shim path is what's embedded in the wrapper
        new_path = str(shim_path.resolve())
        assert any(new_path in a for a in weather["args"] if isinstance(a, str))


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
        assert _unwrap_shimmed(mid["mcpServers"]["weather"]) == ("uv", ["run", "weather.py"])

        await uninstall_shim_from_config(str(cfg_path))

        result = _read_config(cfg_path)
        assert result["mcpServers"]["weather"]["command"] == "uv"
        assert result["mcpServers"]["weather"]["args"] == ["run", "weather.py"]
        assert result["mcpServers"]["remote"] == {"url": "https://example.com"}

    @pytest.mark.asyncio
    async def test_install_upgrades_legacy_to_conditional(self, tmp_path, shim_path):
        """A legacy direct-exec shimmed entry gets upgraded to the conditional
        wrapper form on re-install."""
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
        # Original command is recoverable via the unwrap helper
        assert _unwrap_shimmed(weather) == ("uv", ["run", "weather.py"])
        # And the old shim path is no longer embedded anywhere
        assert old_shim not in weather["command"]
        for a in weather["args"]:
            if isinstance(a, str):
                assert old_shim not in a

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
        assert _unwrap_shimmed(result["mcpServers"]["srv"]) == ("uv", ["run"])

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
        assert _unwrap_shimmed(result["mcpServers"]["bare"]) == ("my-server", [])

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
        assert _unwrap_shimmed(result["mcpServers"]["new_server"]) == ("node", ["index.js"])
        # Existing should still be shimmed, not double-wrapped
        assert _unwrap_shimmed(result["mcpServers"]["existing"]) == ("uv", ["run"])

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
        """User changes the underlying command inside a shimmed entry (e.g.
        switches from uv to node) by editing the wrapped command/args slots."""
        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run", "old.py"]}}}
        cfg_path = _write_config(tmp_path, config)

        with _patch_shim(shim_path), _patch_stdio_names({"srv"}):
            await install_shim_into_config(str(cfg_path))

        # User edits the wrapped command + args inside the conditional wrapper.
        # We use _wrap_command to compute the new wrapped form for "node new.js"
        # while keeping the same shim path. This mimics a user-supplied edit.
        new_cmd, new_args = _wrap_command(str(shim_path.resolve()), "node", ["new.js"])
        mid = _read_config(cfg_path)
        mid["mcpServers"]["srv"]["command"] = new_cmd
        mid["mcpServers"]["srv"]["args"] = new_args
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
# Silent degrade: the wrapper falls through to the original command when
# the shim file isn't present at runtime. These tests exercise the wrapped
# entry as an actual subprocess to verify the conditional behaviour.
# ---------------------------------------------------------------------------


class TestConditionalWrapperSilentDegrade:
    @pytest.mark.skipif(sys.platform == "win32", reason="Unix /bin/sh form")
    def test_unix_wrapper_runs_original_when_shim_missing(self, tmp_path):
        """When the shim file referenced in the wrapper doesn't exist, sh
        falls through to exec the original command."""
        import subprocess

        missing_shim = tmp_path / f"{SHIM_MARKER}.MISSING.sh"
        cmd, args = _wrap_command(str(missing_shim), "/bin/echo", ["hello"])
        result = subprocess.run([cmd, *args], capture_output=True, text=True, timeout=5)
        assert result.returncode == 0
        assert result.stdout.strip() == "hello"

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix /bin/sh form")
    def test_unix_wrapper_runs_shim_when_present(self, tmp_path):
        """When the shim exists and is executable, sh exec's the shim with
        the original command as its args."""
        import os
        import subprocess

        fake_shim = tmp_path / f"{SHIM_MARKER}.PRESENT.sh"
        fake_shim.write_text('#!/bin/sh\necho "via-shim:$@"\n')
        os.chmod(fake_shim, 0o755)

        cmd, args = _wrap_command(str(fake_shim), "/bin/echo", ["hello"])
        result = subprocess.run([cmd, *args], capture_output=True, text=True, timeout=5)
        assert result.returncode == 0
        assert result.stdout.startswith("via-shim:")
        assert "/bin/echo hello" in result.stdout


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
