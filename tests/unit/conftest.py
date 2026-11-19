from unittest.mock import AsyncMock

import pytest

from agent_scan.verify_api import AgentScanConfig


@pytest.fixture(autouse=True)
def _local_config_by_default(monkeypatch):
    # CLI unit tests must not query a live tenant; routing tests provide their own config.
    monkeypatch.setattr("agent_scan.cli.fetch_agent_scan_config", AsyncMock(return_value=AgentScanConfig()))
