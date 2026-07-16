import pytest

import agent_scan.pipelines as pipelines
from agent_scan.models import ControlServer, ScanPathResult
from agent_scan.pipelines import AnalyzeArgs, InspectArgs, PushArgs, inspect_analyze_push_pipeline


@pytest.mark.asyncio
async def test_auto_analysis_mode_without_remote_auth_uses_local_analysis(monkeypatch):
    scan_result = ScanPathResult(path="/tmp/mcp.json", client="test", servers=[], issues=[], labels=[])

    async def fake_inspect_pipeline(*args, **kwargs):
        return [scan_result], ["local-user"]

    async def fail_if_remote_analysis_is_called(*args, **kwargs):
        raise AssertionError("remote analysis should not be called in auto/local mode")

    monkeypatch.setattr(pipelines, "inspect_pipeline", fake_inspect_pipeline)
    monkeypatch.setattr(pipelines, "analyze_machine", fail_if_remote_analysis_is_called)
    results = await inspect_analyze_push_pipeline(
        InspectArgs(timeout=1, tokens=[], paths=[]),
        AnalyzeArgs(
            analysis_url="https://example.invalid/analysis",
            analysis_mode="auto",
            analysis_provider="local",
        ),
        PushArgs(control_servers=[]),
    )

    assert results == [scan_result]


@pytest.mark.asyncio
async def test_explicit_remote_analysis_mode_calls_remote_verifier(monkeypatch):
    scan_result = ScanPathResult(path="/tmp/mcp.json", client="test", servers=[], issues=[], labels=[])
    calls = []

    async def fake_inspect_pipeline(*args, **kwargs):
        return [scan_result], ["local-user"]

    async def fake_remote_analysis(scan_paths, **kwargs):
        calls.append(kwargs)
        return scan_paths

    monkeypatch.setattr(pipelines, "inspect_pipeline", fake_inspect_pipeline)
    monkeypatch.setattr(pipelines, "analyze_machine", fake_remote_analysis)
    results = await inspect_analyze_push_pipeline(
        InspectArgs(timeout=1, tokens=[], paths=[]),
        AnalyzeArgs(
            analysis_url="https://example.invalid/analysis",
            analysis_mode="remote",
            analysis_provider="snyk",
        ),
        PushArgs(control_servers=[]),
    )

    assert results == [scan_result]
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_auto_analysis_mode_with_push_key_uses_remote_verifier(monkeypatch):
    scan_result = ScanPathResult(path="/tmp/mcp.json", client="test", servers=[], issues=[], labels=[])
    calls = []

    async def fake_inspect_pipeline(*args, **kwargs):
        return [scan_result], ["local-user"]

    async def fake_remote_analysis(scan_paths, **kwargs):
        calls.append(kwargs)
        return scan_paths

    monkeypatch.setattr(pipelines, "inspect_pipeline", fake_inspect_pipeline)
    monkeypatch.setattr(pipelines, "analyze_machine", fake_remote_analysis)
    results = await inspect_analyze_push_pipeline(
        InspectArgs(timeout=1, tokens=[], paths=[]),
        AnalyzeArgs(
            analysis_url="https://example.invalid/analysis",
            analysis_mode="auto",
            analysis_provider="snyk",
        ),
        PushArgs(
            control_servers=[
                ControlServer(url="https://example.invalid/push", headers={"x-client-id": "push-key"}, identifier="id")
            ]
        ),
    )

    assert results == [scan_result]
    assert len(calls) == 1
