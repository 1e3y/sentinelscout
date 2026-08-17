from __future__ import annotations

from app.benchmark.compare import compare_pack, format_compare
from app.benchmark.ground_truth import load_ground_truth
from app.benchmark.http_loopback import FixtureHttpServer, LoopbackSafeHttpClient
from app.benchmark.paths import DEFAULT_CI_FIXTURES
from app.benchmark.runner import format_human, run_fixture, write_json
from app.benchmark.schema import validate_result


def _ban_live_discovery_tools(monkeypatch) -> None:
    def banned(*_args, **_kwargs):
        raise AssertionError("offline benchmark must not spawn subfinder or httpx")

    monkeypatch.setattr(
        "app.services.discovery.runner.SubprocessDiscoveryTools.discover_hosts",
        banned,
    )
    monkeypatch.setattr(
        "app.services.discovery.runner.SubprocessDiscoveryTools.probe_hosts",
        banned,
    )
    monkeypatch.setattr("app.benchmark.discovery.invoke_subfinder", banned)
    monkeypatch.setattr(
        "app.benchmark.discovery.LiveLoopbackDiscoveryTools.probe_hosts",
        banned,
    )


def test_default_ci_pack_excludes_retest_delta():
    assert DEFAULT_CI_FIXTURES == ("visible-surface", "naming-traps")
    assert "retest-delta" not in DEFAULT_CI_FIXTURES


def test_ground_truth_uses_bench_example_namespace():
    for fixture_id in ("visible-surface", "naming-traps", "retest-delta"):
        truth = load_ground_truth(fixture_id)
        assert truth.root == "bench.example"
        assert all(
            host.endswith("bench.example") or host == "bench.example" for host in truth.hostnames
        )
        assert "test" not in truth.root.split(".")


def test_loopback_client_never_uses_public_dns():
    truth = load_ground_truth("visible-surface")
    server = FixtureHttpServer(truth)
    try:
        port = server.start()
        client = LoopbackSafeHttpClient(port=port)
        observed = client.fetch("https://admin.bench.example/", method="GET")
        assert observed.reachable is True
        assert observed.status_code == 200
        assert "grafana" in observed.title.lower()
    finally:
        server.stop()


def test_offline_ci_pack_schema_and_report_only_baseline(db_session, monkeypatch, tmp_path, capsys):
    _ban_live_discovery_tools(monkeypatch)
    results = []
    for fixture_id in DEFAULT_CI_FIXTURES:
        result = run_fixture(db_session, fixture_id, "offline")
        validate_result(result)
        assert result["mode"] == "offline"
        assert result["live_discovery"] is None
        assert "pipeline_asset_precision" in result["pipeline_assets"]
        assert "pipeline_asset_recall" in result["pipeline_assets"]
        assert "scout_asset_recall" not in result
        assert "scout_discovery_recall" not in result
        human = format_human(result)
        assert "pipeline_asset_recall" in human
        assert "Scout asset recall" not in human
        assert "Scout discovery recall" not in human
        write_json(result, tmp_path / f"{fixture_id}-offline.json")
        results.append(result)

    pack = compare_pack(results_dir=tmp_path, mode="offline")
    printed = format_compare(pack)
    print(printed)
    captured = capsys.readouterr()
    assert "REPORT-ONLY" in captured.out
    assert pack["fails_ci"] is False
    assert pack["policy"] == "report_only"
    assert len(results) == 2


def test_offline_mode_does_not_call_subprocess_discovery(db_session, monkeypatch):
    _ban_live_discovery_tools(monkeypatch)
    result = run_fixture(db_session, "visible-surface", "offline")
    validate_result(result)
    assert result["warnings"] == []
