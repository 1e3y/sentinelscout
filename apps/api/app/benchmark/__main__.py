"""CLI: python -m app.benchmark {run,compare,serve}"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.benchmark.compare import compare_pack, format_compare
from app.benchmark.ground_truth import load_ground_truth
from app.benchmark.http_loopback import FixtureHttpServer
from app.benchmark.paths import ALL_FIXTURES, DEFAULT_CI_FIXTURES, baselines_root, results_root
from app.benchmark.runner import format_human, run_fixture
from app.core.db import SessionLocal


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m app.benchmark",
        description=(
            "Offline-first Scout evaluation harness. Offline metrics are "
            "pipeline_asset_precision / pipeline_asset_recall, not discovery recall."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run fixture(s) through Scout")
    run.add_argument("--fixture", choices=ALL_FIXTURES, help="Single fixture id")
    run.add_argument(
        "--all",
        action="store_true",
        help="Default CI pack only: visible-surface + naming-traps (not retest-delta)",
    )
    run.add_argument("--mode", choices=("offline", "local_live"), default="offline")
    run.add_argument("--save", action="store_true", help="Write JSON under benchmark/results/")
    run.add_argument(
        "--save-baseline",
        action="store_true",
        help="Write JSON under benchmark/results/baselines/ (review before treating as a gate)",
    )
    run.add_argument("--json", action="store_true", help="Print JSON only")

    compare = sub.add_parser("compare", help="Report-only diff against committed baselines")
    compare.add_argument(
        "--against",
        default=str(baselines_root()),
        help="Baseline directory (default: benchmark/results/baselines)",
    )
    compare.add_argument(
        "--results",
        default=str(results_root()),
        help="Current results directory (default: benchmark/results)",
    )
    compare.add_argument("--mode", choices=("offline", "local_live"), default="offline")
    compare.add_argument(
        "--include-retest-delta",
        action="store_true",
        help="Also compare Fixture C (not part of the default CI pack)",
    )
    compare.add_argument("--json", action="store_true", help="Print JSON only")

    serve = sub.add_parser("serve", help="Serve fixture HTML on loopback (optional local parity)")
    serve.add_argument("--fixture", choices=ALL_FIXTURES, required=True)
    serve.add_argument("--port", type=int, default=18080)

    return parser.parse_args(argv)


def _fixture_ids(args: argparse.Namespace) -> tuple[str, ...]:
    if args.command != "run":
        return ()
    if args.all and args.fixture:
        raise SystemExit("use either --fixture or --all, not both")
    if args.all:
        return DEFAULT_CI_FIXTURES
    if args.fixture:
        return (args.fixture,)
    raise SystemExit("specify --fixture ID or --all")


def _cmd_run(args: argparse.Namespace) -> int:
    results = []
    db = SessionLocal()
    try:
        for fixture_id in _fixture_ids(args):
            result = run_fixture(
                db,
                fixture_id,
                args.mode,
                save=args.save,
                save_baseline=args.save_baseline,
            )
            results.append(result)
            if not args.json:
                print(format_human(result))
                print()
    finally:
        db.close()
    if args.json:
        payload = results[0] if len(results) == 1 else results
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    fixture_ids = ALL_FIXTURES if args.include_retest_delta else DEFAULT_CI_FIXTURES
    pack = compare_pack(
        results_dir=Path(args.results),
        baselines_dir=Path(args.against),
        fixture_ids=fixture_ids,
        mode=args.mode,
    )
    if args.json:
        print(json.dumps(pack, indent=2, sort_keys=True))
    else:
        print(format_compare(pack))
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    truth = load_ground_truth(args.fixture)
    server = FixtureHttpServer(truth, port=args.port)
    port = server.start()
    print(f"Serving {args.fixture} on http://127.0.0.1:{port} (Host: *.bench.example)")
    print("Ctrl+C to stop.")
    try:
        while True:
            import time

            time.sleep(3600)
    except KeyboardInterrupt:
        return 0
    finally:
        server.stop()


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.command == "run":
        return _cmd_run(args)
    if args.command == "compare":
        return _cmd_compare(args)
    if args.command == "serve":
        return _cmd_serve(args)
    raise SystemExit(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
