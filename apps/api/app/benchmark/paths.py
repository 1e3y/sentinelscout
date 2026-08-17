"""Paths for the repo-level benchmark pack."""

from __future__ import annotations

from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def benchmark_root() -> Path:
    return repo_root() / "benchmark"


def fixtures_root() -> Path:
    return benchmark_root() / "fixtures"


def html_root() -> Path:
    return fixtures_root() / "html"


def results_root() -> Path:
    return benchmark_root() / "results"


def baselines_root() -> Path:
    return results_root() / "baselines"


DEFAULT_CI_FIXTURES = ("visible-surface", "naming-traps", "header-surface", "coverage-gaps")
ALL_FIXTURES = ("visible-surface", "naming-traps", "retest-delta", "header-surface", "coverage-gaps")
