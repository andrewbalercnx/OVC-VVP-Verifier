"""Benchmark fixtures for performance testing."""

import json
import os
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import pytest


@dataclass
class BenchmarkStats:
    """Collect and compute statistics for benchmark runs."""

    _data: dict[str, list[float]] = field(default_factory=dict)

    def record(self, metric_name: str, elapsed_seconds: float) -> None:
        """Record a timing measurement.

        Args:
            metric_name: Name of the metric being measured
            elapsed_seconds: Elapsed time in seconds
        """
        if metric_name not in self._data:
            self._data[metric_name] = []
        self._data[metric_name].append(elapsed_seconds)

    def p50(self, metric_name: str) -> float:
        """Get 50th percentile (median) for a metric."""
        if metric_name not in self._data or not self._data[metric_name]:
            return 0.0
        return statistics.median(self._data[metric_name])

    def p95(self, metric_name: str) -> float:
        """Get 95th percentile for a metric."""
        if metric_name not in self._data or not self._data[metric_name]:
            return 0.0
        return self._percentile(self._data[metric_name], 95)

    def p99(self, metric_name: str) -> float:
        """Get 99th percentile for a metric."""
        if metric_name not in self._data or not self._data[metric_name]:
            return 0.0
        return self._percentile(self._data[metric_name], 99)

    def mean(self, metric_name: str) -> float:
        """Get mean for a metric."""
        if metric_name not in self._data or not self._data[metric_name]:
            return 0.0
        return statistics.mean(self._data[metric_name])

    def min(self, metric_name: str) -> float:
        """Get minimum for a metric."""
        if metric_name not in self._data or not self._data[metric_name]:
            return 0.0
        return min(self._data[metric_name])

    def max(self, metric_name: str) -> float:
        """Get maximum for a metric."""
        if metric_name not in self._data or not self._data[metric_name]:
            return 0.0
        return max(self._data[metric_name])

    def count(self, metric_name: str) -> int:
        """Get sample count for a metric."""
        if metric_name not in self._data:
            return 0
        return len(self._data[metric_name])

    def summary(self) -> dict:
        """Get summary of all metrics."""
        result = {}
        for metric_name in self._data:
            result[metric_name] = {
                "count": self.count(metric_name),
                "min": round(self.min(metric_name), 4),
                "max": round(self.max(metric_name), 4),
                "mean": round(self.mean(metric_name), 4),
                "p50": round(self.p50(metric_name), 4),
                "p95": round(self.p95(metric_name), 4),
                "p99": round(self.p99(metric_name), 4),
            }
        return result

    def _percentile(self, data: list[float], p: int) -> float:
        """Calculate percentile."""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        k = (len(sorted_data) - 1) * (p / 100)
        f = int(k)
        c = f + 1
        if c >= len(sorted_data):
            return sorted_data[-1]
        return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])


@pytest.fixture
def benchmark_stats() -> BenchmarkStats:
    """Create a fresh BenchmarkStats instance for each test."""
    return BenchmarkStats()


@pytest.fixture(scope="session")
def benchmark_output_path() -> Path:
    """Get path for benchmark output file."""
    output_dir = Path(os.getenv("VVP_BENCHMARK_OUTPUT_DIR", "."))
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / "benchmark_results.json"


@pytest.fixture(scope="session")
def benchmark_results() -> dict:
    """Shared benchmark results dictionary for all tests."""
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": os.getenv("VVP_TEST_MODE", "local"),
        "tests": {},
    }


@pytest.fixture(autouse=True)
def save_benchmark_results(
    request,
    benchmark_results: dict,
    benchmark_output_path: Path,
):
    """Auto-save benchmark results after each test."""
    yield

    # Only save if we have results
    if benchmark_results["tests"]:
        with open(benchmark_output_path, "w") as f:
            json.dump(benchmark_results, f, indent=2)


class Timer:
    """Context manager for timing code blocks."""

    def __init__(self):
        self.elapsed: float = 0.0
        self._start: float = 0.0

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *args):
        self.elapsed = time.perf_counter() - self._start


@pytest.fixture
def timer() -> Callable[[], Timer]:
    """Factory for creating Timer instances."""
    return Timer
