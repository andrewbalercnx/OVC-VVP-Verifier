"""Pytest fixtures and configuration for test vectors."""

import json
from pathlib import Path
from typing import List

from .schema import VectorCase

VECTORS_DIR = Path(__file__).parent / "data"


def load_all_vectors() -> List[VectorCase]:
    """Load all test vectors from JSON files."""
    vectors = []
    for path in sorted(VECTORS_DIR.glob("v*.json")):
        with open(path) as f:
            vectors.append(VectorCase(**json.load(f)))
    return vectors


def pytest_generate_tests(metafunc):
    """Parametrize test_vector fixture with all vectors."""
    if "test_vector" in metafunc.fixturenames:
        vectors = load_all_vectors()
        metafunc.parametrize("test_vector", vectors, ids=[v.id for v in vectors])
