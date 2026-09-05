"""Shared pytest fixtures for the VaultScope test suite.

The test tree mirrors ``core/`` (spec Section 9). Slice-specific fixtures
belong in that slice's ``tests/<slice>/conftest.py``; only cross-slice
paths and helpers live here.
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def data_dir() -> Path:
    return REPO_ROOT / "data"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Small hand-crafted pcap / JSON fixtures checked into the repo."""
    return REPO_ROOT / "tests" / "fixtures"


@pytest.fixture(scope="session")
def models_dir() -> Path:
    return REPO_ROOT / "models"
