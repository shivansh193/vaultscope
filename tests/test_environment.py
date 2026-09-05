"""Environment smoke tests.

Green here means the repo layout, import path, and the P2 dependency set are
wired up correctly. Slice work replaces/extends these with real tests under
``tests/<slice>/``.
"""

import importlib

import pytest


def test_core_packages_importable():
    for name in (
        "core",
        "core.ingestion",
        "core.ike_parser",
        "core.flow",
        "core.classifiers",
        "core.rules",
    ):
        assert importlib.import_module(name) is not None


def test_core_version_exposed():
    import core

    assert core.__version__ == "0.1.0"


@pytest.mark.parametrize(
    "module",
    ["scapy", "numpy", "pandas", "sklearn", "xgboost", "joblib", "matplotlib", "yaml"],
)
def test_p2_dependencies_present(module):
    assert importlib.import_module(module) is not None


def test_repo_skeleton_exists(repo_root):
    for rel in (
        "core/ike_parser",
        "core/flow",
        "core/classifiers",
        "data/pcaps",
        "data/labels",
        "models",
        "tests/ike_parser",
        "tests/flow",
        "tests/classifiers",
    ):
        assert (repo_root / rel).is_dir(), f"missing {rel}"
