"""Environment smoke tests.

Green here means the repo layout, import path, and the P2 dependency set are
wired up correctly. Slice work replaces/extends these with real tests under
``tests/<slice>/``.
"""

import importlib
import shutil
import subprocess

import pytest


def test_core_packages_importable():
    for name in (
        "core",
        "core.ingestion",
        "core.ike_parser",
        "core.flow",
        "core.classifiers",
        "core.rules",
        "reporting",
        "api",
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
        # pipeline slices (spec Section 3)
        "testbed",
        "core/ingestion",
        "core/ike_parser",
        "core/flow",
        "core/classifiers",
        "core/rules",
        "reporting",
        "api",
        "frontend",
        "scripts",
        # dataset + model artifacts
        "data/pcaps",
        "data/labels",
        "data/mock",
        "models",
        # test tree mirrors the slices
        "tests/testbed",
        "tests/ingestion",
        "tests/ike_parser",
        "tests/flow",
        "tests/classifiers",
        "tests/rules",
        "tests/reporting",
        "tests/core",
        "tests/api",
        "tests/e2e",
        "tests/fixtures",
    ):
        assert (repo_root / rel).is_dir(), f"missing {rel}"


def test_tshark_on_path():
    """``pyshark`` (Stage 1 ingestion) shells out to tshark; it is not a pip dep.

    On macOS, Wireshark.app ships tshark but does not put it on PATH -- symlink
    /Applications/Wireshark.app/Contents/MacOS/tshark into a PATH dir.
    """
    assert shutil.which("tshark") is not None, (
        "tshark not found on PATH. Install Wireshark's CLI: "
        "macOS `brew install wireshark`, Debian/Ubuntu `apt install tshark`, "
        "Windows: install Wireshark and add it to PATH."
    )
    probe = subprocess.run(["tshark", "-v"], capture_output=True, text=True, timeout=30)
    assert probe.returncode == 0, probe.stderr


def test_pyshark_reads_a_pcap(tmp_path):
    """End-to-end Stage 1 dependency check: scapy writes, tshark+pyshark read."""
    import pyshark
    from scapy.all import IP, UDP, Raw, wrpcap

    pcap = tmp_path / "ike.pcap"
    # 28-byte IKEv2 header shape: init SPI | resp SPI | version/exchange/flags | ...
    header = bytes.fromhex("1122334455667788") + b"\x00" * 8 + bytes([0x21, 0x20, 0x22, 0x08])
    wrpcap(
        str(pcap), [IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=500, dport=500) / Raw(header)]
    )

    capture = pyshark.FileCapture(str(pcap), display_filter="udp.port==500 or udp.port==4500")
    try:
        packets = list(capture)
    finally:
        capture.close()
    assert len(packets) == 1
    assert packets[0].udp.dstport == "500"


def test_weasyprint_renders_pdf(tmp_path):
    """Stage 5 dependency check.

    Catches both the macOS native-lib lookup and pydyf drift -- weasyprint 62.3
    needs the pre-0.11 pydyf Stream API, and an unpinned pydyf breaks only at
    write_pdf() time, never at install time.
    """
    # Importing reporting sets DYLD_FALLBACK_LIBRARY_PATH on macOS, and must
    # happen before weasyprint is imported -- hence the in-function imports.
    importlib.import_module("reporting")
    import weasyprint

    pdf = tmp_path / "smoke.pdf"
    weasyprint.HTML(string="<h1>VaultScope</h1>").write_pdf(str(pdf))
    assert pdf.read_bytes().startswith(b"%PDF")
