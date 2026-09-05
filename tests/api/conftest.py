"""Fixtures for the FastAPI backend tests.

Every test gets its own SQLite file via VAULTSCOPE_DB so the suite never
touches the developer's real database and tests cannot leak into each other.

Captures are built with Block A's ``tests/ike_parser/_build.py`` so the API
tests exercise the same wire format the Stage 2 parser is tested against --
these are real decodes end to end, not fixture-mode stand-ins.
"""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ike_parser"))
import _build as B  # noqa: E402  (needs the path insert above)

# One SA per preset, each given a distinct initiator SPI so the parser buckets
# them as separate sessions. Enough sessions for the pagination contract.
_PRESETS = (
    "aes256gcm_ecp521_pfs",
    "aes128cbc_sha256_modp2048",
    "3des_sha1_modp1024",
    "aes128cbc_sha256_modp2048",
)


def _retag(messages: list[bytes], tag: int) -> list[bytes]:
    """Same handshake under a different initiator SPI (byte 0 of the header)."""
    return [bytes([tag]) + m[1:] for m in messages]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULTSCOPE_DB", str(tmp_path / "test.sqlite"))
    monkeypatch.setenv("VAULTSCOPE_REPORT_DIR", str(tmp_path / "reports"))

    from api import main, store

    monkeypatch.setattr(main, "REPORT_DIR", tmp_path / "reports")
    store.init_db()
    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture
def test_pcap(tmp_path):
    """A capture holding five real IKE SAs of mixed severity.

    Four IKEv2 SA_INIT exchanges (strong GCM through 3DES/MODP1024) plus one
    IKEv1 Aggressive Mode exchange, which is DES/MD5/PSK/MODP1024 and so is
    reliably CRITICAL for the severity-filter and findings tests.
    """
    messages: list[bytes] = []
    for tag, preset in enumerate(_PRESETS, start=1):
        messages += _retag(B.sa_init_for_preset(preset), tag)
    messages += B.v1_aggressive_mode()

    pcap = tmp_path / "ike.pcap"
    B.write_pcap(pcap, messages)
    return pcap


@pytest.fixture
def weak_pcap(tmp_path):
    """IKEv1 Aggressive Mode, DES/MD5/PSK/MODP1024 -- CRITICAL on every rule."""
    pcap = tmp_path / "weak.pcap"
    B.write_pcap(pcap, B.v1_aggressive_mode())
    return pcap


@pytest.fixture
def ingested(client, test_pcap):
    """One completed ingest; returns the job_id."""
    with test_pcap.open("rb") as fh:
        response = client.post(
            "/ingest", files={"file": ("ike.pcap", fh, "application/vnd.tcpdump.pcap")}
        )
    assert response.status_code == 200, response.text
    return response.json()["job_id"]
