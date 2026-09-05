"""Fixtures for the Stage 2 IKE parser tests.

Synthetic captures are built by ``tests/ike_parser/_build.py`` (see its
docstring). pytest's default prepend import mode puts this directory on
``sys.path``, so ``import _build`` works from the test modules.
"""

from __future__ import annotations

import _build as B
import pytest


@pytest.fixture
def fixture_pcap(tmp_path):
    """Factory: ``fixture_pcap("aes256gcm_ecp521_pfs")`` -> path to a pcap
    holding the IKE_SA_INIT request/response for that cipher preset."""

    def _make(cipher: str) -> str:
        msgs = B.sa_init_for_preset(cipher)
        return B.write_pcap(tmp_path / f"sa_init_{cipher}.pcap", msgs)

    return _make


@pytest.fixture
def pfs_pcap_fixture(tmp_path) -> str:
    """SA_INIT + a CREATE_CHILD_SA rekey carrying a KE payload -> PFS enabled."""
    msgs = B.sa_init_for_preset("aes256gcm_ecp521_pfs")
    msgs.append(B.create_child_sa(ke_group=19, dh=19, rekey=True))
    return B.write_pcap(tmp_path / "pfs.pcap", msgs)


@pytest.fixture
def no_pfs_pcap_fixture(tmp_path) -> str:
    """SA_INIT + a CREATE_CHILD_SA rekey with no KE and no D-H -> PFS disabled."""
    msgs = B.sa_init_for_preset("aes128cbc_sha256_modp2048")
    msgs.append(B.create_child_sa(ke_group=None, dh=None, rekey=True))
    return B.write_pcap(tmp_path / "no_pfs.pcap", msgs)


@pytest.fixture
def transport_pcap_fixture(tmp_path) -> str:
    """SA_INIT + IKE_AUTH carrying USE_TRANSPORT_MODE -> transport mode."""
    msgs = B.sa_init_for_preset("aes256gcm_ecp521_pfs")
    msgs.append(B.ike_auth_request(auth_method=2, transport=True))
    return B.write_pcap(tmp_path / "transport.pcap", msgs)


@pytest.fixture
def tunnel_pcap_fixture(tmp_path) -> str:
    """SA_INIT + IKE_AUTH with no transport notify -> tunnel mode (default)."""
    msgs = B.sa_init_for_preset("aes256gcm_ecp521_pfs")
    msgs.append(B.ike_auth_request(auth_method=1, transport=False, child_dh=19))
    return B.write_pcap(tmp_path / "tunnel.pcap", msgs)


@pytest.fixture
def nat_t_pcap_fixture(tmp_path) -> str:
    """SA_INIT exchange carried over UDP 4500 with the 4-byte non-ESP marker."""
    msgs = B.sa_init_for_preset("aes128cbc_sha256_modp2048")
    return B.write_pcap(tmp_path / "nat_t.pcap", msgs, port=4500)


@pytest.fixture
def esp_only_fixture(tmp_path) -> str:
    """A mid-session capture: ESP packets only, no IKE handshake observed."""
    return B.write_esp_only_pcap(tmp_path / "esp_only.pcap")


# alias: spec test text uses both names
@pytest.fixture
def esp_only_pcap_fixture(esp_only_fixture) -> str:
    return esp_only_fixture
