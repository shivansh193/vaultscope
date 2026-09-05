"""Reuse the Stage 2 synthetic-message builders for Stage 1 tests."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ike_parser"))
import _build as B  # noqa: E402


@pytest.fixture
def ikev2_pcap(tmp_path) -> str:
    msgs = B.sa_init_for_preset("aes256gcm_ecp521_pfs")
    msgs.append(B.ike_auth_request(auth_method=2))
    return B.write_pcap(tmp_path / "ikev2.pcap", msgs)


@pytest.fixture
def ikev1_pcap(tmp_path) -> str:
    return B.write_pcap(tmp_path / "ikev1.pcap", B.v1_main_mode())


@pytest.fixture
def nat_t_pcap(tmp_path) -> str:
    return B.write_pcap(
        tmp_path / "nat_t.pcap", B.sa_init_for_preset("aes128cbc_sha256_modp2048"), port=4500
    )


@pytest.fixture
def esp_only_pcap(tmp_path) -> str:
    return B.write_esp_only_pcap(tmp_path / "esp_only.pcap")


@pytest.fixture
def two_ikev2_sessions_pcap(tmp_path) -> str:
    a = B.sa_init_for_preset("aes256gcm_ecp521_pfs")
    b = [
        m.replace(B._INIT_SPI, bytes.fromhex("aaaaaaaaaaaaaaaa")).replace(
            B._RESP_SPI, bytes.fromhex("bbbbbbbbbbbbbbbb")
        )
        for m in B.sa_init_for_preset("3des_sha1_modp1024")
    ]
    return B.write_pcap(tmp_path / "two.pcap", a + b)
