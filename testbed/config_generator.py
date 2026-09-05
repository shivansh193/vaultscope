"""Cartesian config generator for strongSwan peer pairs (P1-T1).

Pure: no Docker, no network, no file I/O. :func:`generate_configs` enumerates
the matrix and :func:`render_swanctl` turns one cell into a peer's
``swanctl.conf``.
"""

from dataclasses import dataclass
from itertools import product

from testbed.matrix import CIPHER_SUITES, DH_GROUPS, IP_VERSIONS, MODES, CipherSuite

PSK = "vaultscope-testbed-psk"


@dataclass(frozen=True)
class TunnelConfig:
    name: str
    mode: str
    suite: CipherSuite
    dh_slug: str
    dh_keyword: str
    pfs: bool
    ip_version: str

    def label_config(self) -> dict:
        """Ground truth for this cell, in ``core.models.IkeParams`` vocabulary."""
        return {
            "version": "IKEv2",
            "mode": self.mode,
            "encryption": self.suite.encryption,
            "integrity": self.suite.integrity,
            "dh_group": self.dh_slug.upper(),
            "pfs_status": "enabled" if self.pfs else "disabled",
            "auth_method": "PSK",
            "ip_version": self.ip_version,
        }


def generate_configs() -> list[TunnelConfig]:
    configs = []
    for mode, suite, (dh_slug, dh_keyword), pfs, ip_version in product(
        MODES, CIPHER_SUITES, DH_GROUPS, [True, False], IP_VERSIONS
    ):
        name = "_".join(
            [
                mode,
                suite.slug,
                dh_slug,
                "pfs" if pfs else "nopfs",
                "ipv4" if ip_version == "IPv4" else "ipv6",
            ]
        )
        configs.append(TunnelConfig(name, mode, suite, dh_slug, dh_keyword, pfs, ip_version))
    return configs


def render_swanctl(
    config: TunnelConfig,
    local_ip: str,
    remote_ip: str,
    local_id: str,
    remote_id: str,
) -> str:
    """One peer's ``swanctl.conf``.

    ``swanctl.conf`` is newline-structured; semicolons do not parse. PFS off
    means no DH group in the ESP proposal, so the child SA reuses the IKE SA's
    keying material instead of running a second exchange.
    """
    prefix = "128" if config.ip_version == "IPv6" else "32"
    esp = config.suite.esp_proposal + (f"-{config.dh_keyword}" if config.pfs else "")
    return f"""connections {{
    vaultscope {{
        version = 2
        local_addrs = {local_ip}
        remote_addrs = {remote_ip}
        proposals = {config.suite.ike_proposal}-{config.dh_keyword}
        local-1 {{
            auth = psk
            id = {local_id}
        }}
        remote-1 {{
            auth = psk
            id = {remote_id}
        }}
        children {{
            net {{
                local_ts = {local_ip}/{prefix}
                remote_ts = {remote_ip}/{prefix}
                mode = {config.mode}
                esp_proposals = {esp}
                start_action = none
            }}
        }}
    }}
}}
secrets {{
    ike-vaultscope {{
        id-1 = {local_id}
        id-2 = {remote_id}
        secret = "{PSK}"
    }}
}}
"""
