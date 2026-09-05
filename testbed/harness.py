"""Brings one strongSwan peer pair up in Docker and tears it down (P1-T1).

Each pair gets its own Docker network so pairs can run concurrently. Every
failure path tears the pair down: a cell that will not establish must not leak
containers into the next three hundred.
"""

import contextlib
import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from testbed.config_generator import TunnelConfig, render_swanctl

IMAGE = "vaultscope-testbed"
TESTBED_DIR = Path(__file__).resolve().parent


class HarnessError(RuntimeError):
    """A peer pair could not be brought up, or would not establish."""


def _run(argv: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=check, capture_output=True, text=True)


def ipv6_supported() -> bool:
    """Docker only routes IPv6 when the daemon is configured for it.

    Probing once beats watching every IPv6 cell fail one at a time.
    """
    probe = "vs-ipv6-probe"
    _run(["docker", "network", "rm", probe], check=False)
    created = _run(
        ["docker", "network", "create", "--ipv6", "--subnet", "fd00:dead:beef::/64", probe],
        check=False,
    )
    _run(["docker", "network", "rm", probe], check=False)
    return created.returncode == 0


def build_image() -> None:
    _run(["docker", "build", "-q", "-t", IMAGE, str(TESTBED_DIR)])


@dataclass
class PeerPair:
    network: str
    initiator: str
    responder: str
    initiator_ip: str
    responder_ip: str

    def exec(self, container: str, *argv: str, check: bool = True):
        return _run(["docker", "exec", container, *argv], check=check)

    def exec_detached(self, container: str, *argv: str) -> None:
        """Start a long-running server and return immediately.

        `docker exec -d` rather than shell backgrounding: `nohup a; b &` only
        backgrounds `b`, which silently left servers unstarted.
        """
        _run(["docker", "exec", "-d", container, *argv], check=False)

    def establish(self, timeout: int = 30) -> None:
        """Load configs on both peers and initiate, waiting for INSTALLED."""
        for peer in (self.responder, self.initiator):
            self.exec(peer, "swanctl", "--load-all", check=False)
        self.exec(self.initiator, "swanctl", "--initiate", "--child", "net", check=False)

        deadline = time.time() + timeout
        while time.time() < deadline:
            sas = self.exec(self.initiator, "swanctl", "--list-sas", check=False).stdout
            if "INSTALLED" in sas:
                return
            time.sleep(1)

        log = self.exec(self.initiator, "cat", "/tmp/charon.log", check=False).stdout
        raise HarnessError(f"SA did not establish within {timeout}s. charon said:\n{log[-2000:]}")

    def start_capture(self, path: str = "/tmp/capture.pcap") -> None:
        _run(
            [
                "docker",
                "exec",
                "-d",
                self.initiator,
                "tcpdump",
                "-i",
                "any",
                "-w",
                path,
                "-U",
                "-s",
                "0",
                "udp port 500 or udp port 4500 or esp or ip proto 50",
            ]
        )
        time.sleep(1)  # let tcpdump open the file before traffic starts

    def stop_capture(self) -> None:
        self.exec(self.initiator, "pkill", "-INT", "tcpdump", check=False)
        time.sleep(1)

    def copy_out(self, container: str, src: str, dest: Path) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        _run(["docker", "cp", f"{container}:{src}", str(dest)])


@contextlib.contextmanager
def peer_pair(config: TunnelConfig, index: int) -> Iterator[PeerPair]:
    """One initiator/responder pair on its own network, torn down on exit."""
    if shutil.which("docker") is None:
        raise HarnessError("docker is not on PATH")

    network = f"vs-net-{index}"
    initiator, responder = f"vs-i-{index}", f"vs-r-{index}"
    ipv6 = config.ip_version == "IPv6"
    if ipv6:
        subnet = f"fd00:90:{index}::/64"
        local_ip, remote_ip = f"fd00:90:{index}::2", f"fd00:90:{index}::3"
    else:
        subnet = f"10.90.{index}.0/24"
        local_ip, remote_ip = f"10.90.{index}.2", f"10.90.{index}.3"

    workdir = Path(tempfile.mkdtemp(prefix="vs-testbed-"))
    (workdir / "i.conf").write_text(render_swanctl(config, local_ip, remote_ip, "alice", "bob"))
    (workdir / "r.conf").write_text(render_swanctl(config, remote_ip, local_ip, "bob", "alice"))

    net_argv = ["docker", "network", "create", "--subnet", subnet, network]
    if ipv6:
        net_argv.insert(3, "--ipv6")
    _run(["docker", "rm", "-f", initiator, responder], check=False)
    _run(["docker", "network", "rm", network], check=False)
    _run(net_argv, check=False)

    try:
        for name, ip, conf in ((initiator, local_ip, "i.conf"), (responder, remote_ip, "r.conf")):
            _run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    name,
                    "--network",
                    network,
                    "--ip6" if ipv6 else "--ip",
                    ip,
                    "--privileged",
                    "-v",
                    f"{workdir / conf}:/etc/swanctl/conf.d/vaultscope.conf",
                    IMAGE,
                    "sleep",
                    "infinity",
                ]
            )
            _run(
                [
                    "docker",
                    "exec",
                    "-d",
                    name,
                    "sh",
                    "-c",
                    "/usr/sbin/charon-systemd > /tmp/charon.log 2>&1",
                ]
            )
        time.sleep(4)  # charon needs a moment before its socket accepts swanctl
        yield PeerPair(network, initiator, responder, local_ip, remote_ip)
    finally:
        for name in (initiator, responder):
            _run(["docker", "rm", "-f", name], check=False)
        _run(["docker", "network", "rm", network], check=False)
        shutil.rmtree(workdir, ignore_errors=True)
